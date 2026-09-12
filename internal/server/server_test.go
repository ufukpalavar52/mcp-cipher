package server_test

import (
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"mcp-cipher/internal/keyring"
	"mcp-cipher/internal/server"
	pb "mcp-cipher/pkg/pb/cipher"
)

// Exercised over a real gRPC connection rather than by calling the methods directly, so
// the interceptor, the status codes and the generated types are all part of what is tested.
func dial(t *testing.T, keys map[string]string, active, token string) pb.CipherServiceClient {
	t.Helper()

	ring, err := keyring.New(keys, active)
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}

	listener := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer(grpc.UnaryInterceptor(server.TokenInterceptor(token)))
	pb.RegisterCipherServiceServer(
		grpcServer,
		server.New(ring, slog.New(slog.NewTextHandler(io.Discard, nil))),
	)

	go func() { _ = grpcServer.Serve(listener) }()
	t.Cleanup(grpcServer.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	return pb.NewCipherServiceClient(conn)
}

func aes256(seed byte) string {
	key := make([]byte, 32)
	for i := range key {
		key[i] = seed
	}
	return base64.StdEncoding.EncodeToString(key)
}

func withToken(token string) context.Context {
	return metadata.AppendToOutgoingContext(context.Background(), server.TokenHeader, token)
}

func TestEncryptThenDecrypt(t *testing.T) {
	client := dial(t, map[string]string{"v1": aes256(1)}, "v1", "")
	secret := []byte("sk-live-abc123")

	sealed, err := client.Encrypt(context.Background(), &pb.EncryptRequest{
		Plaintext: secret, Context: "model-api-key",
	})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if sealed.GetKeyId() != "v1" {
		t.Fatalf("key id is %q, want v1", sealed.GetKeyId())
	}

	opened, err := client.Decrypt(context.Background(), &pb.DecryptRequest{
		Ciphertext: sealed.GetCiphertext(), Context: "model-api-key", KeyId: "v1",
	})
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(opened.GetPlaintext()) != string(secret) {
		t.Fatalf("got %q, want %q", opened.GetPlaintext(), secret)
	}
}

// Rewrap is why rotation does not require the stored value to travel: the plaintext exists
// only inside the call.
func TestRewrapMovesAValueToTheActiveKey(t *testing.T) {
	client := dial(t, map[string]string{"v1": aes256(1), "v2": aes256(2)}, "v1", "")
	secret := []byte("sk-live-abc123")

	sealed, err := client.Encrypt(context.Background(), &pb.EncryptRequest{
		Plaintext: secret, Context: "ctx",
	})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// The ring now rotates; a fresh client stands in for the restarted service.
	rotated := dial(t, map[string]string{"v1": aes256(1), "v2": aes256(2)}, "v2", "")

	rewrapped, err := rotated.Rewrap(context.Background(), &pb.RewrapRequest{
		Ciphertext: sealed.GetCiphertext(), Context: "ctx", KeyId: "v1",
	})
	if err != nil {
		t.Fatalf("rewrap: %v", err)
	}
	if rewrapped.GetKeyId() != "v2" {
		t.Fatalf("rewrapped under %q, want v2", rewrapped.GetKeyId())
	}

	opened, err := rotated.Decrypt(context.Background(), &pb.DecryptRequest{
		Ciphertext: rewrapped.GetCiphertext(), Context: "ctx", KeyId: "v2",
	})
	if err != nil {
		t.Fatalf("decrypt after rewrap: %v", err)
	}
	if string(opened.GetPlaintext()) != string(secret) {
		t.Fatal("the value changed during rewrap")
	}
}

func TestAWrongContextIsRefused(t *testing.T) {
	client := dial(t, map[string]string{"v1": aes256(1)}, "v1", "")

	sealed, _ := client.Encrypt(context.Background(), &pb.EncryptRequest{
		Plaintext: []byte("secret"), Context: "model-api-key",
	})

	_, err := client.Decrypt(context.Background(), &pb.DecryptRequest{
		Ciphertext: sealed.GetCiphertext(), Context: "ssh-private-key", KeyId: "v1",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("got %v, want InvalidArgument", status.Code(err))
	}
}

func TestAnUnknownKeyIsAPreconditionFailure(t *testing.T) {
	// Not NotFound: the request is well formed and the value may be perfectly valid, but
	// this service cannot open it as configured — which an operator fixes by loading the key.
	client := dial(t, map[string]string{"v1": aes256(1)}, "v1", "")

	_, err := client.Decrypt(context.Background(), &pb.DecryptRequest{
		Ciphertext: make([]byte, 40), Context: "ctx", KeyId: "v9",
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("got %v, want FailedPrecondition", status.Code(err))
	}
}

func TestEmptyInputIsRejected(t *testing.T) {
	client := dial(t, map[string]string{"v1": aes256(1)}, "v1", "")

	if _, err := client.Encrypt(context.Background(), &pb.EncryptRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("encrypt: got %v, want InvalidArgument", status.Code(err))
	}
	if _, err := client.Decrypt(context.Background(), &pb.DecryptRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("decrypt: got %v, want InvalidArgument", status.Code(err))
	}
}

func TestTheTokenIsEnforced(t *testing.T) {
	client := dial(t, map[string]string{"v1": aes256(1)}, "v1", "s3cret")
	request := &pb.EncryptRequest{Plaintext: []byte("x"), Context: "ctx"}

	if _, err := client.Encrypt(context.Background(), request); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no token: got %v, want Unauthenticated", status.Code(err))
	}
	if _, err := client.Encrypt(withToken("wrong"), request); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("wrong token: got %v, want Unauthenticated", status.Code(err))
	}
	if _, err := client.Encrypt(withToken("s3cret"), request); err != nil {
		t.Fatalf("correct token: %v", err)
	}
}

func TestKeysReportsTheRing(t *testing.T) {
	client := dial(t, map[string]string{"v1": aes256(1), "v2": aes256(2)}, "v2", "")

	keys, err := client.Keys(context.Background(), &pb.KeysRequest{})
	if err != nil {
		t.Fatalf("keys: %v", err)
	}
	if keys.GetActiveKeyId() != "v2" || len(keys.GetKnownKeyIds()) != 2 {
		t.Fatalf("got %+v", keys)
	}
}

// The health check must answer an orchestrator's probe without credentials. Requiring
// them would put the token into every compose file and probe that wants to wait for this
// service, and the answer — serving or not — gives nothing away that opening a TCP
// connection does not.
func TestHealthDoesNotRequireTheToken(t *testing.T) {
	ring, err := keyring.New(map[string]string{"v1": aes256(1)}, "v1")
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}

	listener := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer(grpc.UnaryInterceptor(server.TokenInterceptor("s3cret")))
	pb.RegisterCipherServiceServer(
		grpcServer,
		server.New(ring, slog.New(slog.NewTextHandler(io.Discard, nil))),
	)

	healthServer := health.NewServer()
	healthpb.RegisterHealthServer(grpcServer, healthServer)
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)

	go func() { _ = grpcServer.Serve(listener) }()
	t.Cleanup(grpcServer.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	// No token on the context, deliberately.
	response, err := healthpb.NewHealthClient(conn).Check(
		context.Background(), &healthpb.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("health check was refused: %v", err)
	}
	if response.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("status is %v", response.GetStatus())
	}

	// The cipher methods are still protected.
	client := pb.NewCipherServiceClient(conn)
	if _, err := client.Keys(context.Background(), &pb.KeysRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("cipher methods lost their protection: %v", status.Code(err))
	}
}
