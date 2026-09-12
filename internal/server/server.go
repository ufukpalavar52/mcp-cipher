// Package server exposes the keyring over gRPC.
//
// Every method here is deliberately terse about failure. A caller learns that a value
// could not be opened, never whether the key id was unknown, the key was wrong or the
// context did not match — those distinctions are exactly what an attacker probing the
// service would want, and none of them help a legitimate caller, who has one thing to do
// either way.
package server

import (
	"context"
	"errors"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"mcp-cipher/internal/cipher"
	"mcp-cipher/internal/keyring"
	pb "mcp-cipher/pkg/pb/cipher"
)

type Server struct {
	pb.UnimplementedCipherServiceServer

	ring *keyring.Keyring
	log  *slog.Logger
}

func New(ring *keyring.Keyring, log *slog.Logger) *Server {
	return &Server{ring: ring, log: log}
}

func (s *Server) Encrypt(_ context.Context, request *pb.EncryptRequest) (*pb.EncryptResponse, error) {
	if len(request.GetPlaintext()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "plaintext is required")
	}

	id, key := s.ring.Active()

	sealed, err := cipher.Seal(key, request.GetPlaintext(), request.GetContext())
	if err != nil {
		// The message is logged without the value; an error from Seal is a broken key or a
		// broken random source, and neither is the caller's to see.
		s.log.Error("encrypt failed", "key_id", id, "error", err)
		return nil, status.Error(codes.Internal, "could not encrypt")
	}

	s.log.Info("encrypted", "key_id", id, "context", request.GetContext(), "bytes", len(sealed))
	return &pb.EncryptResponse{Ciphertext: sealed, KeyId: id}, nil
}

func (s *Server) Decrypt(_ context.Context, request *pb.DecryptRequest) (*pb.DecryptResponse, error) {
	plaintext, err := s.open(request.GetCiphertext(), request.GetContext(), request.GetKeyId())
	if err != nil {
		return nil, err
	}

	s.log.Info("decrypted", "key_id", request.GetKeyId(), "context", request.GetContext())
	return &pb.DecryptResponse{Plaintext: plaintext}, nil
}

// Rewrap opens under the old key and seals under the active one.
//
// The plaintext exists only inside this call. That is the reason the operation lives here
// rather than being a Decrypt followed by an Encrypt in the caller: rotating a stored value
// should not require the value to travel anywhere.
func (s *Server) Rewrap(_ context.Context, request *pb.RewrapRequest) (*pb.RewrapResponse, error) {
	plaintext, err := s.open(request.GetCiphertext(), request.GetContext(), request.GetKeyId())
	if err != nil {
		return nil, err
	}

	id, key := s.ring.Active()

	sealed, sealErr := cipher.Seal(key, plaintext, request.GetContext())
	if sealErr != nil {
		s.log.Error("rewrap failed", "key_id", id, "error", sealErr)
		return nil, status.Error(codes.Internal, "could not encrypt")
	}

	s.log.Info("rewrapped", "from_key_id", request.GetKeyId(), "to_key_id", id)
	return &pb.RewrapResponse{Ciphertext: sealed, KeyId: id}, nil
}

func (s *Server) Keys(_ context.Context, _ *pb.KeysRequest) (*pb.KeysResponse, error) {
	return &pb.KeysResponse{
		ActiveKeyId: s.ring.ActiveID(),
		KnownKeyIds: s.ring.IDs(),
	}, nil
}

// open is the shared path for Decrypt and Rewrap, so both answer failure identically.
func (s *Server) open(sealed []byte, context, keyID string) ([]byte, error) {
	if len(sealed) == 0 {
		return nil, status.Error(codes.InvalidArgument, "ciphertext is required")
	}

	key, err := s.ring.Get(keyID)
	if err != nil {
		if errors.Is(err, keyring.ErrUnknownKey) {
			// FailedPrecondition rather than NotFound: the request is well formed and the
			// value may well be valid, but this service cannot open it in its current
			// configuration — which is something an operator can fix by loading the key.
			s.log.Warn("decrypt requested with an unknown key", "key_id", keyID)
			return nil, status.Error(codes.FailedPrecondition, "this service cannot open that value")
		}
		return nil, status.Error(codes.Internal, "could not decrypt")
	}

	plaintext, err := cipher.Open(key, sealed, context)
	if err != nil {
		s.log.Warn("decrypt failed", "key_id", keyID, "context", context)
		return nil, status.Error(codes.InvalidArgument, "could not decrypt")
	}
	return plaintext, nil
}
