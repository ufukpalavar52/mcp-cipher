// Command mcp-cipher serves the MCP stack's encryption keys over gRPC.
//
// It is the only process that holds them. Every other service stores ciphertext and a key
// id, which means none of them has to be trusted with a key in order to store a secret,
// and a database dump on its own reveals nothing.
package main

import (
	"context"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"

	"mcp-cipher/internal/config"
	"mcp-cipher/internal/keyring"
	"mcp-cipher/internal/logfile"
	"mcp-cipher/internal/server"
	pb "mcp-cipher/pkg/pb/cipher"
)

func main() {
	out, closer, logErr := logfile.Writer("mcp-cipher")
	if closer != nil {
		defer closer.Close()
	}

	log := slog.New(slog.NewTextHandler(out, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// Reported once there is somewhere to report it. Said before the logger exists and it
	// would go nowhere, which is the one message that must not.
	if logErr != nil {
		log.Warn("no log file; console only", "error", logErr)
	}

	cfg, err := config.Load()
	if err != nil {
		// Fatal rather than degraded. A cipher service that starts without usable keys can
		// only refuse every request, and it would refuse them at the moment someone is
		// trying to save a secret rather than at the moment someone is deploying it.
		log.Error("configuration is unusable", "error", err)
		os.Exit(1)
	}

	ring, err := keyring.New(cfg.Keys, cfg.ActiveKeyID)
	if err != nil {
		log.Error("keyring is unusable", "error", err)
		os.Exit(1)
	}

	if cfg.RemoteStatus == "" {
		log.Info("configuration read from mcp-config")
	} else {
		// Not an error. The keys came from the environment and are already loaded, so this
		// service works either way — but a process running on local defaults should say so
		// rather than look identical to one that is centrally configured.
		log.Warn("using local configuration", "reason", cfg.RemoteStatus)
	}

	if cfg.Token == "" {
		log.Warn("no MCP_CIPHER_TOKEN set; every caller that can reach this port can decrypt")
	}

	listener, err := net.Listen("tcp", cfg.Address)
	if err != nil {
		log.Error("could not listen", "address", cfg.Address, "error", err)
		os.Exit(1)
	}

	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(server.TokenInterceptor(cfg.Token)),

		// Permission for clients to ping while idle, which is the only way they find out
		// their connection has died.
		//
		// An executor builds one client and keeps it for the life of the process, and its
		// jobs can be days apart. Nothing between the two containers tells either end when
		// it drops an idle connection, so the client goes on believing it is connected and
		// the next call blocks until its deadline: a job on 24 September failed five
		// seconds in — the cipher timeout exactly — and this service's log had nothing for
		// that day, because the call never arrived.
		//
		// The client's answer is to ping every thirty seconds. Without this it would be
		// disconnected for doing so: the default policy tolerates a ping every five
		// minutes and none at all while no call is in flight, which is precisely the idle
		// stretch in question. Twenty seconds leaves the client's thirty a margin, so a
		// little clock drift is not read as an attack.
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             20 * time.Second,
			PermitWithoutStream: true,
		}),
	)

	pb.RegisterCipherServiceServer(grpcServer, server.New(ring, log))

	// Health, so an orchestrator can wait for this before starting the services that
	// depend on it; reflection so grpcurl works without the proto file to hand.
	healthServer := health.NewServer()
	healthpb.RegisterHealthServer(grpcServer, healthServer)
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	reflection.Register(grpcServer)

	log.Info("mcp-cipher listening",
		"address", cfg.Address,
		"active_key", ring.ActiveID(),
		"keys", ring.IDs(),
		"auth", cfg.Token != "")

	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			log.Error("server stopped", "error", err)
			os.Exit(1)
		}
	}()

	waitForSignal(log, grpcServer)
}

// waitForSignal stops the server gracefully, so a decrypt already in flight finishes
// rather than failing at whichever service was waiting on it.
func waitForSignal(log *slog.Logger, grpcServer *grpc.Server) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	<-signals

	log.Info("shutting down")

	stopped := make(chan struct{})
	go func() {
		grpcServer.GracefulStop()
		close(stopped)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	select {
	case <-stopped:
		log.Info("stopped cleanly")
	case <-ctx.Done():
		// A caller holding the connection open must not keep the process alive forever.
		log.Warn("graceful stop timed out; forcing")
		grpcServer.Stop()
	}
}
