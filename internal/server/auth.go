package server

import (
	"context"
	"crypto/subtle"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// TokenHeader carries the shared secret callers present.
const TokenHeader = "x-cipher-token"

// healthService is exempt from the token check.
//
// A liveness probe is run by an orchestrator, not by a caller, and requiring credentials
// would mean putting the token into every compose file and probe definition that wants to
// wait for this service. The answer it gives away is "serving" or "not serving", which
// anyone able to open a TCP connection can already determine.
const healthService = "/grpc.health.v1.Health/"

// TokenInterceptor rejects calls that do not present the token.
//
// Returns a no-op interceptor when no token is configured, rather than a check that
// always passes: the difference is visible at start up, where it is logged, instead of
// being buried in a comparison against an empty string.
func TokenInterceptor(expected string) grpc.UnaryServerInterceptor {
	if expected == "" {
		return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			return handler(ctx, req)
		}
	}

	want := []byte(expected)

	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if strings.HasPrefix(info.FullMethod, healthService) {
			return handler(ctx, req)
		}

		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing credentials")
		}

		values := md.Get(TokenHeader)
		if len(values) != 1 {
			return nil, status.Error(codes.Unauthenticated, "missing credentials")
		}

		// Constant time: a length-independent early return would leak the token one
		// character at a time to anyone able to measure the difference.
		if subtle.ConstantTimeCompare([]byte(values[0]), want) != 1 {
			return nil, status.Error(codes.Unauthenticated, "invalid credentials")
		}

		return handler(ctx, req)
	}
}
