package config

import (
	"strings"
	"testing"
)

func TestKeysAreCollectedByPrefix(t *testing.T) {
	t.Setenv("MCP_CIPHER_KEY_V1", "aaaa")
	t.Setenv("MCP_CIPHER_KEY_V2", "bbbb")
	t.Setenv("MCP_CIPHER_ACTIVE_KEY", "v2")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if len(cfg.Keys) != 2 || cfg.Keys["v1"] != "aaaa" {
		t.Fatalf("got %+v", cfg.Keys)
	}
	if cfg.ActiveKeyID != "v2" {
		t.Fatalf("active is %q, want v2", cfg.ActiveKeyID)
	}
}

func TestASingleKeyNeedsNoActiveDeclaration(t *testing.T) {
	t.Setenv("MCP_CIPHER_KEY_ONLY", "aaaa")
	t.Setenv("MCP_CIPHER_ACTIVE_KEY", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.ActiveKeyID != "only" {
		t.Fatalf("active is %q, want only", cfg.ActiveKeyID)
	}
}

func TestSeveralKeysRequireAChoice(t *testing.T) {
	// Picking one arbitrarily would seal new values under a key the operator did not mean,
	// and the mistake would only surface when the other key was retired.
	t.Setenv("MCP_CIPHER_KEY_V1", "aaaa")
	t.Setenv("MCP_CIPHER_KEY_V2", "bbbb")
	t.Setenv("MCP_CIPHER_ACTIVE_KEY", "")

	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "ACTIVE_KEY") {
		t.Fatalf("got %v, want a demand for an active key", err)
	}
}

func TestANamedButEmptyKeyIsAnError(t *testing.T) {
	// A half finished edit, not a request for a blank key.
	t.Setenv("MCP_CIPHER_KEY_V1", "")

	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("got %v, want a complaint about the empty key", err)
	}
}

func TestNoKeysAtAllIsAnError(t *testing.T) {
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "no keys configured") {
		t.Fatalf("got %v, want a complaint about missing keys", err)
	}
}

func TestTheDefaultAddressIsLoopback(t *testing.T) {
	// Defaulting to 0.0.0.0 would make the permissive case the one you get by forgetting.
	t.Setenv("MCP_CIPHER_KEY_V1", "aaaa")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !strings.HasPrefix(cfg.Address, "127.0.0.1:") {
		t.Fatalf("default address is %q", cfg.Address)
	}
}
