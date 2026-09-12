// Package config reads this service's settings from the environment.
//
// The environment and nothing else. Keys must not sit in a file this repository tracks,
// and a config server would mean the keys travel over the network to reach the one process
// that exists to keep them off it.
package config

import (
	"fmt"
	"os"
	"strings"
)

const (
	// Every variable named MCP_CIPHER_KEY_<ID> contributes a key with that id.
	keyPrefix = "MCP_CIPHER_KEY_"

	envActiveKey = "MCP_CIPHER_ACTIVE_KEY"
	envAddress   = "MCP_CIPHER_ADDRESS"
	envToken     = "MCP_CIPHER_TOKEN"
)

type Config struct {
	// Keys by id. At least one is required.
	Keys map[string]string

	// Which key new values are sealed under.
	ActiveKeyID string

	// Where to listen. Defaults to loopback: this service should be reachable from the
	// machines that need it and from nowhere else, and defaulting to 0.0.0.0 makes the
	// permissive case the one you get by forgetting.
	Address string

	// Shared secret callers present. Empty disables the check, which is only defensible
	// on a loopback address.
	Token string

	// Why the config server was not used, empty when it was. Reported at start up so a
	// service running on local defaults is visible rather than merely quiet.
	RemoteStatus string
}

// Load reads the environment, failing on anything that would leave the service unable to
// do its job. Starting successfully and refusing every request is worse than not starting.
func Load() (Config, error) {
	cfg := Config{
		Keys:        map[string]string{},
		ActiveKeyID: os.Getenv(envActiveKey),
		Address:     valueOr(os.Getenv(envAddress), "127.0.0.1:9090"),
		Token:       os.Getenv(envToken),
	}

	// Recorded before the remote overlay, so a value set here is not silently replaced by
	// a central one. The environment outranks the config server; without this the
	// distinction between "set locally" and "left at the default" would be lost.
	fromEnvironment := map[string]bool{
		"address": os.Getenv(envAddress) != "",
		"token":   os.Getenv(envToken) != "",
	}

	for _, entry := range os.Environ() {
		name, value, found := strings.Cut(entry, "=")
		if !found || !strings.HasPrefix(name, keyPrefix) {
			continue
		}

		id := strings.ToLower(strings.TrimPrefix(name, keyPrefix))
		if value == "" {
			// A named but empty key is a half finished edit, not a request for a blank
			// key; carrying on would seal values under something unusable.
			return cfg, fmt.Errorf("%s is set but empty", name)
		}
		cfg.Keys[id] = value
	}

	if len(cfg.Keys) == 0 {
		return cfg, fmt.Errorf("no keys configured: set at least one %s<ID>", keyPrefix)
	}

	if cfg.ActiveKeyID == "" {
		if len(cfg.Keys) != 1 {
			return cfg, fmt.Errorf("%s is required when more than one key is configured", envActiveKey)
		}
		// With exactly one key there is nothing to choose, so naming it is busywork.
		for id := range cfg.Keys {
			cfg.ActiveKeyID = id
		}
	}

	cfg.ActiveKeyID = strings.ToLower(cfg.ActiveKeyID)

	// Last, and never fatal: the keys are already loaded, so this service can do its job
	// whatever the config server has to say. RemoteStatus records why it did not answer.
	cfg.RemoteStatus = applyRemote(&cfg, fromEnvironment)

	return cfg, nil
}

func valueOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
