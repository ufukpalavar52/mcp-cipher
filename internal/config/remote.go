package config

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

// Reads the settings mcp-config holds for this service.
//
// Not a Spring client, so the two things a Spring client gets for free happen here:
// fetching /{application}/{profile}, and resolving the ${NAME:default} placeholders the
// config server deliberately leaves alone.
//
// **The keys are not among them, and must never be.** That config server's overrides reach
// every client; a key placed there would be handed to all of them, which is exactly what
// this service exists to prevent. Keys come from this process's environment and nowhere
// else. What is read remotely is where to listen and who may call — deployment facts, not
// secrets.
//
// The request is authenticated. mcp-config refuses an anonymous caller because it hands
// out the database password and the JWT signing key; the credentials come from this
// process's environment, the same pair every other client presents.

const (
	envConfigServer   = "CONFIG_SERVER_URL"
	envProfile        = "CONFIG_PROFILE"
	envConfigUser     = "CONFIG_USER"
	envConfigPassword = "CONFIG_PASSWORD"

	remoteApplication = "mcp-cipher"
	remotePrefix      = "mcp-cipher."
)

// remoteSettable is the allow list. Anything else served under the prefix is ignored, so
// adding a key centrally cannot change how this process behaves until someone here decides
// it should.
var remoteSettable = map[string]func(*Config, string){
	"address": func(c *Config, v string) { c.Address = v },
	"token":   func(c *Config, v string) { c.Token = v },
}

var placeholder = regexp.MustCompile(`\$\{([A-Za-z0-9_.-]+)(?::([^}]*))?\}`)

type environmentDocument struct {
	PropertySources []struct {
		Name   string         `json:"name"`
		Source map[string]any `json:"source"`
	} `json:"propertySources"`
}

// applyRemote overlays what the config server says, leaving anything already set by the
// environment alone.
//
// The environment wins, matching the precedence a Spring client applies: central
// configuration overrides the code's defaults, and the machine in front of you overrides
// both. Unreachable is not an error — this service must keep starting when the config
// server is down, because the alternative is that an outage there prevents anyone from
// reading a secret anywhere.
func applyRemote(cfg *Config, fromEnvironment map[string]bool) string {
	base := strings.TrimRight(os.Getenv(envConfigServer), "/")
	if base == "" {
		return "no CONFIG_SERVER_URL set"
	}

	profile := os.Getenv(envProfile)
	if profile == "" {
		profile = "default"
	}

	endpoint := fmt.Sprintf("%s/%s/%s", base, remoteApplication, profile)

	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Sprintf("%s is not a usable address: %v", endpoint, err)
	}

	if user := os.Getenv(envConfigUser); user != "" {
		request.SetBasicAuth(user, os.Getenv(envConfigPassword))
	}

	client := &http.Client{Timeout: 5 * time.Second}

	response, err := client.Do(request)
	if err != nil {
		return fmt.Sprintf("%s is unreachable: %v", endpoint, err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode == http.StatusUnauthorized {
		// Named, because the fix is a pair of variables rather than anything about this
		// service: without it the message is "answered 401" and the reader goes looking
		// for a problem in the config server.
		return fmt.Sprintf("%s refused the credentials; set %s and %s",
			endpoint, envConfigUser, envConfigPassword)
	}

	if response.StatusCode != http.StatusOK {
		return fmt.Sprintf("%s answered %d", endpoint, response.StatusCode)
	}

	var document environmentDocument
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
		return fmt.Sprintf("%s returned an unusable body: %v", endpoint, err)
	}

	served := flatten(document)

	for name, value := range served {
		if !strings.HasPrefix(name, remotePrefix) {
			continue
		}

		field := strings.TrimPrefix(name, remotePrefix)
		apply, allowed := remoteSettable[field]
		if !allowed || fromEnvironment[field] {
			continue
		}

		if resolved := resolve(value, served); resolved != "" {
			apply(cfg, resolved)
		}
	}

	return ""
}

// flatten collapses the property sources into one map. Earlier sources win, which is the
// precedence a Spring client applies: the service's own file overrides the shared one.
func flatten(document environmentDocument) map[string]any {
	merged := map[string]any{}

	for i := len(document.PropertySources) - 1; i >= 0; i-- {
		for name, value := range document.PropertySources[i].Source {
			merged[name] = value
		}
	}
	return merged
}

// resolve substitutes ${NAME:default}, in the order a Spring client would.
//
// The environment first, then the properties the config server itself served, then the
// inline default. That middle step is not optional: the config server cannot substitute a
// placeholder into a file it serves, so a value it wants to supply arrives as a separate
// property — mcp-config sends MCP_CIPHER_TOKEN alongside mcp-cipher.token=${MCP_CIPHER_TOKEN:}.
// Looking only at the environment resolved it to the empty default and quietly started the
// service with authentication switched off.
func resolve(value any, served map[string]any) string {
	text, ok := value.(string)
	if !ok {
		return fmt.Sprintf("%v", value)
	}

	return placeholder.ReplaceAllStringFunc(text, func(match string) string {
		parts := placeholder.FindStringSubmatch(match)
		name, fallback := parts[1], parts[2]

		if found := os.Getenv(name); found != "" {
			return found
		}
		if found, ok := served[name].(string); ok && found != "" {
			return found
		}
		return fallback
	})
}
