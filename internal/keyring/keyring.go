// Package keyring holds the keys this service seals values with.
//
// More than one, deliberately. A single key means rotation is impossible without a
// flag day: every stored value would have to be re-encrypted in the same moment the key
// changes, and anything missed becomes unreadable. With a ring, one key is active for new
// values while every key still opens what it sealed, so rotation is a background job
// rather than an outage.
package keyring

import (
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ErrUnknownKey is returned for a key id the ring does not hold. It is deliberately
// indistinguishable from a wrong key id and a retired one: a caller learns that it cannot
// be opened, not why.
var ErrUnknownKey = errors.New("no such key")

// Keyring is immutable once built. Rotation replaces the ring rather than mutating it, so
// a request in flight always sees a consistent set.
type Keyring struct {
	keys     map[string][]byte
	activeID string
}

// New builds a ring from id/key pairs and names the active one.
//
// Keys are validated here rather than at first use: a service that starts with an
// unusable key and only says so when someone tries to save a secret has turned a
// configuration error into a runtime one.
func New(keys map[string]string, activeID string) (*Keyring, error) {
	if len(keys) == 0 {
		return nil, errors.New("keyring is empty: configure at least one key")
	}

	decoded := make(map[string][]byte, len(keys))

	for id, encoded := range keys {
		if strings.TrimSpace(id) == "" {
			return nil, errors.New("a key id may not be blank")
		}

		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
		if err != nil {
			return nil, fmt.Errorf("key %q is not valid base64: %w", id, err)
		}

		// AES-128, AES-192 or AES-256. Anything else is a typo rather than a choice.
		switch len(raw) {
		case 16, 24, 32:
		default:
			return nil, fmt.Errorf("key %q must decode to 16, 24 or 32 bytes, got %d", id, len(raw))
		}

		decoded[id] = raw
	}

	if _, ok := decoded[activeID]; !ok {
		return nil, fmt.Errorf("active key %q is not in the keyring", activeID)
	}

	return &Keyring{keys: decoded, activeID: activeID}, nil
}

// ActiveID names the key new values are sealed under.
func (r *Keyring) ActiveID() string {
	return r.activeID
}

// Active returns the key new values are sealed under.
func (r *Keyring) Active() (string, []byte) {
	return r.activeID, r.keys[r.activeID]
}

// Get returns the key with this id. An empty id means the active key, which lets a caller
// that has never rotated omit it entirely.
func (r *Keyring) Get(id string) ([]byte, error) {
	if id == "" {
		return r.keys[r.activeID], nil
	}

	key, ok := r.keys[id]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownKey, id)
	}
	return key, nil
}

// IDs lists every key that can still decrypt, sorted so the output is stable.
func (r *Keyring) IDs() []string {
	ids := make([]string, 0, len(r.keys))
	for id := range r.keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
