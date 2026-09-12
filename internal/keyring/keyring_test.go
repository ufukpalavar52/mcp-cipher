package keyring

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func aes256() string {
	return base64.StdEncoding.EncodeToString(make([]byte, 32))
}

func TestRotationKeepsOldKeysReadable(t *testing.T) {
	// The reason the ring exists. Retiring a key for new values must not make the values
	// it already sealed unreadable, or rotation would mean re-encrypting everything in
	// the same moment — and anything missed would be lost.
	ring, err := New(map[string]string{"v1": aes256(), "v2": aes256()}, "v2")
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	if ring.ActiveID() != "v2" {
		t.Fatalf("active is %q, want v2", ring.ActiveID())
	}
	if _, err := ring.Get("v1"); err != nil {
		t.Fatalf("the retired key can no longer decrypt: %v", err)
	}
}

func TestASingleKeyNeedsNoActiveDeclaration(t *testing.T) {
	ring, err := New(map[string]string{"only": aes256()}, "only")
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if _, err := ring.Get(""); err != nil {
		t.Fatalf("an empty id should mean the active key: %v", err)
	}
}

func TestAnUnknownKeyIsReported(t *testing.T) {
	ring, _ := New(map[string]string{"v1": aes256()}, "v1")

	if _, err := ring.Get("v9"); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("got %v, want ErrUnknownKey", err)
	}
}

// Validation at construction, not at first use: a service that starts with an unusable key
// and only says so when someone saves a secret has turned a deploy-time error into a
// runtime one.
func TestUnusableConfigurationIsRejectedAtStartUp(t *testing.T) {
	cases := map[string]struct {
		keys   map[string]string
		active string
		want   string
	}{
		"empty ring":         {map[string]string{}, "v1", "at least one key"},
		"not base64":         {map[string]string{"v1": "not base64!!"}, "v1", "valid base64"},
		"wrong key length":   {map[string]string{"v1": base64.StdEncoding.EncodeToString(make([]byte, 7))}, "v1", "16, 24 or 32 bytes"},
		"active not in ring": {map[string]string{"v1": aes256()}, "v2", "not in the keyring"},
		"blank id":           {map[string]string{" ": aes256()}, " ", "may not be blank"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := New(tc.keys, tc.active)
			if err == nil {
				t.Fatal("accepted an unusable configuration")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestIDsAreStable(t *testing.T) {
	// Reported over the wire, so an unstable order would show up as spurious changes.
	ring, _ := New(map[string]string{"v2": aes256(), "v1": aes256(), "v3": aes256()}, "v3")

	ids := ring.IDs()
	if len(ids) != 3 || ids[0] != "v1" || ids[2] != "v3" {
		t.Fatalf("got %v, want sorted", ids)
	}
}
