package cipher

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

func key(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("could not generate a key: %v", err)
	}
	return k
}

func TestRoundTrip(t *testing.T) {
	k := key(t)
	secret := []byte("sk-a-real-looking-api-key")

	sealed, err := Seal(k, secret, "model-api-key")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	if bytes.Contains(sealed, secret) {
		t.Fatal("the plaintext is present in the ciphertext")
	}

	opened, err := Open(k, sealed, "model-api-key")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(opened, secret) {
		t.Fatalf("got %q, want %q", opened, secret)
	}
}

// The property that makes AES-GCM the right choice: a value that has been altered fails
// to open, rather than opening into something else. A silently corrupted API key would be
// indistinguishable from a wrong one.
func TestATamperedValueDoesNotOpen(t *testing.T) {
	k := key(t)

	sealed, err := Seal(k, []byte("secret"), "ctx")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	for _, at := range []int{0, len(sealed) / 2, len(sealed) - 1} {
		altered := bytes.Clone(sealed)
		altered[at] ^= 0xFF

		if _, err := Open(k, altered, "ctx"); !errors.Is(err, ErrNotAuthentic) {
			t.Fatalf("a byte flipped at %d was accepted: %v", at, err)
		}
	}
}

// Binding the context is what stops one compromised call site reading another's secrets:
// a value sealed as a model key cannot be opened as an SSH key, even with the right key.
func TestTheContextIsBinding(t *testing.T) {
	k := key(t)

	sealed, err := Seal(k, []byte("secret"), "model-api-key")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	if _, err := Open(k, sealed, "ssh-private-key"); !errors.Is(err, ErrNotAuthentic) {
		t.Fatalf("a value opened under the wrong context: %v", err)
	}
}

func TestAnotherKeyDoesNotOpenIt(t *testing.T) {
	sealed, err := Seal(key(t), []byte("secret"), "ctx")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	if _, err := Open(key(t), sealed, "ctx"); !errors.Is(err, ErrNotAuthentic) {
		t.Fatalf("a different key opened the value: %v", err)
	}
}

// Nonce reuse under GCM leaks the key stream, so it must never happen — not even for the
// same plaintext under the same key, which is the case a careless implementation gets
// wrong by deriving the nonce from the input.
func TestEachSealUsesAFreshNonce(t *testing.T) {
	k := key(t)
	seen := map[string]bool{}

	for i := 0; i < 500; i++ {
		sealed, err := Seal(k, []byte("identical plaintext"), "ctx")
		if err != nil {
			t.Fatalf("seal: %v", err)
		}

		nonce := string(sealed[:12])
		if seen[nonce] {
			t.Fatal("a nonce was reused")
		}
		seen[nonce] = true
	}
}

func TestATruncatedValueIsRejected(t *testing.T) {
	if _, err := Open(key(t), []byte{1, 2, 3}, "ctx"); !errors.Is(err, ErrCiphertextTooShort) {
		t.Fatal("a value shorter than a nonce was not rejected")
	}
}

func TestAnEmptyPlaintextRoundTrips(t *testing.T) {
	// Not a useful secret, but it must not be a crash: the server rejects empty input,
	// and this layer should not also depend on that.
	k := key(t)

	sealed, err := Seal(k, []byte{}, "ctx")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	opened, err := Open(k, sealed, "ctx")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if len(opened) != 0 {
		t.Fatalf("got %q, want empty", opened)
	}
}
