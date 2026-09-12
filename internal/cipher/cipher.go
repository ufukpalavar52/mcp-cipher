// Package cipher seals and opens individual values.
//
// AES-GCM throughout: authenticated encryption, so a value that has been altered fails to
// open rather than opening into something else. That property is the whole reason to
// prefer it here — a silently corrupted API key would be indistinguishable from a wrong
// one, and the failure would surface as a puzzling 401 from a model provider.
package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// ErrCiphertextTooShort means the value cannot even contain a nonce, so it was never
// produced by Seal.
var ErrCiphertextTooShort = errors.New("ciphertext is too short to contain a nonce")

// ErrNotAuthentic means the value failed its authentication tag: it was altered, sealed
// under a different key, or sealed for a different context.
var ErrNotAuthentic = errors.New("ciphertext failed authentication")

// Seal encrypts plaintext under key, binding context into the result.
//
// The layout is [nonce][ciphertext+tag], one blob in one column. A nonce stored separately
// is a second field that has to stay in step with the first, and the day it does not the
// value is unrecoverable.
//
// The nonce is random per call and never derived from the plaintext, the key or a counter.
// Reusing a nonce under GCM does not merely weaken it: it leaks the key stream and lets an
// attacker forge messages.
func Seal(key, plaintext []byte, context string) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("could not generate a nonce: %w", err)
	}

	// The nonce is prepended by passing it as dst, which Seal appends to.
	return aead.Seal(nonce, nonce, plaintext, []byte(context)), nil
}

// Open decrypts a value produced by Seal.
//
// A mismatched context fails exactly as a wrong key does. That is the point of binding it:
// a value sealed as a model API key cannot be opened as an SSH key even by a caller
// holding both, so one compromised call site cannot read another's secrets.
func Open(key, sealed []byte, context string) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}

	if len(sealed) < aead.NonceSize() {
		return nil, ErrCiphertextTooShort
	}

	nonce, body := sealed[:aead.NonceSize()], sealed[aead.NonceSize():]

	plaintext, err := aead.Open(nil, nonce, body, []byte(context))
	if err != nil {
		// The underlying error says only "message authentication failed" and is not worth
		// passing on; what matters is that nothing can be trusted from this value.
		return nil, ErrNotAuthentic
	}
	return plaintext, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("invalid key: %w", err)
	}
	return cipher.NewGCM(block)
}
