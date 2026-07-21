package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestFingerprintSecretUsesKeyedNormalizedValue(t *testing.T) {
	opts := Options{FingerprintKey: "test-fingerprint-key"}

	first := fingerprintSecret(`TOKEN="super-secret-value"`, opts)
	second := fingerprintSecret("super-secret-value", opts)
	if first == "" {
		t.Fatal("expected fingerprint")
	}
	if first != second {
		t.Fatalf("expected assignment and raw secret to share fingerprint, got %q and %q", first, second)
	}

	otherKey := fingerprintSecret("super-secret-value", Options{FingerprintKey: "other-key"})
	if first == otherKey {
		t.Fatalf("expected different key to produce different fingerprint %q", first)
	}

	plain := sha256.Sum256([]byte("super-secret-value"))
	if first == "hmac-sha256:"+hex.EncodeToString(plain[:])[:32] {
		t.Fatalf("expected fingerprint to differ from plain SHA-256")
	}
}

func TestWithFingerprintKeyUsesStableDefault(t *testing.T) {
	opts := withFingerprintKey(Options{})
	if opts.FingerprintKey != defaultFingerprintKey {
		t.Fatalf("expected stable default fingerprint key, got %q", opts.FingerprintKey)
	}
}

func TestWithFingerprintKeyUsesEphemeralWhenRequested(t *testing.T) {
	first := withFingerprintKey(Options{EphemeralFingerprint: true})
	second := withFingerprintKey(Options{EphemeralFingerprint: true})
	if first.FingerprintKey == "" || second.FingerprintKey == "" {
		t.Fatalf("expected ephemeral fingerprint keys, got %q and %q", first.FingerprintKey, second.FingerprintKey)
	}
	if first.FingerprintKey == second.FingerprintKey {
		t.Fatalf("expected different ephemeral fingerprint keys, got %q", first.FingerprintKey)
	}
}
