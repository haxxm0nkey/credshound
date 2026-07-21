package scanner

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

const defaultFingerprintKeyBytes = 32
const defaultFingerprintKey = "credshound-default-fingerprint-key-v1"

func withFingerprintKey(opts Options) Options {
	if strings.TrimSpace(opts.FingerprintKey) != "" {
		return opts
	}
	if !opts.EphemeralFingerprint {
		opts.FingerprintKey = defaultFingerprintKey
		return opts
	}
	key := make([]byte, defaultFingerprintKeyBytes)
	if _, err := rand.Read(key); err != nil {
		return opts
	}
	opts.FingerprintKey = hex.EncodeToString(key)
	return opts
}

func fingerprintSecret(value string, opts Options) string {
	value = normalizeFingerprintSecret(value)
	if value == "" {
		return ""
	}
	key := strings.TrimSpace(opts.FingerprintKey)
	if key == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte(value))
	return "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil))[:32]
}

func normalizeFingerprintSecret(value string) string {
	value = strings.TrimSpace(value)
	if _, secret, ok := splitAssignment(value); ok {
		value = secret
	}
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"'[](){}<>`)
	return value
}
