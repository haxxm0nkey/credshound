package scanner

import "strings"

func redact(value string, show bool) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, "\n", `\n`)
	value = strings.ReplaceAll(value, "\r", `\r`)
	if show {
		return truncate(value, 220)
	}

	if key, secret, ok := splitAssignment(value); ok {
		return truncate(key+"="+redactSecret(secret), 220)
	}
	return truncate(redactSecret(value), 220)
}

func splitAssignment(value string) (string, string, bool) {
	idx := strings.Index(value, "=")
	colon := strings.Index(value, ":")
	if idx < 0 || (colon >= 0 && colon < idx) {
		idx = colon
	}
	if idx < 0 {
		return "", "", false
	}
	key := strings.TrimSpace(value[:idx])
	secret := strings.TrimSpace(value[idx+1:])
	if key == "" || secret == "" {
		return "", "", false
	}
	return key, secret, true
}

func redactSecret(value string) string {
	value = strings.Trim(value, `"'`)
	if len(value) <= 8 {
		return "****"
	}
	return value[:4] + "****" + value[len(value)-4:]
}

func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max-3] + "..."
}
