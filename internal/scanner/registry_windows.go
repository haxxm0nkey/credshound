//go:build windows

package scanner

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

func scanRegistry(ctx context.Context, compiled []compiledCredential, opts Options) ([]Finding, error) {
	var findings []Finding
	for _, item := range compiled {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		for _, location := range item.locations {
			if strings.ToLower(location.Type) != "windows_registry" {
				continue
			}
			for _, rawPath := range splitPathList(location.Path) {
				key, display, err := openRegistryKey(rawPath)
				if err != nil {
					continue
				}
				keyFindings := scanRegistryKey(item, key, display, opts)
				key.Close()
				findings = append(findings, keyFindings...)
			}
		}
	}
	return findings, nil
}

func scanRegistryKey(item compiledCredential, key registry.Key, display string, opts Options) []Finding {
	names, err := key.ReadValueNames(-1)
	if err != nil {
		return nil
	}

	var findings []Finding
	for _, name := range names {
		value, _, err := key.GetStringValue(name)
		if err != nil {
			if ints, _, intErr := key.GetIntegerValue(name); intErr == nil {
				value = fmt.Sprintf("%d", ints)
			} else {
				continue
			}
		}

		evidence := name
		confidence := "medium"
		if value != "" {
			evidence = name + "=" + value
		}

		if len(item.patterns) > 0 {
			matched := false
			for _, re := range item.patterns {
				if re.MatchString(name) || re.MatchString(value) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}

		findings = append(findings, item.finding("registry", confidence, display+"\\"+name, evidence, opts))
	}
	return findings
}

func openRegistryKey(path string) (registry.Key, string, error) {
	hive, subkey, display, ok := parseRegistryPath(path)
	if !ok {
		return 0, "", fmt.Errorf("unsupported registry path %q", path)
	}
	key, err := registry.OpenKey(hive, subkey, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
	if err == nil {
		return key, display, nil
	}
	key, err = registry.OpenKey(hive, subkey, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS|registry.WOW64_32KEY)
	if err == nil {
		return key, display, nil
	}
	return 0, "", err
}

func parseRegistryPath(raw string) (registry.Key, string, string, bool) {
	normalized := strings.TrimSpace(raw)
	normalized = strings.TrimPrefix(normalized, `Registry::`)
	normalized = strings.ReplaceAll(normalized, `/`, `\`)
	normalized = strings.Replace(normalized, `:\`, `\`, 1)
	parts := strings.SplitN(normalized, `\`, 2)
	if len(parts) != 2 {
		return 0, "", "", false
	}

	hiveName := strings.ToUpper(parts[0])
	subkey := strings.Trim(parts[1], `\`)

	switch hiveName {
	case "HKCU", "HKEY_CURRENT_USER":
		return registry.CURRENT_USER, subkey, `HKCU\` + subkey, true
	case "HKLM", "HKEY_LOCAL_MACHINE":
		return registry.LOCAL_MACHINE, subkey, `HKLM\` + subkey, true
	case "HKCR", "HKEY_CLASSES_ROOT":
		return registry.CLASSES_ROOT, subkey, `HKCR\` + subkey, true
	case "HKU", "HKEY_USERS":
		return registry.USERS, subkey, `HKU\` + subkey, true
	default:
		return 0, "", "", false
	}
}
