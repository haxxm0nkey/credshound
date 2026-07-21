package scanner

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type builtinFileCheck struct {
	ID                         string
	Name                       string
	Product                    string
	Vendor                     string
	Category                   string
	CredentialType             string
	Paths                      []string
	GlobPaths                  []string
	ExcludeNames               []string
	Patterns                   []*regexp.Regexp
	TemplateCrossCheck         bool
	TemplateLocationCrossCheck bool
}

type builtinFileCheckData struct {
	ID                         string   `yaml:"id"`
	Name                       string   `yaml:"name"`
	Product                    string   `yaml:"product"`
	Vendor                     string   `yaml:"vendor"`
	Category                   string   `yaml:"category"`
	CredentialType             string   `yaml:"type"`
	Paths                      []string `yaml:"paths"`
	GlobPaths                  []string `yaml:"glob_paths"`
	ExcludeNames               []string `yaml:"exclude_names"`
	Patterns                   []string `yaml:"patterns"`
	TemplateCrossCheck         bool     `yaml:"template_cross_check"`
	TemplateLocationCrossCheck bool     `yaml:"template_location_cross_check"`
}

type builtinFileCheckSet struct {
	Checks []builtinFileCheckData `yaml:"checks"`
}

//go:embed builtin_checks.yaml
var builtinChecksYAML []byte

var builtinFileChecks = mustLoadBuiltinFileChecks(builtinChecksYAML)

func mustLoadBuiltinFileChecks(data []byte) []builtinFileCheck {
	checks, err := loadBuiltinFileChecks(data)
	if err != nil {
		panic(err)
	}
	return checks
}

func loadBuiltinFileChecks(data []byte) ([]builtinFileCheck, error) {
	var raw builtinFileCheckSet
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse builtin checks: %w", err)
	}
	if len(raw.Checks) == 0 {
		return nil, fmt.Errorf("parse builtin checks: no checks defined")
	}

	checks := make([]builtinFileCheck, 0, len(raw.Checks))
	for _, item := range raw.Checks {
		if item.ID == "" {
			return nil, fmt.Errorf("parse builtin checks: check id is required")
		}
		if item.Name == "" {
			return nil, fmt.Errorf("parse builtin checks: check %q name is required", item.ID)
		}
		if item.CredentialType == "" {
			return nil, fmt.Errorf("parse builtin checks: check %q type is required", item.ID)
		}
		if len(item.Paths) == 0 {
			return nil, fmt.Errorf("parse builtin checks: check %q paths are required", item.ID)
		}
		if len(item.Patterns) == 0 {
			return nil, fmt.Errorf("parse builtin checks: check %q patterns are required", item.ID)
		}

		check := builtinFileCheck{
			ID:                         item.ID,
			Name:                       item.Name,
			Product:                    firstNonEmpty(item.Product, "Filesystem"),
			Vendor:                     item.Vendor,
			Category:                   categoryOrUnknown(item.Category),
			CredentialType:             item.CredentialType,
			Paths:                      item.Paths,
			GlobPaths:                  item.GlobPaths,
			ExcludeNames:               item.ExcludeNames,
			TemplateCrossCheck:         item.TemplateCrossCheck,
			TemplateLocationCrossCheck: item.TemplateLocationCrossCheck,
			Patterns:                   make([]*regexp.Regexp, 0, len(item.Patterns)),
		}
		for _, pattern := range item.Patterns {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("parse builtin checks: check %q pattern %q: %w", item.ID, pattern, err)
			}
			check.Patterns = append(check.Patterns, re)
		}
		checks = append(checks, check)
	}
	return checks, nil
}

func builtinTemplateCrossCheckTargets(ctx context.Context, opts Options) ([]string, error) {
	seen := make(map[string]bool)
	var targets []string
	for _, check := range builtinFileChecks {
		if !check.TemplateCrossCheck {
			continue
		}
		for _, rawPath := range check.Paths {
			expanded, err := expandFileTargets(ctx, rawPath, opts)
			if err != nil {
				return targets, err
			}
			for _, target := range expanded {
				addTarget(&targets, seen, target)
			}
		}
	}
	return targets, nil
}

func scanBuiltinFiles(ctx context.Context, opts Options) ([]Finding, error) {
	var findings []Finding
	for _, check := range builtinFileChecks {
		targets, err := builtinTargets(ctx, check, opts)
		if err != nil {
			return findings, err
		}
		for _, target := range targets {
			select {
			case <-ctx.Done():
				return findings, ctx.Err()
			default:
			}

			fileFindings, err := scanOneBuiltinFile(check, target, opts, true)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
					continue
				}
				return findings, err
			}
			findings = append(findings, fileFindings...)
		}
	}
	semanticFindings, err := scanSemanticAIConfigs(ctx, opts)
	if err != nil {
		return findings, err
	}
	findings = append(findings, semanticFindings...)
	return findings, nil
}

func builtinTargets(ctx context.Context, check builtinFileCheck, opts Options) ([]string, error) {
	seen := make(map[string]bool)
	var targets []string
	for _, rawPath := range check.Paths {
		expanded, err := expandFileTargets(ctx, rawPath, opts)
		if err != nil {
			return targets, err
		}
		for _, target := range expanded {
			if shouldSkipBuiltinTarget(check, target) {
				continue
			}
			addTarget(&targets, seen, target)
		}
	}
	for _, rawPath := range check.GlobPaths {
		expanded, err := expandBuiltinGlobPath(rawPath, check)
		if err != nil {
			return targets, err
		}
		for _, target := range expanded {
			select {
			case <-ctx.Done():
				return targets, ctx.Err()
			default:
			}
			if shouldSkipBuiltinTarget(check, target) {
				continue
			}
			addTarget(&targets, seen, target)
		}
	}
	return targets, nil
}

func scanBuiltinTemplateLocationCrossCheckFiles(targets []string, opts Options) ([]Finding, error) {
	var findings []Finding
	if len(targets) == 0 {
		return findings, nil
	}
	for _, check := range builtinFileChecks {
		if !check.TemplateLocationCrossCheck {
			continue
		}
		for _, target := range targets {
			fileFindings, err := scanOneBuiltinFile(check, target, opts, false)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
					continue
				}
				return findings, err
			}
			findings = append(findings, fileFindings...)
		}
	}
	return findings, nil
}

func expandBuiltinGlobPath(rawPath string, check builtinFileCheck) ([]string, error) {
	if rawPath == "" {
		return nil, nil
	}
	if strings.Contains(rawPath, "**") {
		return nil, fmt.Errorf("parse builtin checks: check %q recursive glob %q is not supported", check.ID, rawPath)
	}
	if looksWindowsSpecific(rawPath) {
		return nil, nil
	}

	expanded := expandWindowsEnv(rawPath)
	expanded = os.ExpandEnv(expanded)
	expanded = expandHome(expanded)
	matches, err := filepath.Glob(expanded)
	if err != nil {
		return nil, fmt.Errorf("expand builtin glob %q: %w", rawPath, err)
	}
	out := make([]string, 0, len(matches))
	for _, match := range matches {
		info, err := os.Stat(match)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
				continue
			}
			return out, err
		}
		if info.IsDir() {
			continue
		}
		out = append(out, filepath.Clean(match))
	}
	return out, nil
}

func shouldSkipBuiltinTarget(check builtinFileCheck, path string) bool {
	name := filepath.Base(path)
	for _, pattern := range check.ExcludeNames {
		if pattern == "" {
			continue
		}
		if matched, err := filepath.Match(pattern, name); err == nil && matched {
			return true
		}
		if pattern == name {
			return true
		}
	}
	return false
}

func scanOneBuiltinFile(check builtinFileCheck, path string, opts Options, includeInfo bool) ([]Finding, error) {
	content, ok, err := readScannableFile(path, opts)
	if err != nil || !ok {
		return nil, err
	}

	var findings []Finding
	if includeInfo {
		findings = append(findings, builtinInfoFinding(path))
	}
	seen := make(map[string]bool)
	for _, re := range check.Patterns {
		matches := re.FindAllStringIndex(content, -1)
		for _, match := range matches {
			evidence := content[match[0]:match[1]]
			location := pathWithLine(path, lineForOffset(content, match[0]))
			key := location + "\x00" + evidence
			if seen[key] {
				continue
			}
			seen[key] = true
			findings = append(findings, builtinFinding(check, location, evidence, opts))
		}
	}
	return findings, nil
}

func builtinInfoFinding(location string) Finding {
	return Finding{
		TemplateID:     "filesystem",
		CredentialID:   "interesting-location",
		Origin:         OriginBuiltin,
		Product:        "Filesystem",
		Credential:     "Interesting location",
		Source:         "file",
		Confidence:     "info",
		Location:       location,
		CredentialType: "config_file",
		Evidence:       "path exists",
	}
}

func builtinFinding(check builtinFileCheck, location, evidence string, opts Options) Finding {
	return Finding{
		TemplateID:        "filesystem",
		CredentialID:      check.ID,
		Origin:            OriginBuiltin,
		Product:           check.Product,
		Vendor:            check.Vendor,
		Category:          check.Category,
		Credential:        check.Name,
		Source:            "file",
		Confidence:        "high",
		Location:          location,
		CredentialType:    check.CredentialType,
		Evidence:          redact(evidence, opts.ShowSecrets),
		SecretFingerprint: fingerprintSecret(evidence, opts),
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}
