package scanner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type semanticAIConfigCheck struct {
	ID             string
	Name           string
	CredentialType string
	Confidence     string
}

var (
	mcpEnvSecretCheck = semanticAIConfigCheck{
		ID:             "ai-mcp-env-secret",
		Name:           "MCP server environment secret",
		CredentialType: "secret_value",
		Confidence:     "high",
	}
	mcpInlineSecretCheck = semanticAIConfigCheck{
		ID:             "ai-mcp-inline-secret",
		Name:           "AI/MCP inline secret",
		CredentialType: "secret_value",
		Confidence:     "high",
	}
	mcpEnvReferenceCheck = semanticAIConfigCheck{
		ID:             "ai-mcp-env-reference",
		Name:           "AI/MCP environment variable reference",
		CredentialType: "environment",
		Confidence:     "info",
	}

	envReferencePattern      = regexp.MustCompile(`\$\{[A-Za-z_][A-Za-z0-9_]*\}`)
	bearerTokenPattern       = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{16,}`)
	assignmentSecretPattern  = regexp.MustCompile(`(?i)\b(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|refresh[_-]?token|client[_-]?secret|secret[_-]?key|secret|password|passwd|pwd)\b\s*[:=]\s*['"]?[A-Za-z0-9._~+/=-]{12,}`)
	envAssignmentPattern     = regexp.MustCompile(`(?i)\b[A-Z][A-Z0-9_]*(?:API[_-]?KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|AUTH)[A-Z0-9_]*\s*=\s*['"]?[A-Za-z0-9._~+/=-]{12,}`)
	quotedSecretLikePattern  = regexp.MustCompile(`^[A-Za-z0-9._~+/=-]{12,}$`)
	credentialWordSeparators = strings.NewReplacer("-", "_", ".", "_", " ", "_")
)

func scanSemanticAIConfigs(ctx context.Context, opts Options) ([]Finding, error) {
	targets, err := semanticAIConfigTargets(ctx, opts)
	if err != nil {
		return nil, err
	}

	var findings []Finding
	for _, target := range targets {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		content, ok, err := readScannableFile(target, opts)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
				continue
			}
			return findings, err
		}
		if !ok {
			continue
		}
		findings = append(findings, scanOneSemanticAIConfig(target, content, opts)...)
	}
	return findings, nil
}

func semanticAIConfigTargets(ctx context.Context, opts Options) ([]string, error) {
	seen := make(map[string]bool)
	var targets []string
	for _, rawPath := range semanticAIConfigPaths() {
		expanded, err := expandFileTargets(ctx, rawPath, opts)
		if err != nil {
			return targets, err
		}
		for _, target := range expanded {
			addTarget(&targets, seen, target)
		}
	}
	for _, rawPath := range semanticAIConfigGlobPaths() {
		expanded, err := expandSemanticGlobTargets(rawPath, opts)
		if err != nil {
			return targets, err
		}
		for _, target := range expanded {
			addTarget(&targets, seen, target)
		}
	}
	return targets, nil
}

func semanticAIConfigPaths() []string {
	return []string{
		".mcp.json",
		".claude/settings.json",
		".cline/agents.yaml",
		".cline/mcp.json",
		".codex/config.toml",
		".codex/mcp.json",
		".continue/config.json",
		".continue/config.yaml",
		".continue/config.yml",
		".cursor/mcp.json",
		".gemini/settings.json",
		".opencode.json",
		".windsurf/mcp.json",
		"~/Library/Application Support/Claude/claude_desktop_config.json",
		"~/.claude.json",
		"~/.claude/settings.json",
		"~/.cline/data/settings/cline_mcp_settings.json",
		"~/.codex/auth.json",
		"~/.codex/config.toml",
		"~/.codex/mcp.json",
		"~/.config/Claude/claude_desktop_config.json",
		"~/.config/cursor/mcp.json",
		"~/.config/github-copilot/hosts.json",
		"~/.config/opencode/opencode.json",
		"~/.config/windsurf/mcp_config.json",
		"~/.continue/config.json",
		"~/.continue/config.yaml",
		"~/.continue/config.yml",
		"~/.cursor/mcp.json",
		"~/.gemini/oauth_creds.json",
		"~/.gemini/settings.json",
		"~/.hermes/auth.json",
		"~/.hermes/config.yaml",
		"~/.opencode.json",
		"~/.windsurf/mcp.json",
		"%APPDATA%\\Claude\\claude_desktop_config.json",
		"%APPDATA%\\Cursor\\User\\mcp.json",
		"%APPDATA%\\Code\\User\\globalStorage\\saoudrizwan.claude-dev\\settings\\cline_mcp_settings.json",
		"%APPDATA%\\Codeium\\Windsurf\\mcp_config.json",
		"%USERPROFILE%\\.claude.json",
		"%USERPROFILE%\\.claude\\settings.json",
		"%USERPROFILE%\\.cline\\data\\settings\\cline_mcp_settings.json",
		"%USERPROFILE%\\.codex\\auth.json",
		"%USERPROFILE%\\.codex\\config.toml",
		"%USERPROFILE%\\.codex\\mcp.json",
		"%USERPROFILE%\\.continue\\config.json",
		"%USERPROFILE%\\.continue\\config.yaml",
		"%USERPROFILE%\\.cursor\\mcp.json",
		"%USERPROFILE%\\.gemini\\oauth_creds.json",
		"%USERPROFILE%\\.gemini\\settings.json",
		"%USERPROFILE%\\.hermes\\auth.json",
		"%USERPROFILE%\\.hermes\\config.yaml",
		"%USERPROFILE%\\.opencode.json",
	}
}

func semanticAIConfigGlobPaths() []string {
	return []string{
		".claude/backups/*.json",
		".continue/mcpServers/*.json",
		"~/.claude/backups/*.json",
		"~/.continue/mcpServers/*.json",
		"%USERPROFILE%\\.claude\\backups\\*.json",
		"%USERPROFILE%\\.continue\\mcpServers\\*.json",
	}
}

func expandSemanticGlobTargets(rawPath string, opts Options) ([]string, error) {
	if rawPath == "" || strings.Contains(rawPath, "**") {
		return nil, nil
	}
	var patterns []string
	if looksWindowsSpecific(rawPath) {
		patterns = expandWSLFileTargets(rawPath, opts)
		if len(patterns) == 0 {
			return nil, nil
		}
	} else {
		expanded := expandWindowsEnv(rawPath)
		expanded = os.ExpandEnv(expanded)
		expanded = expandHome(expanded)
		if filepath.IsAbs(expanded) {
			patterns = append(patterns, expanded)
		} else {
			for _, root := range opts.Roots {
				if root == "" {
					continue
				}
				patterns = append(patterns, filepath.Join(root, expanded))
			}
			if len(patterns) == 0 {
				patterns = append(patterns, expanded)
			}
		}
	}

	seen := make(map[string]bool)
	var targets []string
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return targets, fmt.Errorf("expand semantic AI config glob %q: %w", rawPath, err)
		}
		for _, match := range matches {
			info, err := os.Stat(match)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
					continue
				}
				return targets, err
			}
			if info.IsDir() {
				continue
			}
			addTarget(&targets, seen, match)
		}
	}
	return targets, nil
}

func scanOneSemanticAIConfig(path, content string, opts Options) []Finding {
	var findings []Finding
	seen := make(map[string]bool)
	var parsed any
	if err := yaml.Unmarshal([]byte(content), &parsed); err == nil && parsed != nil {
		scanSemanticNode(path, content, parsed, nil, opts, &findings, seen)
	}
	scanSemanticContentFallback(path, content, opts, &findings, seen)
	return findings
}

func scanSemanticNode(path, content string, node any, stack []string, opts Options, findings *[]Finding, seen map[string]bool) {
	switch value := node.(type) {
	case map[string]any:
		if mcp, ok := mapValueCI(value, "mcpServers", "mcp_servers"); ok {
			scanMCPServers(path, content, mcp, opts, findings, seen)
		}
		for key, child := range value {
			nextStack := append(stack, key)
			if stringValue, ok := scalarString(child); ok {
				recordSemanticString(path, content, key, stringValue, nextStack, opts, findings, seen)
			}
			scanSemanticNode(path, content, child, nextStack, opts, findings, seen)
		}
	case []any:
		for _, child := range value {
			scanSemanticNode(path, content, child, stack, opts, findings, seen)
		}
		scanArgListSecrets(path, content, value, opts, findings, seen)
	}
}

func scanMCPServers(path, content string, node any, opts Options, findings *[]Finding, seen map[string]bool) {
	switch servers := node.(type) {
	case map[string]any:
		for serverName, server := range servers {
			scanMCPServer(path, content, serverName, server, opts, findings, seen)
		}
	case []any:
		for _, server := range servers {
			name := "mcp-server"
			if serverMap, ok := server.(map[string]any); ok {
				if rawName, ok := scalarString(serverMap["name"]); ok && strings.TrimSpace(rawName) != "" {
					name = rawName
				}
			}
			scanMCPServer(path, content, name, server, opts, findings, seen)
		}
	}
}

func scanMCPServer(path, content, serverName string, node any, opts Options, findings *[]Finding, seen map[string]bool) {
	serverMap, ok := node.(map[string]any)
	if !ok {
		return
	}
	if envNode, ok := mapValueCI(serverMap, "env"); ok {
		if envMap, ok := envNode.(map[string]any); ok {
			for key, raw := range envMap {
				value, ok := scalarString(raw)
				if !ok {
					continue
				}
				for _, ref := range envReferences(value) {
					addSemanticFinding(path, content, mcpEnvReferenceCheck, ref, opts, findings, seen)
				}
				if suspiciousCredentialName(key) && secretValueLooksLike(value) {
					addSemanticFinding(path, content, mcpEnvSecretCheck, key+"="+value, opts, findings, seen)
				}
			}
		}
	}
	if argsNode, ok := mapValueCI(serverMap, "args"); ok {
		if args, ok := argsNode.([]any); ok {
			scanArgListSecrets(path, content, args, opts, findings, seen)
		}
	}
	_ = serverName
}

func recordSemanticString(path, content, key, value string, stack []string, opts Options, findings *[]Finding, seen map[string]bool) {
	for _, ref := range envReferences(value) {
		addSemanticFinding(path, content, mcpEnvReferenceCheck, ref, opts, findings, seen)
	}
	if suspiciousCredentialName(key) && secretValueLooksLike(value) {
		addSemanticFinding(path, content, mcpInlineSecretCheck, key+"="+value, opts, findings, seen)
		return
	}
	if suspiciousCredentialName(strings.Join(stack, "_")) && secretValueLooksLike(value) {
		addSemanticFinding(path, content, mcpInlineSecretCheck, value, opts, findings, seen)
	}
}

func scanArgListSecrets(path, content string, args []any, opts Options, findings *[]Finding, seen map[string]bool) {
	for i := 0; i < len(args); i++ {
		value, ok := scalarString(args[i])
		if !ok {
			continue
		}
		for _, ref := range envReferences(value) {
			addSemanticFinding(path, content, mcpEnvReferenceCheck, ref, opts, findings, seen)
		}
		if inlineSecretString(value) {
			addSemanticFinding(path, content, mcpInlineSecretCheck, value, opts, findings, seen)
			continue
		}
		if suspiciousCLIFlag(value) && i+1 < len(args) {
			next, ok := scalarString(args[i+1])
			if ok && secretValueLooksLike(next) {
				addSemanticFinding(path, content, mcpInlineSecretCheck, value+"="+next, opts, findings, seen)
			}
		}
	}
}

func scanSemanticContentFallback(path, content string, opts Options, findings *[]Finding, seen map[string]bool) {
	for _, re := range []*regexp.Regexp{envReferencePattern, bearerTokenPattern, assignmentSecretPattern, envAssignmentPattern} {
		for _, match := range re.FindAllString(content, -1) {
			check := mcpInlineSecretCheck
			if strings.HasPrefix(match, "${") {
				check = mcpEnvReferenceCheck
			}
			addSemanticFinding(path, content, check, match, opts, findings, seen)
		}
	}
}

func addSemanticFinding(path, content string, check semanticAIConfigCheck, evidence string, opts Options, findings *[]Finding, seen map[string]bool) {
	evidence = strings.TrimSpace(evidence)
	if evidence == "" {
		return
	}
	offset := semanticEvidenceOffset(content, evidence)
	line := 1
	if offset >= 0 {
		line = lineForOffset(content, offset)
	}
	location := pathWithLine(path, line)
	key := check.ID + "\x00" + location + "\x00" + evidence
	if seen[key] {
		return
	}
	seen[key] = true
	finding := Finding{
		TemplateID:     "filesystem",
		CredentialID:   check.ID,
		Origin:         OriginBuiltin,
		Product:        "AI/MCP configuration",
		Vendor:         "Unknown",
		Category:       "ai",
		Credential:     check.Name,
		Source:         "file",
		Confidence:     check.Confidence,
		Location:       location,
		CredentialType: check.CredentialType,
		Evidence:       evidence,
	}
	if check.Confidence != "info" {
		finding.SecretFingerprint = fingerprintSecret(evidence, opts)
		finding.Evidence = redact(evidence, opts.ShowSecrets)
	} else {
		finding.Evidence = evidence
	}
	*findings = append(*findings, finding)
}

func semanticEvidenceOffset(content, evidence string) int {
	if offset := strings.Index(content, evidence); offset >= 0 {
		return offset
	}
	key, value, ok := splitAssignment(evidence)
	if ok {
		if offset := strings.Index(content, key); offset >= 0 {
			return offset
		}
		value = strings.Trim(value, `"'`)
		if offset := strings.Index(content, value); offset >= 0 {
			return offset
		}
	}
	return -1
}

func mapValueCI(value map[string]any, keys ...string) (any, bool) {
	for existingKey, existingValue := range value {
		for _, key := range keys {
			if strings.EqualFold(existingKey, key) {
				return existingValue, true
			}
		}
	}
	return nil, false
}

func scalarString(value any) (string, bool) {
	switch typed := value.(type) {
	case string:
		return typed, true
	case fmt.Stringer:
		return typed.String(), true
	default:
		return "", false
	}
}

func envReferences(value string) []string {
	return envReferencePattern.FindAllString(value, -1)
}

func suspiciousCredentialName(name string) bool {
	normalized := strings.ToUpper(credentialWordSeparators.Replace(name))
	for _, token := range []string{"API_KEY", "APIKEY", "ACCESS_TOKEN", "AUTH_TOKEN", "BEARER_TOKEN", "CLIENT_SECRET", "REFRESH_TOKEN", "SECRET_KEY", "SECRET", "TOKEN", "PASSWORD", "PASSWD", "PWD"} {
		if strings.Contains(normalized, token) {
			return true
		}
	}
	return false
}

func secretValueLooksLike(value string) bool {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"'`)
	if value == "" || strings.HasPrefix(value, "${") {
		return false
	}
	lower := strings.ToLower(value)
	switch lower {
	case "false", "null", "none", "placeholder", "redacted", "secret", "token", "true", "your-api-key", "your-token":
		return false
	}
	if strings.Contains(lower, "example") || strings.Contains(lower, "replace_me") || strings.Contains(lower, "changeme") {
		return false
	}
	return len(value) >= 8 && quotedSecretLikePattern.MatchString(value)
}

func inlineSecretString(value string) bool {
	return bearerTokenPattern.MatchString(value) || assignmentSecretPattern.MatchString(value) || envAssignmentPattern.MatchString(value)
}

func suspiciousCLIFlag(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimLeft(value, "-")
	return suspiciousCredentialName(value)
}
