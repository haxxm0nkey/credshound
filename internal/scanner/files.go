package scanner

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

func scanFiles(ctx context.Context, compiled []compiledCredential, opts Options) ([]Finding, error) {
	var findings []Finding
	var templateCrossCheckTargets []string
	seenTemplateConfigTargets := make(map[string]bool)
	var templateConfigTargets []string
	if opts.EnableBuiltins {
		targets, err := builtinTemplateCrossCheckTargets(ctx, opts)
		if err != nil {
			return findings, err
		}
		templateCrossCheckTargets = targets
	}

	for _, item := range compiled {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		var configTargets []string
		for _, location := range item.locations {
			if strings.ToLower(location.Type) != "config_file" {
				continue
			}
			for _, rawPath := range splitPathList(location.Path) {
				targets, err := expandFileTargets(ctx, rawPath, opts)
				if err != nil {
					return findings, err
				}
				configTargets = append(configTargets, targets...)
				for _, target := range targets {
					addTarget(&templateConfigTargets, seenTemplateConfigTargets, target)
					fileFindings, err := scanOneConfigFile(item, target, opts)
					if err != nil {
						if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
							continue
						}
						return findings, err
					}
					findings = append(findings, fileFindings...)
				}
			}
		}

		if len(item.patterns) > 0 && len(templateCrossCheckTargets) > 0 {
			crossCheckFindings, err := scanTemplatePatternsInFiles(item, templateCrossCheckTargets, opts)
			if err != nil {
				return findings, err
			}
			findings = append(findings, crossCheckFindings...)
		}

		envNames := environmentVariableNames(item)
		if len(envNames) > 0 {
			targets, err := envCrossCheckTargets(ctx, configTargets, templateCrossCheckTargets, opts)
			if err != nil {
				return findings, err
			}
			envFindings, err := scanEnvNamesInFiles(item, envNames, targets, opts)
			if err != nil {
				return findings, err
			}
			findings = append(findings, envFindings...)
		}
	}
	if opts.EnableBuiltins {
		builtinFindings, err := scanBuiltinTemplateLocationCrossCheckFiles(templateConfigTargets, opts)
		if err != nil {
			return findings, err
		}
		findings = append(findings, builtinFindings...)
	}
	return findings, nil
}

func scanOneConfigFile(item compiledCredential, path string, opts Options) ([]Finding, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, nil
	}
	if opts.MaxFileSize > 0 && info.Size() > opts.MaxFileSize {
		return nil, nil
	}

	findings := []Finding{item.infoFinding("file", path, "path exists", opts)}
	if len(item.patterns) == 0 {
		return findings, nil
	}

	patternFindings, err := scanOneFile(item, path, opts)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return findings, nil
		}
		return nil, err
	}
	findings = append(findings, patternFindings...)
	return findings, nil
}

func scanOneFile(item compiledCredential, path string, opts Options) ([]Finding, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, nil
	}
	if opts.MaxFileSize > 0 && info.Size() > opts.MaxFileSize {
		return nil, nil
	}

	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	content := string(b)
	return scanContentPatterns(item, path, content, allPatternIndexes(item), opts), nil
}

func scanContentPatterns(item compiledCredential, path, content string, patternIndexes []int, opts Options) []Finding {
	var findings []Finding
	seen := make(map[string]bool)
	for _, patternIndex := range patternIndexes {
		if patternIndex < 0 || patternIndex >= len(item.patterns) {
			continue
		}
		re := item.patterns[patternIndex]
		matches := re.FindAllStringIndex(content, -1)
		for _, match := range matches {
			evidence := content[match[0]:match[1]]
			line := lineForOffset(content, match[0])
			location := pathWithLine(path, line)
			key := location + "\x00" + evidence
			if seen[key] {
				continue
			}
			seen[key] = true
			findings = append(findings, item.finding("file", "high", location, evidence, opts))
		}
	}
	return findings
}

func allPatternIndexes(item compiledCredential) []int {
	indexes := make([]int, len(item.patterns))
	for i := range item.patterns {
		indexes[i] = i
	}
	return indexes
}

func environmentVariableNames(item compiledCredential) []string {
	seen := make(map[string]bool)
	var names []string
	for _, location := range item.locations {
		if strings.ToLower(location.Type) != "environment" {
			continue
		}
		for _, name := range splitPathList(location.Path) {
			name = strings.TrimSpace(name)
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			names = append(names, name)
		}
	}
	return names
}

func scanTemplatePatternsInFiles(item compiledCredential, targets []string, opts Options) ([]Finding, error) {
	var findings []Finding
	patternIndexes := templateCrossCheckPatternIndexes(item)
	if len(patternIndexes) == 0 {
		return findings, nil
	}
	for _, target := range targets {
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
		fileFindings := scanContentPatterns(item, target, content, patternIndexes, opts)
		findings = append(findings, fileFindings...)
	}
	return findings, nil
}

func templateCrossCheckPatternIndexes(item compiledCredential) []int {
	if !credentialTypeEligibleForCrossCheck(item.cred.Type) {
		return nil
	}

	var indexes []int
	for i, pattern := range item.patternRaw {
		if patternEligibleForCrossCheck(pattern) {
			indexes = append(indexes, i)
		}
	}
	return indexes
}

func credentialTypeEligibleForCrossCheck(credentialType string) bool {
	credentialType = strings.ToLower(strings.TrimSpace(credentialType))
	if credentialType == "" {
		return false
	}
	if strings.Contains(credentialType, "password") || strings.Contains(credentialType, "connection") {
		return false
	}
	return strings.Contains(credentialType, "token") ||
		strings.Contains(credentialType, "secret") ||
		strings.Contains(credentialType, "key")
}

func patternEligibleForCrossCheck(pattern string) bool {
	lower := strings.ToLower(pattern)
	for _, fragment := range []string{
		`[^\s:@]+:[^\s`,
		`[^\\s:@]+:[^\\s`,
		`[^\s:@]+@[^\s:@]+`,
		`[^\\s:@]+@[^\\s:@]+`,
	} {
		if strings.Contains(lower, fragment) {
			return false
		}
	}
	return hasSpecificCredentialLiteral(pattern)
}

func hasSpecificCredentialLiteral(pattern string) bool {
	for _, literal := range literalAlphaNumRuns(pattern) {
		literal = strings.ToLower(literal)
		if len(literal) >= 2 && !genericCrossCheckLiteral(literal) {
			return true
		}
	}
	return false
}

func literalAlphaNumRuns(pattern string) []string {
	var runs []string
	var current strings.Builder
	inClass := false
	inRepeat := false
	escaped := false

	flush := func() {
		if current.Len() > 0 {
			runs = append(runs, current.String())
			current.Reset()
		}
	}

	for _, r := range pattern {
		switch {
		case escaped:
			escaped = false
			if !inClass && !inRepeat && isAlphaNumRune(r) {
				current.WriteRune(r)
			} else {
				flush()
			}
			continue
		case r == '\\':
			escaped = true
			flush()
			continue
		case inClass:
			if r == ']' {
				inClass = false
			}
			continue
		case inRepeat:
			if r == '}' {
				inRepeat = false
			}
			continue
		case r == '[':
			inClass = true
			flush()
			continue
		case r == '{':
			inRepeat = true
			flush()
			continue
		case isAlphaNumRune(r):
			current.WriteRune(r)
		default:
			flush()
		}
	}
	flush()
	return runs
}

func genericCrossCheckLiteral(literal string) bool {
	switch literal {
	case "access", "accesskey", "admin", "api", "apikey", "appsecret", "authorization", "basic", "bearer", "begin", "client", "credential", "credentials", "dsa", "ec", "encrypted", "end", "header", "key", "login", "openssh", "password", "passphrase", "passwd", "private", "pwd", "rsa", "secret", "secretkey", "signingsecret", "token", "user", "username", "value":
		return true
	default:
		return false
	}
}

func isAlphaNumRune(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
}

func envCrossCheckTargets(ctx context.Context, configTargets, templateCrossCheckTargets []string, opts Options) ([]string, error) {
	seen := make(map[string]bool)
	var targets []string
	for _, target := range configTargets {
		addTarget(&targets, seen, target)
	}
	for _, target := range templateCrossCheckTargets {
		addTarget(&targets, seen, target)
	}
	for _, rawPath := range defaultCredentialFilePaths() {
		expanded, err := expandFileTargets(ctx, rawPath, opts)
		if err != nil {
			return targets, err
		}
		for _, target := range expanded {
			addTarget(&targets, seen, target)
		}
	}
	return targets, nil
}

func addTarget(targets *[]string, seen map[string]bool, target string) {
	if target == "" {
		return
	}
	clean := filepath.Clean(target)
	if seen[clean] {
		return
	}
	seen[clean] = true
	*targets = append(*targets, clean)
}

func scanEnvNamesInFiles(item compiledCredential, names, targets []string, opts Options) ([]Finding, error) {
	var findings []Finding
	for _, target := range targets {
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

		for _, name := range names {
			for _, offset := range envNameOffsets(content, name) {
				location := pathWithLine(target, lineForOffset(content, offset))
				findings = append(findings, item.infoFinding("file", location, name, opts))
			}
		}
	}
	return findings, nil
}

func readScannableFile(path string, opts Options) (string, bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", false, err
	}
	if info.IsDir() {
		return "", false, nil
	}
	if opts.MaxFileSize > 0 && info.Size() > opts.MaxFileSize {
		return "", false, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false, err
	}
	return string(b), true, nil
}

func envNameOffsets(content, name string) []int {
	var offsets []int
	start := 0
	for {
		idx := strings.Index(content[start:], name)
		if idx < 0 {
			return offsets
		}
		offset := start + idx
		end := offset + len(name)
		if isEnvNameBoundary(content, offset-1) && isEnvNameBoundary(content, end) {
			offsets = append(offsets, offset)
		}
		start = end
	}
}

func isEnvNameBoundary(content string, index int) bool {
	if index < 0 || index >= len(content) {
		return true
	}
	ch := content[index]
	return !(ch == '_' || ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9')
}

func defaultCredentialFilePaths() []string {
	return []string{
		".env",
		".env.development",
		".env.local",
		".env.production",
		".env.test",
		".envrc",
		".git/config",
		".git-credentials",
		".netrc",
		"auth.json",
		"auth.yaml",
		"auth.yml",
		"config.ini",
		"config.json",
		"config.toml",
		"config.yaml",
		"config.yml",
		"config/config.ini",
		"config/config.json",
		"config/config.toml",
		"config/config.yaml",
		"config/config.yml",
		"config/credentials",
		"config/secrets",
		"credentials",
		"credentials.ini",
		"credentials.json",
		"credentials.toml",
		"credentials.yaml",
		"credentials.yml",
		"secrets",
		"secrets.ini",
		"secrets.json",
		"secrets.toml",
		"secrets.yaml",
		"secrets.yml",
		"settings.ini",
		"settings.json",
		"settings.toml",
		"settings.yaml",
		"settings.yml",
		"values.yaml",
		"values.yml",
		"ConsoleHost_history.txt",
		"~/.config/config.ini",
		"~/.config/config.json",
		"~/.config/config.toml",
		"~/.config/config.yaml",
		"~/.config/config.yml",
		"~/.config/credentials",
		"~/.config/secrets",
		"~/.git-credentials",
		"~/.netrc",
		"%APPDATA%\\config.ini",
		"%APPDATA%\\config.json",
		"%APPDATA%\\config.toml",
		"%APPDATA%\\config.yaml",
		"%APPDATA%\\config.yml",
		"%APPDATA%\\credentials",
		"%APPDATA%\\secrets",
		"%APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
		"%APPDATA%\\Microsoft\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
		"%USERPROFILE%\\.git-credentials",
		"%USERPROFILE%\\.netrc",
		"%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
		"%USERPROFILE%\\AppData\\Roaming\\Microsoft\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
	}
}

func expandFileTargets(ctx context.Context, rawPath string, opts Options) ([]string, error) {
	if rawPath == "" {
		return nil, nil
	}
	if runtime.GOOS != "windows" && looksWindowsSpecific(rawPath) {
		return nil, nil
	}
	expanded := expandWindowsEnv(rawPath)
	expanded = os.ExpandEnv(expanded)
	expanded = expandHome(expanded)

	if filepath.IsAbs(expanded) {
		return []string{filepath.Clean(expanded)}, nil
	}

	if opts.Recursive && isBareFilename(expanded) {
		return recursiveFileTargets(ctx, expanded, opts)
	}

	var targets []string
	for _, root := range opts.Roots {
		if root == "" {
			continue
		}
		targets = append(targets, filepath.Clean(filepath.Join(root, expanded)))
	}
	return targets, nil
}

func expandHome(path string) string {
	if path == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			return home
		}
	}
	if strings.HasPrefix(path, "~/") || strings.HasPrefix(path, `~\`) {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

func looksWindowsSpecific(path string) bool {
	if strings.Contains(path, "%") {
		return true
	}
	if len(path) >= 3 && path[1] == ':' && (path[2] == '\\' || path[2] == '/') {
		return true
	}
	return false
}

func isBareFilename(path string) bool {
	if path == "" || path == "." || path == ".." {
		return false
	}
	if filepath.IsAbs(path) {
		return false
	}
	return !strings.ContainsAny(path, `/\`)
}

func recursiveFileTargets(ctx context.Context, filename string, opts Options) ([]string, error) {
	seen := make(map[string]bool)
	var targets []string
	for _, root := range opts.Roots {
		if root == "" {
			continue
		}
		root = filepath.Clean(root)
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				if errors.Is(err, os.ErrPermission) {
					return nil
				}
				return err
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			if d.IsDir() {
				if shouldSkipDir(d.Name(), opts) && path != root {
					return filepath.SkipDir
				}
				if opts.MaxDepth >= 0 && depthFromRoot(root, path) > opts.MaxDepth {
					return filepath.SkipDir
				}
				return nil
			}

			if d.Name() != filename {
				return nil
			}
			if opts.MaxDepth >= 0 && depthFromRoot(root, filepath.Dir(path)) > opts.MaxDepth {
				return nil
			}
			clean := filepath.Clean(path)
			if seen[clean] {
				return nil
			}
			seen[clean] = true
			targets = append(targets, clean)
			return nil
		})
		if err != nil {
			if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
				continue
			}
			return targets, err
		}
	}
	return targets, nil
}

func shouldSkipDir(name string, opts Options) bool {
	if opts.SkipDirs == nil {
		return defaultSkipDirs()[name]
	}
	return opts.SkipDirs[name]
}

func defaultSkipDirs() map[string]bool {
	return map[string]bool{
		".cache":       true,
		".git":         true,
		".gocache":     true,
		".hg":          true,
		".idea":        true,
		".svn":         true,
		".terraform":   true,
		".venv":        true,
		".vscode":      true,
		"__pycache__":  true,
		"build":        true,
		"coverage":     true,
		"dist":         true,
		"node_modules": true,
		"target":       true,
		"vendor":       true,
		"venv":         true,
	}
}

func depthFromRoot(root, path string) int {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." {
		return 0
	}
	depth := 1
	for _, r := range rel {
		if r == os.PathSeparator {
			depth++
		}
	}
	return depth
}

func expandWindowsEnv(path string) string {
	var b strings.Builder
	for i := 0; i < len(path); {
		if path[i] != '%' {
			b.WriteByte(path[i])
			i++
			continue
		}
		end := strings.IndexByte(path[i+1:], '%')
		if end < 0 {
			b.WriteByte(path[i])
			i++
			continue
		}
		name := path[i+1 : i+1+end]
		if value, ok := os.LookupEnv(name); ok {
			b.WriteString(value)
		} else {
			b.WriteString("%")
			b.WriteString(name)
			b.WriteString("%")
		}
		i += end + 2
	}
	return b.String()
}

func lineForOffset(content string, offset int) int {
	if offset < 0 {
		return 1
	}
	if offset > len(content) {
		offset = len(content)
	}
	line := 1
	for i := 0; i < offset; i++ {
		if content[i] == '\n' {
			line++
		}
	}
	return line
}

func pathWithLine(path string, line int) string {
	if line <= 0 {
		return path
	}
	return path + ":" + strconv.Itoa(line)
}
