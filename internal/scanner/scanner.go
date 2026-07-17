package scanner

import (
	"context"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/haxxm0nkey/credshound/internal/templates"
)

const maxInterestingLocationReferences = 50

type Options struct {
	Roots          []string
	MaxFileSize    int64
	Recursive      bool
	MaxDepth       int
	SkipDirs       map[string]bool
	ShowSecrets    bool
	URLBase        string
	EnableBuiltins bool
	IncludeSources map[string]bool
	ExcludeSources map[string]bool
}

type Result struct {
	Findings []Finding
	Stats    Stats
}

type Stats struct {
	Templates       int
	Credentials     int
	Patterns        int
	SkippedPatterns int
}

type compiledCredential struct {
	entry      templates.Entry
	cred       templates.Credential
	locations  []templates.Location
	patterns   []*regexp.Regexp
	patternRaw []string
}

func Scan(ctx context.Context, entries []templates.Entry, opts Options) ([]Finding, error) {
	result, err := ScanWithStats(ctx, entries, opts)
	if err != nil {
		return nil, err
	}
	return result.Findings, nil
}

func ScanWithStats(ctx context.Context, entries []templates.Entry, opts Options) (Result, error) {
	compiled, stats := compile(entries)

	var findings []Finding
	if sourceEnabled("env", opts) {
		envFindings := scanEnvironment(ctx, compiled, opts)
		findings = append(findings, envFindings...)
	}

	if sourceEnabled("file", opts) {
		fileFindings, err := scanFiles(ctx, compiled, opts)
		if err != nil {
			return Result{}, err
		}
		if opts.EnableBuiltins {
			builtinFindings, err := scanBuiltinFiles(ctx, opts)
			if err != nil {
				return Result{}, err
			}
			findings = append(findings, builtinFindings...)
			fileFindings = suppressTemplateFindingsForBuiltins(fileFindings, builtinFindings)
		}
		findings = append(findings, fileFindings...)
	}

	if sourceEnabled("registry", opts) {
		registryFindings, err := scanRegistry(ctx, compiled, opts)
		if err != nil {
			return Result{}, err
		}
		findings = append(findings, registryFindings...)
	}

	findings = dedupeFindings(findings)
	findings = dedupeHighFindingsBySecret(findings)
	findings = aggregateInfoFindings(findings)
	findings = sortFindings(findings)
	return Result{Findings: findings, Stats: stats}, nil
}

func suppressTemplateFindingsForBuiltins(templateFindings, builtinFindings []Finding) []Finding {
	if len(templateFindings) == 0 || len(builtinFindings) == 0 {
		return templateFindings
	}

	highSignal := make(map[string]bool, len(builtinFindings))
	coveredPaths := make(map[string]bool, len(builtinFindings))
	for _, finding := range builtinFindings {
		if finding.TemplateID != "filesystem" || finding.Source != "file" || !strings.EqualFold(finding.Confidence, "high") {
			continue
		}
		highSignal[finding.Source+"\x00"+finding.Location+"\x00"+finding.Evidence] = true
		location, _ := splitLocationLine(finding.Location)
		coveredPaths[location] = true
	}

	out := make([]Finding, 0, len(templateFindings))
	for _, finding := range templateFindings {
		if highSignal[finding.Source+"\x00"+finding.Location+"\x00"+finding.Evidence] {
			continue
		}
		if strings.EqualFold(finding.Confidence, "info") && finding.Source == "file" && finding.Evidence == "path exists" && coveredPaths[finding.Location] {
			continue
		}
		out = append(out, finding)
	}
	return out
}

func compile(entries []templates.Entry) ([]compiledCredential, Stats) {
	var out []compiledCredential
	stats := Stats{Templates: len(entries)}
	for _, entry := range entries {
		for _, cred := range entry.Credentials {
			stats.Credentials++
			compiled := compiledCredential{
				entry:      entry,
				cred:       cred,
				locations:  cred.Location,
				patternRaw: make([]string, 0, len(cred.LooksLike)),
			}
			for _, looksLike := range cred.LooksLike {
				if strings.TrimSpace(looksLike.Pattern) == "" {
					continue
				}
				pattern := normalizeLargeRepeatCounts(looksLike.Pattern)
				re, err := regexp.Compile(pattern)
				if err != nil {
					stats.SkippedPatterns++
					continue
				}
				compiled.patterns = append(compiled.patterns, re)
				compiled.patternRaw = append(compiled.patternRaw, pattern)
				stats.Patterns++
			}
			out = append(out, compiled)
		}
	}
	return out, stats
}

func sourceEnabled(source string, opts Options) bool {
	source = strings.ToLower(source)
	if len(opts.IncludeSources) > 0 && !opts.IncludeSources[source] {
		return false
	}
	return !opts.ExcludeSources[source]
}

func dedupeFindings(findings []Finding) []Finding {
	seen := make(map[string]bool, len(findings))
	out := make([]Finding, 0, len(findings))
	for _, finding := range findings {
		key := strings.Join([]string{
			finding.TemplateID,
			finding.CredentialID,
			finding.Source,
			finding.Location,
			finding.Evidence,
		}, "\x00")
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, finding)
	}
	return out
}

func dedupeHighFindingsBySecret(findings []Finding) []Finding {
	slots := make([]Finding, 0, len(findings))
	secretSlots := make(map[string]int)

	for _, finding := range findings {
		key, ok := secretDedupeKey(finding)
		if !ok {
			slots = append(slots, finding)
			continue
		}

		if slotIndex, exists := secretSlots[key]; exists {
			if findingDedupeRank(finding) > findingDedupeRank(slots[slotIndex]) {
				slots[slotIndex] = finding
			}
			continue
		}

		secretSlots[key] = len(slots)
		slots = append(slots, finding)
	}
	return slots
}

func secretDedupeKey(f Finding) (string, bool) {
	if !strings.EqualFold(f.Confidence, "high") {
		return "", false
	}
	if f.Evidence == "" {
		return "", false
	}

	secret := f.Evidence
	if _, value, ok := splitAssignment(secret); ok {
		secret = value
	}
	secret = strings.TrimSpace(secret)
	secret = strings.Trim(secret, `"'[](){}<>`)
	if secret == "" || secret == "****" {
		return "", false
	}
	if alphaNumCount(secret) < 3 || !strings.Contains(secret, "****") {
		return "", false
	}
	return strings.ToLower(f.Source) + "\x00" + secret, true
}

func alphaNumCount(value string) int {
	count := 0
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			count++
		}
	}
	return count
}

func findingDedupeRank(f Finding) int {
	rank := 0
	if f.TemplateID != "filesystem" {
		rank += 100
	}
	if f.URL != "" {
		rank += 20
	}
	if !strings.Contains(strings.ToLower(f.CredentialType), "password") {
		rank += 5
	}
	return rank
}

type observationSlot struct {
	finding   Finding
	refSeen   map[string]bool
	refURLs   map[string]string
	refOrder  []string
	slotIndex int
}

func aggregateInfoFindings(findings []Finding) []Finding {
	slots := make([]Finding, 0, len(findings))
	observations := make(map[string]*observationSlot)

	for _, finding := range findings {
		key, synthetic, ok := syntheticObservation(finding)
		if !ok {
			slots = append(slots, finding)
			continue
		}
		if key == "" {
			continue
		}

		observation, exists := observations[key]
		if !exists {
			observation = &observationSlot{
				finding:   synthetic,
				refSeen:   make(map[string]bool),
				refURLs:   make(map[string]string),
				slotIndex: len(slots),
			}
			observations[key] = observation
			slots = append(slots, synthetic)
		}
		observation.addReference(finding.TemplateID, finding.URL)
	}

	for _, observation := range observations {
		observation.finding.References = observation.refOrder
		if len(observation.refOrder) == 1 {
			observation.finding.URL = observation.refURLs[observation.refOrder[0]]
		}
		if shouldSuppressObservation(observation.finding) {
			slots[observation.slotIndex] = Finding{}
			continue
		}
		slots[observation.slotIndex] = observation.finding
	}
	return compactFindings(slots)
}

func shouldSuppressObservation(f Finding) bool {
	return f.TemplateID == "filesystem" &&
		f.CredentialID == "interesting-location" &&
		len(f.References) > maxInterestingLocationReferences
}

func compactFindings(findings []Finding) []Finding {
	out := make([]Finding, 0, len(findings))
	for _, finding := range findings {
		if finding.TemplateID == "" && finding.CredentialID == "" {
			continue
		}
		out = append(out, finding)
	}
	return out
}

func sortFindings(findings []Finding) []Finding {
	sort.SliceStable(findings, func(i, j int) bool {
		left := findingSortKey(findings[i])
		right := findingSortKey(findings[j])
		for idx := range left {
			if left[idx] == right[idx] {
				continue
			}
			return left[idx] < right[idx]
		}
		return false
	})
	return findings
}

func findingSortKey(f Finding) []string {
	return []string{
		findingTypeOrder(f),
		f.TemplateID + ":" + f.CredentialID,
		f.Source,
		f.Confidence,
		f.Location,
		f.Evidence,
	}
}

func findingTypeOrder(f Finding) string {
	if f.TemplateID == "filesystem" {
		switch f.CredentialID {
		case "interesting-location":
			return "00"
		case "env-name-reference":
			return "01"
		}
		return "02"
	}
	return "10"
}

func (o *observationSlot) addReference(reference, url string) {
	reference = strings.TrimSpace(reference)
	if reference == "filesystem" {
		return
	}
	if reference == "" || o.refSeen[reference] {
		return
	}
	o.refSeen[reference] = true
	o.refURLs[reference] = url
	o.refOrder = append(o.refOrder, reference)
}

func syntheticObservation(f Finding) (string, Finding, bool) {
	if strings.ToLower(f.Confidence) != "info" || strings.ToLower(f.Source) != "file" {
		return "", Finding{}, false
	}

	switch f.Evidence {
	case "path exists":
		if isLowSignalPathExists(f.Location) {
			return "", Finding{}, true
		}
		synthetic := Finding{
			TemplateID:     "filesystem",
			CredentialID:   "interesting-location",
			Origin:         OriginObservation,
			Product:        "Filesystem",
			Credential:     "Interesting location",
			Source:         "file",
			Confidence:     "info",
			Location:       f.Location,
			CredentialType: "config_file",
			Evidence:       "path exists",
		}
		return strings.Join([]string{synthetic.CredentialID, synthetic.Source, synthetic.Location}, "\x00"), synthetic, true
	default:
		location, _ := splitLocationLine(f.Location)
		synthetic := Finding{
			TemplateID:     "filesystem",
			CredentialID:   "env-name-reference",
			Origin:         OriginObservation,
			Product:        "Filesystem",
			Credential:     "Environment variable name reference",
			Source:         "file",
			Confidence:     "info",
			Location:       location,
			CredentialType: "environment",
			Evidence:       "env var name referenced",
		}
		return strings.Join([]string{synthetic.CredentialID, synthetic.Source, synthetic.Location}, "\x00"), synthetic, true
	}
}

func isLowSignalPathExists(location string) bool {
	location = strings.TrimSpace(location)
	if location == "" {
		return false
	}
	normalized := strings.ReplaceAll(location, "\\", "/")
	base := path.Base(normalized)
	switch base {
	case ".bash_login", ".bash_logout", ".bash_profile", ".bashrc", ".cshrc", ".login", ".logout", ".profile", ".tcshrc", ".zlogin", ".zlogout", ".zprofile", ".zshenv", ".zshrc", "passwd":
		return true
	default:
		return false
	}
}

func splitLocationLine(location string) (string, string) {
	idx := strings.LastIndex(location, ":")
	if idx < 0 || idx == len(location)-1 {
		return location, ""
	}
	line := location[idx+1:]
	for _, r := range line {
		if r < '0' || r > '9' {
			return location, ""
		}
	}
	return location[:idx], line
}

var repeatCountPattern = regexp.MustCompile(`(^|[^\\])\{([0-9]+)(,([0-9]*))?\}`)

func normalizeLargeRepeatCounts(pattern string) string {
	return repeatCountPattern.ReplaceAllStringFunc(pattern, func(match string) string {
		parts := repeatCountPattern.FindStringSubmatch(match)
		if len(parts) != 5 {
			return match
		}

		min, err := strconv.Atoi(parts[2])
		if err != nil {
			return match
		}

		prefix := parts[1]
		comma := parts[3]
		maxValue := parts[4]

		if comma == "" {
			if min > 1000 {
				return prefix + "{1000,}"
			}
			return match
		}

		if maxValue == "" {
			if min > 1000 {
				return prefix + "{1000,}"
			}
			return match
		}

		max, err := strconv.Atoi(maxValue)
		if err != nil || max <= 1000 {
			return match
		}
		if min > 1000 {
			min = 1000
		}
		return prefix + "{" + strconv.Itoa(min) + ",}"
	})
}

func (c compiledCredential) finding(source, confidence, location, evidence string, opts Options) Finding {
	return c.findingWithEvidence(source, confidence, location, redact(evidence, opts.ShowSecrets), opts)
}

func (c compiledCredential) infoFinding(source, location, evidence string, opts Options) Finding {
	return c.findingWithEvidence(source, "info", location, evidence, opts)
}

func (c compiledCredential) findingWithEvidence(source, confidence, location, evidence string, opts Options) Finding {
	return Finding{
		TemplateID:     c.entry.ID,
		CredentialID:   c.cred.ID,
		Origin:         OriginTemplate,
		Product:        c.entry.Name,
		Vendor:         c.entry.Vendor,
		Category:       categoryOrUnknown(c.entry.Category),
		Credential:     c.cred.Name,
		Source:         source,
		Confidence:     confidence,
		Location:       location,
		CredentialType: c.cred.Type,
		Evidence:       evidence,
		URL:            readMoreURL(opts.URLBase, c.entry.ID, c.cred.ID),
	}
}

func categoryOrUnknown(category string) string {
	category = strings.TrimSpace(category)
	if category == "" {
		return "unknown"
	}
	return category
}

func readMoreURL(base, entryID, credentialID string) string {
	base = strings.TrimRight(base, "/")
	if base == "" {
		return ""
	}
	escapedEntry := url.PathEscape(entryID)
	escapedCredential := url.PathEscape(credentialID)
	return base + "/" + path.Clean(escapedEntry) + "#" + escapedCredential
}

func splitPathList(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		part = strings.Trim(part, `"'`)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
