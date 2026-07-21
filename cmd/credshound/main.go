package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	bloodhoundintegration "github.com/haxxm0nkey/credshound/internal/integrations/bloodhound"
	"github.com/haxxm0nkey/credshound/internal/report"
	"github.com/haxxm0nkey/credshound/internal/scanner"
	"github.com/haxxm0nkey/credshound/internal/templates"
	"github.com/haxxm0nkey/credshound/internal/updater"
)

var version = "dev"
var defaultInstallDir = updater.DefaultInstallDir
var updateTemplates = updater.Update
var currentTime = time.Now

const staleTemplatesAfter = 7 * 24 * time.Hour

type missingTemplatesError struct {
	CacheDir string
}

type rawCLIError struct {
	Message string
	Help    string
}

func (e rawCLIError) Error() string {
	if e.Help == "" {
		return e.Message
	}
	return e.Message + "\n" + e.Help
}

func (e missingTemplatesError) Error() string {
	return "no templates found"
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		printRunError(os.Stderr, err)
		os.Exit(1)
	}
}

func printRunError(w io.Writer, err error) {
	var raw rawCLIError
	if errors.As(err, &raw) {
		fmt.Fprintf(w, "%v\n", err)
		return
	}
	fmt.Fprintf(w, "credshound: %v\n", err)
}

func hasHelpFlag(args []string) bool {
	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			return true
		}
	}
	return false
}

func flagErrorMessage(err error) string {
	message := err.Error()
	const prefix = "flag provided but not defined: "
	if strings.HasPrefix(message, prefix) {
		return "unknown flag: " + strings.TrimSpace(strings.TrimPrefix(message, prefix))
	}
	return message
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return runScan(args, stdout, stderr)
	}

	switch args[0] {
	case "-bh-setup":
		return runBloodHoundSetup(args[1:], stdout)
	case "inspect-templates":
		return runInspectTemplates(args[1:], stdout)
	case "update-templates", "-ut", "-update-templates":
		return runUpdateTemplates(args[1:], stdout)
	case "-version", "--version":
		fmt.Fprintf(stdout, "credshound %s\n", version)
		return nil
	case "-h", "--help":
		printScanUsage(stdout)
		return nil
	default:
		if hasHelpFlag(args) {
			printScanUsage(stdout)
			return nil
		}
		return runScan(args, stdout, stderr)
	}
}

func runScan(args []string, stdout, stderr io.Writer) error {
	var roots []string
	var skipDirs repeatedFlag
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	templateShort := fs.String("t", "", "path to LOLCreds templates repository, entries directory, or zip archive")
	templateLong := fs.String("templates", "", "path to LOLCreds templates repository, entries directory, or zip archive")
	jsonlShort := fs.Bool("j", false, "write findings in JSONL format")
	jsonlLong := fs.Bool("jsonl", false, "write findings in JSONL format")
	bloodHoundShort := fs.Bool("bh", false, "write findings as BloodHound OpenGraph JSON")
	bloodHoundLong := fs.Bool("bloodhound", false, "write findings as BloodHound OpenGraph JSON")
	outputShort := fs.String("o", "", "output file to write findings")
	outputLong := fs.String("output", "", "output file to write findings")
	fingerprintKey := fs.String("fingerprint-key", "", "stable credential fingerprint key for BloodHound reuse analysis")
	ephemeralFingerprint := fs.Bool("ephemeral-fingerprint", false, "use a per-scan random fingerprint key")
	sources := fs.String("sources", "", "comma-separated sources to scan: env,file,proc")
	excludeSourcesFlag := fs.String("exclude-sources", "", "comma-separated sources to exclude: env,file,proc")
	includeIDs := fs.String("id", "", "finding IDs to include: template or template:credential")
	excludeIDs := fs.String("eid", "", "finding IDs to exclude: template or template:credential")
	includeSeverity := fs.String("severity", "", "finding severities to include: info,medium,high")
	excludeSeverity := fs.String("es", "", "finding severities to exclude: info,medium,high")
	includeTypes := fs.String("type", "", "credential types to include")
	excludeTypes := fs.String("etype", "", "credential types to exclude")
	includeOrigins := fs.String("origin", "", "finding origins to include: template,builtin,observation")
	excludeOrigins := fs.String("eorigin", "", "finding origins to exclude: template,builtin,observation")
	debug := fs.Bool("debug", false, "print template compatibility stats to stderr")
	versionFlag := fs.Bool("version", false, "show version")
	showSecrets := fs.Bool("show-secrets", false, "print full secret values")
	silent := fs.Bool("silent", false, "suppress non-finding output")
	noColorLong := fs.Bool("no-color", false, "disable output content coloring")
	noColorShort := fs.Bool("nc", false, "disable output content coloring")
	disableUpdateCheckShort := fs.Bool("duc", false, "disable template freshness warning")
	disableUpdateCheckLong := fs.Bool("disable-update-check", false, "disable template freshness warning")
	maxFileSize := fs.Int64("max-file-size", 2*1024*1024, "maximum config file size to read in bytes")
	recursive := fs.Bool("recursive", false, "recursively search roots for bare config filenames")
	maxDepth := fs.Int("max-depth", 6, "maximum recursive directory depth below each root")
	timeout := fs.Duration("timeout", 60*time.Second, "scan timeout")
	fs.Var(&skipDirs, "skip-dir", "directory name to skip during recursive scans; may be repeated")

	if hasHelpFlag(args) {
		printScanUsage(stdout)
		return nil
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printScanUsage(stdout)
			return nil
		}
		return rawCLIError{Message: flagErrorMessage(err), Help: "Use -h for help."}
	}
	if *versionFlag {
		fmt.Fprintf(stdout, "credshound %s\n", version)
		return nil
	}
	noColor := *noColorLong || *noColorShort
	disableUpdateCheck := *disableUpdateCheckShort || *disableUpdateCheckLong
	resolvedDataFlag, err := resolveTemplateFlag(*templateShort, *templateLong)
	if err != nil {
		return err
	}
	formatName := "text"
	if *jsonlShort || *jsonlLong {
		formatName = "jsonl"
	}
	if *bloodHoundShort || *bloodHoundLong {
		if formatName != "text" {
			return errors.New("use only one output format: text, jsonl, or bloodhound")
		}
		formatName = "bloodhound"
	}
	outputPath, err := resolveOutputFlag(*outputShort, *outputLong)
	if err != nil {
		return err
	}
	includeSources, err := parseSources(*sources)
	if err != nil {
		return err
	}
	if len(includeSources) == 0 {
		includeSources = map[string]bool{"env": true, "file": true}
	}
	excludeSources, err := parseSources(*excludeSourcesFlag)
	if err != nil {
		return err
	}
	filters, err := parseFindingFilters(findingFilterInputs{
		IncludeIDs:      *includeIDs,
		ExcludeIDs:      *excludeIDs,
		IncludeSeverity: *includeSeverity,
		ExcludeSeverity: *excludeSeverity,
		IncludeTypes:    *includeTypes,
		ExcludeTypes:    *excludeTypes,
		IncludeOrigins:  *includeOrigins,
		ExcludeOrigins:  *excludeOrigins,
	})
	if err != nil {
		return err
	}
	if noColor {
		// Text output is intentionally plain for now; keep the flag for nuclei-like CLI muscle memory.
	}
	if *silent {
		// No banner is emitted today, so findings remain unchanged.
	}

	resolvedDataDir, usingCache, err := resolveDataDir(resolvedDataFlag)
	if err != nil {
		var missing missingTemplatesError
		if errors.As(err, &missing) && *silent && resolvedDataFlag == "" {
			return nil
		}
		if errors.As(err, &missing) && formatName == "text" && !*silent && resolvedDataFlag == "" {
			printMissingTemplates(stdout, missing.CacheDir, !noColor)
			return nil
		}
		return err
	}

	entries, err := templates.Load(resolvedDataDir)
	if err != nil {
		return err
	}
	var metadata *updater.Result
	if usingCache && !disableUpdateCheck {
		if result, err := updater.ReadMetadata(resolvedDataDir); err == nil {
			metadata = &result
		}
	}
	for _, root := range fs.Args() {
		if root != "" {
			roots = append(roots, root)
		}
	}
	if len(roots) == 0 {
		roots = append(roots, ".")
	}
	skipDirMap := defaultSkipDirs()
	for _, dir := range skipDirs {
		skipDirMap[dir] = true
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	fingerprintKeyValue := firstNonEmpty(*fingerprintKey, os.Getenv("CREDSHOUND_FINGERPRINT_KEY"))
	if *ephemeralFingerprint && strings.TrimSpace(*fingerprintKey) == "" {
		fingerprintKeyValue = ""
	}

	result, err := scanner.ScanWithStats(ctx, entries, scanner.Options{
		Roots:                roots,
		MaxFileSize:          *maxFileSize,
		Recursive:            *recursive,
		MaxDepth:             *maxDepth,
		SkipDirs:             skipDirMap,
		ShowSecrets:          *showSecrets,
		URLBase:              "https://lolcreds.haxx.it",
		EnableBuiltins:       true,
		IncludeSources:       includeSources,
		ExcludeSources:       excludeSources,
		FingerprintKey:       fingerprintKeyValue,
		EphemeralFingerprint: *ephemeralFingerprint,
	})
	if err != nil {
		return err
	}
	result.Findings = filterFindings(result.Findings, filters)
	outputFindings := result.Findings
	if *silent {
		outputFindings = withoutInfoFindings(outputFindings)
	}
	if formatName == "text" && !*silent {
		printBanner(stdout, !noColor)
		printScanInfo(stdout, result, roots, includeSources, excludeSources, *recursive, *maxDepth, resolvedDataDir, usingCache, metadata, noColor)
	}
	if *debug && !*silent {
		fmt.Fprintf(
			stderr,
			"loaded %d templates, scanned %d credentials, compiled %d patterns, skipped %d unsupported patterns\n",
			result.Stats.Templates,
			result.Stats.Credentials,
			result.Stats.Patterns,
			result.Stats.SkippedPatterns,
		)
	}

	findingsWriter := stdout
	var outputFile *os.File
	if outputPath != "" {
		outputFile, err = os.OpenFile(outputPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return err
		}
		defer outputFile.Close()
		findingsWriter = outputFile
	}

	switch formatName {
	case "text":
		return report.WriteText(findingsWriter, outputFindings, report.TextOptions{Color: !noColor})
	case "jsonl":
		enc := json.NewEncoder(findingsWriter)
		for _, finding := range outputFindings {
			if err := enc.Encode(finding); err != nil {
				return err
			}
		}
		return nil
	case "bloodhound":
		return report.WriteBloodHound(findingsWriter, outputFindings)
	}
	return nil
}

func runBloodHoundSetup(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("-bh-setup", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	server := fs.String("server", "", "BloodHound server URL")
	username := fs.String("username", "", "BloodHound username")
	password := fs.String("password", "", "BloodHound password")
	token := fs.String("token", "", "BloodHound JWT bearer token")
	noIcons := fs.Bool("no-icons", false, "skip custom node icon setup")
	noQueries := fs.Bool("no-queries", false, "skip saved query import")
	resetQueries := fs.Bool("reset-queries", false, "delete existing CredsHound saved queries before import")
	noVerifySSL := fs.Bool("no-verify-ssl", false, "skip TLS certificate verification")
	timeout := fs.Duration("timeout", 30*time.Second, "BloodHound API timeout")
	noColorLong := fs.Bool("no-color", false, "disable output content coloring")
	noColorShort := fs.Bool("nc", false, "disable output content coloring")
	silent := fs.Bool("silent", false, "suppress non-essential output")

	if hasHelpFlag(args) {
		printBloodHoundSetupUsage(stdout)
		return nil
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printBloodHoundSetupUsage(stdout)
			return nil
		}
		return rawCLIError{Message: flagErrorMessage(err), Help: "Use -bh-setup -h for help."}
	}

	noColor := *noColorLong || *noColorShort
	resolvedServer := firstNonEmpty(*server, os.Getenv("BLOODHOUND_URL"), "http://localhost:8080")

	if !*silent {
		printBanner(stdout, !noColor)
		printStatus(stdout, "INF", "BloodHound: "+resolvedServer, !noColor)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	result, err := bloodhoundintegration.Run(ctx, bloodhoundintegration.Options{
		Server:       resolvedServer,
		Username:     firstNonEmpty(*username, os.Getenv("BLOODHOUND_USERNAME")),
		Password:     firstNonEmpty(*password, os.Getenv("BLOODHOUND_PASSWORD")),
		Token:        firstNonEmpty(*token, os.Getenv("BLOODHOUND_TOKEN")),
		NoIcons:      *noIcons,
		NoQueries:    *noQueries,
		ResetQueries: *resetQueries,
		NoVerifySSL:  *noVerifySSL,
		Timeout:      *timeout,
	})
	if err != nil {
		return err
	}

	if !*silent {
		printBloodHoundSetupResult(stdout, result, !noColor)
	}
	return nil
}

func runUpdateTemplates(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("update-templates", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	installDir, err := defaultInstallDir()
	if err != nil {
		return err
	}
	timeout := fs.Duration("timeout", 2*time.Minute, "download timeout")
	noColorLong := fs.Bool("no-color", false, "disable output content coloring")
	noColorShort := fs.Bool("nc", false, "disable output content coloring")
	silent := fs.Bool("silent", false, "suppress non-essential output")

	if hasHelpFlag(args) {
		printUpdateUsage(stdout, installDir)
		return nil
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printUpdateUsage(stdout, installDir)
			return nil
		}
		return rawCLIError{Message: flagErrorMessage(err), Help: "Use -ut -h for help."}
	}
	noColor := *noColorLong || *noColorShort

	if !*silent {
		printBanner(stdout, !noColor)
		printStatus(stdout, "INF", "Downloading LOLCreds templates", !noColor)
		printStatus(stdout, "INF", "Source: "+updater.DefaultSourceURL, !noColor)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	result, err := updateTemplates(ctx, updater.Options{
		SourceURL:  updater.DefaultSourceURL,
		InstallDir: installDir,
	})
	if err != nil {
		if !*silent {
			printUpdateFailure(stdout, err, updater.DefaultSourceURL, !noColor)
		}
		return nil
	}

	if !*silent {
		printStatus(stdout, "INF", fmt.Sprintf("Extracted %d file(s)", result.Files), !noColor)
		printStatus(stdout, "INF", "Templates installed to "+result.InstallDir, !noColor)
	}
	return nil
}

func runInspectTemplates(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("inspect-templates", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	templateShort := fs.String("t", "", "path to LOLCreds templates repository, entries directory, or zip archive")
	templateLong := fs.String("templates", "", "path to LOLCreds templates repository, entries directory, or zip archive")

	if hasHelpFlag(args) {
		printInspectTemplatesUsage(stdout)
		return nil
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printInspectTemplatesUsage(stdout)
			return nil
		}
		return rawCLIError{Message: flagErrorMessage(err), Help: "Use inspect-templates -h for help."}
	}

	resolvedDataFlag, err := resolveTemplateFlag(*templateShort, *templateLong)
	if err != nil {
		return err
	}
	resolvedDataDir, _, err := resolveDataDir(resolvedDataFlag)
	if err != nil {
		return err
	}
	entries, err := templates.Load(resolvedDataDir)
	if err != nil {
		return err
	}

	report := inspectTemplateData(entries)
	writeTemplateInspection(stdout, report)
	return nil
}

type templateInspection struct {
	EnvironmentVariables []string
	AbsolutePaths        []string
	RelativePaths        []string
	Patterns             []string
}

func inspectTemplateData(entries []templates.Entry) templateInspection {
	envNames := make(map[string]bool)
	absolutePaths := make(map[string]bool)
	relativePaths := make(map[string]bool)
	patterns := make(map[string]bool)

	for _, entry := range entries {
		for _, credential := range entry.Credentials {
			for _, location := range credential.Location {
				locationType := strings.ToLower(strings.TrimSpace(location.Type))
				for _, value := range splitTemplatePathList(location.Path) {
					switch locationType {
					case "environment":
						envNames[value] = true
					case "config_file":
						if isDirectTemplatePath(value) {
							absolutePaths[value] = true
						} else {
							relativePaths[value] = true
						}
					}
				}
			}
			for _, looksLike := range credential.LooksLike {
				pattern := strings.TrimSpace(looksLike.Pattern)
				if pattern != "" {
					patterns[pattern] = true
				}
			}
		}
	}

	return templateInspection{
		EnvironmentVariables: sortedKeys(envNames),
		AbsolutePaths:        sortedKeys(absolutePaths),
		RelativePaths:        sortedKeys(relativePaths),
		Patterns:             sortedKeys(patterns),
	}
}

func splitTemplatePathList(value string) []string {
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

func isDirectTemplatePath(path string) bool {
	if path == "" {
		return false
	}
	if filepath.IsAbs(path) || path == "~" || strings.HasPrefix(path, "~/") || strings.HasPrefix(path, `~\`) {
		return true
	}
	if strings.HasPrefix(path, "%") && strings.Contains(path[1:], "%") {
		return true
	}
	if len(path) >= 3 && path[1] == ':' && (path[2] == '\\' || path[2] == '/') {
		return true
	}
	return false
}

func sortedKeys(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func writeTemplateInspection(w io.Writer, report templateInspection) {
	writeStringSection(w, "Environment variables", report.EnvironmentVariables)
	writeStringSection(w, "Absolute paths", report.AbsolutePaths)
	writeStringSection(w, "Relative paths", report.RelativePaths)
	writeStringSection(w, "Patterns", report.Patterns)
}

func writeStringSection(w io.Writer, title string, values []string) {
	fmt.Fprintf(w, "%s (%d)\n", title, len(values))
	for _, value := range values {
		fmt.Fprintln(w, value)
	}
	fmt.Fprintln(w)
}

type findingFilterInputs struct {
	IncludeIDs      string
	ExcludeIDs      string
	IncludeSeverity string
	ExcludeSeverity string
	IncludeTypes    string
	ExcludeTypes    string
	IncludeOrigins  string
	ExcludeOrigins  string
}

type findingFilters struct {
	IncludeIDs      map[string]bool
	ExcludeIDs      map[string]bool
	IncludeSeverity map[string]bool
	ExcludeSeverity map[string]bool
	IncludeTypes    map[string]bool
	ExcludeTypes    map[string]bool
	IncludeOrigins  map[string]bool
	ExcludeOrigins  map[string]bool
}

func parseFindingFilters(inputs findingFilterInputs) (findingFilters, error) {
	includeSeverity, err := parseValidatedList(inputs.IncludeSeverity, "severity", validSeverity)
	if err != nil {
		return findingFilters{}, err
	}
	excludeSeverity, err := parseValidatedList(inputs.ExcludeSeverity, "severity", validSeverity)
	if err != nil {
		return findingFilters{}, err
	}
	includeOrigins, err := parseValidatedList(inputs.IncludeOrigins, "origin", validOrigin)
	if err != nil {
		return findingFilters{}, err
	}
	excludeOrigins, err := parseValidatedList(inputs.ExcludeOrigins, "origin", validOrigin)
	if err != nil {
		return findingFilters{}, err
	}

	return findingFilters{
		IncludeIDs:      parseNormalizedList(inputs.IncludeIDs),
		ExcludeIDs:      parseNormalizedList(inputs.ExcludeIDs),
		IncludeSeverity: includeSeverity,
		ExcludeSeverity: excludeSeverity,
		IncludeTypes:    parseNormalizedList(inputs.IncludeTypes),
		ExcludeTypes:    parseNormalizedList(inputs.ExcludeTypes),
		IncludeOrigins:  includeOrigins,
		ExcludeOrigins:  excludeOrigins,
	}, nil
}

func parseValidatedList(value, label string, valid func(string) bool) (map[string]bool, error) {
	items := parseNormalizedList(value)
	for item := range items {
		if !valid(item) {
			return nil, fmt.Errorf("unsupported %s %q", label, item)
		}
	}
	return items, nil
}

func parseNormalizedList(value string) map[string]bool {
	items := make(map[string]bool)
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(strings.ToLower(part))
		if part == "" {
			continue
		}
		items[part] = true
	}
	return items
}

func validSeverity(value string) bool {
	switch value {
	case "info", "low", "medium", "high":
		return true
	default:
		return false
	}
}

func validOrigin(value string) bool {
	switch value {
	case scanner.OriginTemplate, scanner.OriginBuiltin, scanner.OriginObservation:
		return true
	default:
		return false
	}
}

func filterFindings(findings []scanner.Finding, filters findingFilters) []scanner.Finding {
	if filters.empty() {
		return findings
	}
	out := make([]scanner.Finding, 0, len(findings))
	for _, finding := range findings {
		if !findingPassesFilters(finding, filters) {
			continue
		}
		out = append(out, finding)
	}
	return out
}

func (f findingFilters) empty() bool {
	return len(f.IncludeIDs) == 0 &&
		len(f.ExcludeIDs) == 0 &&
		len(f.IncludeSeverity) == 0 &&
		len(f.ExcludeSeverity) == 0 &&
		len(f.IncludeTypes) == 0 &&
		len(f.ExcludeTypes) == 0 &&
		len(f.IncludeOrigins) == 0 &&
		len(f.ExcludeOrigins) == 0
}

func findingPassesFilters(finding scanner.Finding, filters findingFilters) bool {
	if len(filters.IncludeIDs) > 0 && !findingIDMatches(finding, filters.IncludeIDs) {
		return false
	}
	if findingIDMatches(finding, filters.ExcludeIDs) {
		return false
	}
	if !valueIncluded(finding.Confidence, filters.IncludeSeverity) {
		return false
	}
	if valueExcluded(finding.Confidence, filters.ExcludeSeverity) {
		return false
	}
	if !valueIncluded(finding.CredentialType, filters.IncludeTypes) {
		return false
	}
	if valueExcluded(finding.CredentialType, filters.ExcludeTypes) {
		return false
	}
	if !valueIncluded(finding.Origin, filters.IncludeOrigins) {
		return false
	}
	if valueExcluded(finding.Origin, filters.ExcludeOrigins) {
		return false
	}
	return true
}

func findingIDMatches(finding scanner.Finding, ids map[string]bool) bool {
	if len(ids) == 0 {
		return false
	}
	templateID := strings.ToLower(strings.TrimSpace(finding.TemplateID))
	credentialID := strings.ToLower(strings.TrimSpace(finding.CredentialID))
	fullID := templateID + ":" + credentialID
	return ids[templateID] || ids[fullID]
}

func valueIncluded(value string, include map[string]bool) bool {
	if len(include) == 0 {
		return true
	}
	return include[strings.ToLower(strings.TrimSpace(value))]
}

func valueExcluded(value string, exclude map[string]bool) bool {
	if len(exclude) == 0 {
		return false
	}
	return exclude[strings.ToLower(strings.TrimSpace(value))]
}

func resolveDataDir(dataDir string) (string, bool, error) {
	if dataDir != "" {
		return dataDir, false, nil
	}
	cacheDir, err := defaultInstallDir()
	if err != nil {
		return "", false, err
	}
	if updater.HasTemplates(cacheDir) {
		return cacheDir, true, nil
	}
	return "", false, missingTemplatesError{CacheDir: cacheDir}
}

func resolveTemplateFlag(values ...string) (string, error) {
	var resolved string
	for _, value := range values {
		if value == "" {
			continue
		}
		if resolved != "" && resolved != value {
			return "", errors.New("use either -t or -templates, not both")
		}
		resolved = value
	}
	return resolved, nil
}

func resolveOutputFlag(short, long string) (string, error) {
	if short != "" && long != "" && short != long {
		return "", errors.New("use either -o or -output, not both")
	}
	if short != "" {
		return short, nil
	}
	return long, nil
}

func printUsage(w io.Writer) {
	printScanUsage(w)
}

func printScanUsage(w io.Writer) {
	printBanner(w, false)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  credshound [flags] [root...]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Examples:")
	fmt.Fprintln(w, "  credshound -ut")
	fmt.Fprintln(w, "  credshound .")
	fmt.Fprintln(w, "  credshound ~/project /etc")
	fmt.Fprintln(w, "  credshound -t ~/Downloads/lolcreds-data-main.zip")
	fmt.Fprintln(w, "  credshound -recursive .")
	fmt.Fprintln(w, "  credshound -t ~/lolcreds-templates -sources env,file")
	fmt.Fprintln(w, "  credshound -t ~/lolcreds-templates -sources env,file,proc")
	fmt.Fprintln(w, "  credshound -t ~/lolcreds-templates -exclude-sources env -j")
	fmt.Fprintln(w, "  credshound -bloodhound -o credshound-bloodhound.json")
	fmt.Fprintln(w, "  credshound -silent -j -o findings.jsonl")
	fmt.Fprintln(w, "  credshound -bh-setup -server http://localhost:8080")
	fmt.Fprintln(w, "  credshound inspect-templates -t ~/lolcreds-templates")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "TARGET:")
	fmt.Fprintln(w, "  [root...]                  roots for project-local config files; default .")
	fmt.Fprintln(w, "  -recursive                 recursively search roots for bare filenames like .env or values.yaml")
	fmt.Fprintln(w, "  -max-depth N               maximum recursive depth below each root, default 6")
	fmt.Fprintln(w, "  -skip-dir NAME             directory name to skip during recursive scans; repeatable")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "TEMPLATES:")
	fmt.Fprintln(w, "  -t, -templates PATH        LOLCreds templates directory, entries directory, or zip archive")
	fmt.Fprintln(w, "  -ut, -update-templates     download/update LOLCreds templates")
	fmt.Fprintln(w, "  -duc, -disable-update-check disable template freshness warning")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "SOURCES:")
	fmt.Fprintln(w, "  -sources LIST              sources to scan: env,file,proc")
	fmt.Fprintln(w, "  -exclude-sources LIST      sources to exclude: env,file,proc")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "FILTERING:")
	fmt.Fprintln(w, "  -id LIST                   include finding IDs: template or template:credential")
	fmt.Fprintln(w, "  -eid LIST                  exclude finding IDs: template or template:credential")
	fmt.Fprintln(w, "  -severity LIST             include severities: info,medium,high")
	fmt.Fprintln(w, "  -es LIST                   exclude severities: info,medium,high")
	fmt.Fprintln(w, "  -type LIST                 include credential types")
	fmt.Fprintln(w, "  -etype LIST                exclude credential types")
	fmt.Fprintln(w, "  -origin LIST               include origins: template,builtin,observation")
	fmt.Fprintln(w, "  -eorigin LIST              exclude origins: template,builtin,observation")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "OUTPUT:")
	fmt.Fprintln(w, "  -silent                    display findings only")
	fmt.Fprintln(w, "  -nc, -no-color             disable output content coloring (ANSI escape codes)")
	fmt.Fprintln(w, "  -j, -jsonl                 write findings in JSONL format")
	fmt.Fprintln(w, "  -o, -output PATH           write findings to file")
	fmt.Fprintln(w, "  -fingerprint-key KEY       stable credential fingerprint key for BloodHound reuse analysis")
	fmt.Fprintln(w, "  -ephemeral-fingerprint     use a per-scan random fingerprint key")
	fmt.Fprintln(w, "  -show-secrets              print full secret values")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "INTEGRATIONS:")
	fmt.Fprintln(w, "  -bh, -bloodhound           write findings as BloodHound OpenGraph JSON")
	fmt.Fprintln(w, "  -bh-setup                  register BloodHound icons and saved queries")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "OPTIMIZATIONS:")
	fmt.Fprintln(w, "  -max-file-size N           maximum config file size in bytes, default 2097152")
	fmt.Fprintln(w, "  -timeout DURATION          scan timeout, default 1m")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "DEBUG:")
	fmt.Fprintln(w, "  -debug                     print template compatibility stats")
	fmt.Fprintln(w, "  -version                   show version")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Recursive scanning is only used for bare config filenames. Absolute paths, home-relative paths,")
	fmt.Fprintln(w, "and relative paths with directories are checked directly. Skip dirs affect only recursive searches.")
}

func printBloodHoundSetupUsage(w io.Writer) {
	printBanner(w, false)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  credshound -bh-setup [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Examples:")
	fmt.Fprintln(w, "  credshound -bh-setup -server http://localhost:8080")
	fmt.Fprintln(w, "  BLOODHOUND_URL=http://localhost:8080 BLOODHOUND_TOKEN=... credshound -bh-setup")
	fmt.Fprintln(w, "  BLOODHOUND_URL=http://localhost:8080 BLOODHOUND_USERNAME=admin BLOODHOUND_PASSWORD=... credshound -bh-setup")
	fmt.Fprintln(w, "  credshound -bh-setup -reset-queries")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "INTEGRATION:")
	fmt.Fprintln(w, "  BloodHound OpenGraph       register custom node icons and saved Cypher queries")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Flags:")
	fmt.Fprintln(w, "  -server URL           BloodHound server URL, default BLOODHOUND_URL or http://localhost:8080")
	fmt.Fprintln(w, "  -token TOKEN          BloodHound JWT bearer token, default BLOODHOUND_TOKEN")
	fmt.Fprintln(w, "  -username USER        BloodHound username, default BLOODHOUND_USERNAME")
	fmt.Fprintln(w, "  -password PASSWORD    BloodHound password, default BLOODHOUND_PASSWORD")
	fmt.Fprintln(w, "  -reset-queries        delete existing CredsHound saved queries before import")
	fmt.Fprintln(w, "  -no-icons             skip custom node icon setup")
	fmt.Fprintln(w, "  -no-queries           skip saved query import")
	fmt.Fprintln(w, "  -no-verify-ssl        skip TLS certificate verification")
	fmt.Fprintln(w, "  -timeout DURATION     BloodHound API timeout, default 30s")
	fmt.Fprintln(w, "  -silent               suppress non-essential output")
	fmt.Fprintln(w, "  -nc, -no-color        disable output content coloring (ANSI escape codes)")
}

func printInspectTemplatesUsage(w io.Writer) {
	printBanner(w, false)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  credshound inspect-templates [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Examples:")
	fmt.Fprintln(w, "  credshound inspect-templates -t ~/lolcreds-templates")
	fmt.Fprintln(w, "  credshound inspect-templates -t ~/Downloads/lolcreds-data-main.zip")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Flags:")
	fmt.Fprintln(w, "  -t, -templates PATH        LOLCreds templates directory, entries directory, or zip archive")
}

func printUpdateUsage(w io.Writer, defaultInstallDir string) {
	printBanner(w, false)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  credshound update-templates [flags]")
	fmt.Fprintln(w, "  credshound -ut [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Examples:")
	fmt.Fprintln(w, "  credshound update-templates")
	fmt.Fprintln(w, "  credshound -ut")
	fmt.Fprintln(w, "  credshound -t ~/Downloads/lolcreds-data-main.zip -recursive .")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Template cache:")
	fmt.Fprintf(w, "  %s\n", defaultInstallDir)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Flags:")
	fmt.Fprintln(w, "  -timeout DURATION     Download timeout, default 2m")
	fmt.Fprintln(w, "  -silent               Suppress non-essential output")
	fmt.Fprintln(w, "  -nc, -no-color        Disable output content coloring (ANSI escape codes)")
}

func printMissingTemplates(w io.Writer, cacheDir string, color bool) {
	printBanner(w, color)
	printStatus(w, "WRN", "No LOLCreds templates found in cache", color)
	printStatus(w, "INF", "Template cache: "+cacheDir, color)
	printStatus(w, "INF", onlineUpdateHint(), color)
	printStatus(w, "INF", offlineScanHint(), color)
	fmt.Fprintln(w)
}

func updateError(err error) error {
	var downloadErr updater.DownloadError
	if errors.As(err, &downloadErr) {
		return fmt.Errorf("%w\n%s\n%s", err, onlineUpdateHint(), offlineScanHint())
	}
	return err
}

func printUpdateFailure(w io.Writer, err error, sourceURL string, color bool) {
	printStatus(w, "WRN", "Could not download LOLCreds templates", color)
	printStatus(w, "INF", "Reason: "+err.Error(), color)
	printStatus(w, "INF", offlineScanHint(), color)
	printStatus(w, "INF", "Offline zip: "+sourceURL, color)
}

func printBloodHoundSetupResult(w io.Writer, result bloodhoundintegration.Result, color bool) {
	if result.IconsCreated {
		printStatus(w, "INF", fmt.Sprintf("Registered %d BloodHound node kind(s)", len(bloodhoundintegration.NodeKinds)), color)
	}
	if result.IconsUpdated {
		printStatus(w, "INF", fmt.Sprintf("Updated %d BloodHound node kind icon(s)", len(bloodhoundintegration.NodeKinds)), color)
	}
	if !result.IconsCreated && !result.IconsUpdated {
		printStatus(w, "INF", "BloodHound node icon setup skipped", color)
	}
	if result.QueriesRemoved > 0 {
		printStatus(w, "INF", fmt.Sprintf("Removed %d existing CredsHound saved query(s)", result.QueriesRemoved), color)
	}
	if result.QueriesCreated == 0 && result.QueriesUpdated == 0 && result.QueriesSkipped == 0 && result.QueriesRemoved == 0 {
		printStatus(w, "INF", "BloodHound saved query import skipped", color)
		return
	}
	printStatus(w, "INF", fmt.Sprintf("Imported %d saved query(s); updated %d; skipped %d current", result.QueriesCreated, result.QueriesUpdated, result.QueriesSkipped), color)
}

func onlineUpdateHint() string {
	return fmt.Sprintf("Run credshound -ut to download templates from %s", updater.DefaultSourceURL)
}

func offlineScanHint() string {
	return "Offline scan: credshound -t /path/to/lolcreds-data-main.zip"
}

func printBanner(w io.Writer, color bool) {
	lines := []string{
		"   ______              __     __  __                      __",
		"  / ____/_______  ____/ /____/ / / /___  __  ______  ____/ /",
		" / /   / ___/ _ \\/ __  / ___/ /_/ / __ \\/ / / / __ \\/ __  / ",
		"/ /___/ /  /  __/ /_/ (__  ) __  / /_/ / /_/ / / / / /_/ /  ",
		"\\____/_/   \\___/\\__,_/____/_/ /_/\\____/\\__,_/_/ /_/\\__,_/   ",
	}
	for _, line := range lines {
		if color {
			line = ansi(line, magentaBold)
		}
		fmt.Fprintln(w, line)
	}
	tagline := fmt.Sprintf("        credential surface scanner | v%s", version)
	if color {
		tagline = ansi(tagline, white)
	}
	fmt.Fprintln(w, tagline)
	fmt.Fprintln(w)
}

func printScanInfo(w io.Writer, result scanner.Result, roots []string, include, exclude map[string]bool, recursive bool, maxDepth int, dataDir string, usingCache bool, metadata *updater.Result, noColor bool) {
	color := !noColor
	if usingCache {
		printStatus(w, "INF", "Templates: "+dataDir+" (cache)", color)
		printTemplateAge(w, metadata, currentTime(), color)
	} else {
		printStatus(w, "INF", "Templates: "+dataDir, color)
	}
	printStatus(w, "INF", fmt.Sprintf("Loaded %d template(s) and %d credential definition(s)", result.Stats.Templates, result.Stats.Credentials), color)
	printStatus(w, "INF", fmt.Sprintf("Compiled %d matcher pattern(s)", result.Stats.Patterns), color)
	if result.Stats.SkippedPatterns > 0 {
		printStatus(w, "WRN", fmt.Sprintf("Skipped %d unsupported matcher pattern(s)", result.Stats.SkippedPatterns), color)
	}
	printStatus(w, "INF", "Enabled sources: "+enabledSources(include, exclude), color)
	printStatus(w, "INF", "Scan roots: "+strings.Join(roots, ", "), color)
	if recursive {
		printStatus(w, "INF", fmt.Sprintf("Recursive bare-filename scan enabled with max depth %d", maxDepth), color)
	}
	printStatus(w, "INF", fmt.Sprintf("Found %d credential exposure(s)", credentialFindingCount(result.Findings)), color)
	if observations := infoFindingCount(result.Findings); observations > 0 {
		printStatus(w, "INF", fmt.Sprintf("Found %d informational observation(s)", observations), color)
	}
	fmt.Fprintln(w)
}

func withoutInfoFindings(findings []scanner.Finding) []scanner.Finding {
	out := make([]scanner.Finding, 0, len(findings))
	for _, finding := range findings {
		if strings.EqualFold(finding.Confidence, "info") {
			continue
		}
		out = append(out, finding)
	}
	return out
}

func credentialFindingCount(findings []scanner.Finding) int {
	return len(withoutInfoFindings(findings))
}

func infoFindingCount(findings []scanner.Finding) int {
	count := 0
	for _, finding := range findings {
		if strings.EqualFold(finding.Confidence, "info") {
			count++
		}
	}
	return count
}

func printTemplateAge(w io.Writer, metadata *updater.Result, now time.Time, color bool) {
	if metadata == nil || metadata.UpdatedAt.IsZero() {
		return
	}
	age := now.Sub(metadata.UpdatedAt)
	if age < 0 {
		age = 0
	}
	if age >= staleTemplatesAfter {
		printStatus(w, "WRN", fmt.Sprintf("Templates are %s old. Run credshound -ut to update.", ageLabel(age)), color)
		printStatus(w, "INF", offlineScanHint(), color)
		return
	}
	if ageLabel(age) == "today" {
		printStatus(w, "INF", "Templates last updated today", color)
		return
	}
	printStatus(w, "INF", "Templates last updated "+ageLabel(age)+" ago", color)
}

func ageLabel(age time.Duration) string {
	days := int(age.Hours() / 24)
	if days <= 0 {
		return "today"
	}
	if days == 1 {
		return "1d"
	}
	return fmt.Sprintf("%dd", days)
}

func printStatus(w io.Writer, level, message string, color bool) {
	label := "[" + level + "]"
	if color {
		switch level {
		case "INF":
			label = ansi(label, blueBold)
		case "WRN":
			label = ansi(label, yellowBold)
		default:
			label = ansi(label, cyanBright)
		}
		message = highlightStatusMessage(message)
	}
	fmt.Fprintf(w, "%s %s\n", label, message)
}

func highlightStatusMessage(message string) string {
	replacements := []struct {
		old string
		new string
	}{
		{updater.DefaultSourceURL, ansi(updater.DefaultSourceURL, linkBlue)},
		{"credshound -ut", ansi("credshound -ut", whiteBold)},
		{"credshound -t /path/to/lolcreds-data-main.zip", ansi("credshound -t /path/to/lolcreds-data-main.zip", whiteBold)},
	}
	for _, replacement := range replacements {
		message = strings.ReplaceAll(message, replacement.old, replacement.new)
	}

	if strings.HasPrefix(message, "Template cache: ") {
		return message
	}
	if strings.HasPrefix(message, "Templates: ") {
		return message
	}
	return message
}

func enabledSources(include, exclude map[string]bool) string {
	all := []string{"env", "file", "proc"}
	var enabled []string
	for _, source := range all {
		if len(include) > 0 && !include[source] {
			continue
		}
		if exclude[source] {
			continue
		}
		enabled = append(enabled, source)
	}
	if len(enabled) == 0 {
		return "none"
	}
	return strings.Join(enabled, ",")
}

func ansi(value, color string) string {
	if value == "" || color == "" {
		return value
	}
	return color + value + reset
}

func parseSources(value string) (map[string]bool, error) {
	sources := make(map[string]bool)
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(strings.ToLower(part))
		if part == "" {
			continue
		}
		source, ok := normalizeSource(part)
		if !ok {
			return nil, fmt.Errorf("unsupported source %q", part)
		}
		sources[source] = true
	}
	return sources, nil
}

func normalizeSource(source string) (string, bool) {
	switch source {
	case "env", "environment":
		return "env", true
	case "file", "files", "config_file", "config-files", "config":
		return "file", true
	case "proc", "process", "processes", "proc-environ":
		return "proc", true
	default:
		return "", false
	}
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

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

type repeatedFlag []string

func (f *repeatedFlag) String() string {
	return strings.Join(*f, ",")
}

func (f *repeatedFlag) Set(value string) error {
	if value == "" {
		return errors.New("empty value")
	}
	*f = append(*f, value)
	return nil
}

const (
	reset       = "\x1b[0m"
	magentaBold = "\x1b[1;95m"
	blueBold    = "\x1b[1;94m"
	yellowBold  = "\x1b[1;93m"
	cyanBright  = "\x1b[96m"
	white       = "\x1b[37m"
	whiteBold   = "\x1b[1;97m"
	linkBlue    = "\x1b[4;94m"
)
