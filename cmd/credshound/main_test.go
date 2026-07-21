package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/haxxm0nkey/credshound/internal/updater"
)

func TestRunRootFlagHelp(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	if err := run([]string{"-h"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	out := stdout.String()
	for _, want := range []string{"credshound [flags] [root...]", "credshound .", "credshound ~/project /etc", "TARGET:", "TEMPLATES:", "SOURCES:", "FILTERING:", "OUTPUT:", "INTEGRATIONS:", "-t, -templates", "-sources", "env,file,proc", "-id LIST", "-eid LIST", "-severity LIST", "-origin LIST", "-j, -jsonl", "-bh, -bloodhound", "-bh-setup", "-o, -output", "-fingerprint-key KEY", "-ephemeral-fingerprint", "-duc, -disable-update-check", "Skip dirs affect only recursive searches"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected help output to contain %q, got:\n%s", want, out)
		}
	}
	if strings.Contains(out, "-root") || strings.Contains(out, "-d,") || strings.Contains(out, "-format") || strings.Contains(out, "registry") {
		t.Fatalf("expected help output to hide removed compatibility flags, got:\n%s", out)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr, got %q", stderr.String())
	}
}

func TestRunUpdateTemplatesFlagHelp(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	if err := run([]string{"update-templates", "-h"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "credshound -ut") {
		t.Fatalf("expected update help, got:\n%s", stdout.String())
	}
	if strings.Contains(stdout.String(), "--source") || strings.Contains(stdout.String(), "--cache-dir") || strings.Contains(stdout.String(), "credshound ut") {
		t.Fatalf("expected update help to keep source hidden, got:\n%s", stdout.String())
	}
}

func TestRunInspectTemplatesFlagHelp(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	if err := run([]string{"inspect-templates", "-h"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	got := stdout.String()
	for _, want := range []string{"credshound inspect-templates [flags]", "-t, -templates", "lolcreds-data-main.zip"} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected %q in inspect help, got:\n%s", want, got)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr, got %q", stderr.String())
	}
}

func TestRunBloodHoundSetupFlagHelp(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	if err := run([]string{"-bh-setup", "-h"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	got := stdout.String()
	for _, want := range []string{"credshound -bh-setup [flags]", "INTEGRATION:", "BloodHound OpenGraph", "-server URL", "-token TOKEN", "-reset-queries", "BLOODHOUND_URL"} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected %q in BloodHound setup help, got:\n%s", want, got)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr, got %q", stderr.String())
	}
}

func TestPrintRunErrorForBloodHoundSetupUnknownFlagSuggestsHelp(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := run([]string{"-bh-setup", "-asdf"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected unknown flag error")
	}
	var out bytes.Buffer
	printRunError(&out, err)
	if got, want := out.String(), "unknown flag: -asdf\nUse -bh-setup -h for help.\n"; got != want {
		t.Fatalf("unexpected error output\nwant %q\n got %q", want, got)
	}
}

func TestRunInspectTemplatesPrintsTemplateData(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := run([]string{"inspect-templates", "-t", "../../testdata/lolcreds-data"}, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	got := stdout.String()
	for _, want := range []string{
		"Environment variables (1)\nEXAMPLE_API_TOKEN\n",
		"Absolute paths (0)\n",
		"Relative paths (1)\n.env\n",
		"Patterns (2)\n",
		"ex_[A-Za-z0-9]{32,}",
		`(?i)api[_-]?key\s*[:=]\s*['"]?[A-Za-z0-9]{16,}['"]?`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected %q in inspect output, got:\n%s", want, got)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr, got %q", stderr.String())
	}
}

func TestPrintRunErrorForUnknownFlagSuggestsHelp(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := run([]string{"-v"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected unknown flag error")
	}
	var out bytes.Buffer
	printRunError(&out, err)
	if got, want := out.String(), "unknown flag: -v\nUse -h for help.\n"; got != want {
		t.Fatalf("unexpected error output\nwant %q\n got %q", want, got)
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("expected no direct output, stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestPrintRunErrorForUpdateUnknownFlagSuggestsHelp(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := run([]string{"-ut", "-asdf"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected unknown flag error")
	}
	var out bytes.Buffer
	printRunError(&out, err)
	if got, want := out.String(), "unknown flag: -asdf\nUse -ut -h for help.\n"; got != want {
		t.Fatalf("unexpected error output\nwant %q\n got %q", want, got)
	}
}

func TestRunPositionalRootScans(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := run([]string{"-t", "../../testdata/lolcreds-data", "-sources", "file", "-recursive", "-silent", "-nc", "../../testdata/scan-root"}, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	got := stdout.String()
	if !strings.Contains(got, "[example-product:project-api-token]") || !strings.Contains(got, "testdata/scan-root/service/.env:1") {
		t.Fatalf("expected findings from positional scan root, got:\n%s", got)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr, got %q", stderr.String())
	}
}

func TestHelpWinsForUnknownCommand(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	if err := run([]string{"asdfadsf", "-h"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "Usage:") || !strings.Contains(stdout.String(), "credshound [flags] [root...]") {
		t.Fatalf("expected help output, got:\n%s", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr, got %q", stderr.String())
	}
}

func TestHelpWinsForUnknownFlag(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	if err := run([]string{"-asdf", "-h"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "Usage:") {
		t.Fatalf("expected help output, got:\n%s", stdout.String())
	}
}

func TestResolveDataDirUsesExplicitPath(t *testing.T) {
	got, usingCache, err := resolveDataDir("/tmp/templates")
	if err != nil {
		t.Fatal(err)
	}
	if got != "/tmp/templates" || usingCache {
		t.Fatalf("unexpected resolution: %q cache=%v", got, usingCache)
	}
}

func TestResolveTemplateFlag(t *testing.T) {
	got, err := resolveTemplateFlag("", "/tmp/templates.zip")
	if err != nil {
		t.Fatal(err)
	}
	if got != "/tmp/templates.zip" {
		t.Fatalf("expected long template flag value, got %q", got)
	}

	got, err = resolveTemplateFlag("/tmp/templates", "/tmp/templates")
	if err != nil {
		t.Fatal(err)
	}
	if got != "/tmp/templates" {
		t.Fatalf("expected shared template flag value, got %q", got)
	}

	if _, err := resolveTemplateFlag("/a", "/b"); err == nil {
		t.Fatal("expected conflicting template flags to fail")
	}
}

func TestResolveOutputFlag(t *testing.T) {
	got, err := resolveOutputFlag("/tmp/out.txt", "")
	if err != nil {
		t.Fatal(err)
	}
	if got != "/tmp/out.txt" {
		t.Fatalf("expected output path, got %q", got)
	}
	if _, err := resolveOutputFlag("/a", "/b"); err == nil {
		t.Fatal("expected conflicting output flags to fail")
	}
}

func TestRunRemovedDataFlagFails(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := run([]string{"-d", "../../testdata/lolcreds-data"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected removed -d flag to fail")
	}
	var out bytes.Buffer
	printRunError(&out, err)
	if got, want := out.String(), "unknown flag: -d\nUse -h for help.\n"; got != want {
		t.Fatalf("unexpected error output\nwant %q\n got %q", want, got)
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("expected no direct output, stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestRunRegistrySourceFails(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := run([]string{"-t", "../../testdata/lolcreds-data", "-sources", "registry"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected registry source to fail")
	}
	var out bytes.Buffer
	printRunError(&out, err)
	if got, want := out.String(), "credshound: unsupported source \"registry\"\n"; got != want {
		t.Fatalf("unexpected error output\nwant %q\n got %q", want, got)
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("expected no direct output, stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestParseProcSource(t *testing.T) {
	sources, err := parseSources("process,proc-environ")
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 1 || !sources["proc"] {
		t.Fatalf("expected proc source normalization, got %+v", sources)
	}
}

func TestRunTopLevelTemplateFlagScans(t *testing.T) {
	isolateHome(t)
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := run([]string{"-t", "../../testdata/lolcreds-data", "-silent", "-nc"}, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no findings from fixture without env, got %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr, got %q", stderr.String())
	}
}

func TestRunScansExportedEnvironmentVariable(t *testing.T) {
	t.Setenv("EXAMPLE_API_TOKEN", "ex_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := run([]string{"-t", "../../testdata/lolcreds-data", "-sources", "env", "-silent", "-nc"}, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	got := stdout.String()
	want := "[example-product:api-token-env] [env] [high] [EXAMPLE_API_TOKEN] [api_token] [ex_A****7890] [https://lolcreds.haxx.it/example-product#api-token-env]"
	if !strings.Contains(got, want) {
		t.Fatalf("expected env finding %q, got:\n%s", want, got)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr, got %q", stderr.String())
	}
}

func TestRunFiltersBySeverity(t *testing.T) {
	t.Setenv("EXAMPLE_API_TOKEN", "ex_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := run([]string{"-t", "../../testdata/lolcreds-data", "-sources", "env", "-severity", "medium", "-silent", "-nc"}, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected high finding to be filtered by medium severity, got:\n%s", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr, got %q", stderr.String())
	}
}

func TestRunFiltersByID(t *testing.T) {
	t.Setenv("EXAMPLE_API_TOKEN", "ex_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := run([]string{"-t", "../../testdata/lolcreds-data", "-sources", "env", "-id", "example-product:api-token-env", "-silent", "-nc"}, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "[example-product:api-token-env]") {
		t.Fatalf("expected included finding, got:\n%s", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr, got %q", stderr.String())
	}
}

func TestRunExcludesByID(t *testing.T) {
	t.Setenv("EXAMPLE_API_TOKEN", "ex_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := run([]string{"-t", "../../testdata/lolcreds-data", "-sources", "env", "-eid", "example-product", "-silent", "-nc"}, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected excluded finding to be omitted, got:\n%s", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr, got %q", stderr.String())
	}
}

func TestRunRejectsUnsupportedSeverityFilter(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := run([]string{"-t", "../../testdata/lolcreds-data", "-severity", "critical"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected unsupported severity to fail")
	}
	if !strings.Contains(err.Error(), `unsupported severity "critical"`) {
		t.Fatalf("unexpected error %v", err)
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("expected no direct output, stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestRunJSONLShortFlag(t *testing.T) {
	t.Setenv("EXAMPLE_API_TOKEN", "ex_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := run([]string{"-t", "../../testdata/lolcreds-data", "-sources", "env", "-silent", "-j"}, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), `"template_id":"example-product"`) {
		t.Fatalf("expected JSONL finding, got:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), `"source":"env"`) {
		t.Fatalf("expected env JSONL finding, got:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), `"origin":"template"`) {
		t.Fatalf("expected JSONL finding to include template origin, got:\n%s", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr, got %q", stderr.String())
	}
}

func TestRunBloodHoundFingerprintKeyFlagIsStable(t *testing.T) {
	t.Setenv("EXAMPLE_API_TOKEN", "ex_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")

	first := runBloodHoundForTest(t, "-fingerprint-key", "shared-test-key")
	second := runBloodHoundForTest(t, "-fingerprint-key", "shared-test-key")
	third := runBloodHoundForTest(t, "-fingerprint-key", "other-test-key")

	firstCredential := credentialNodeForTest(t, first)
	secondCredential := credentialNodeForTest(t, second)
	thirdCredential := credentialNodeForTest(t, third)

	if firstCredential.ID != secondCredential.ID {
		t.Fatalf("expected same key to produce same credential ID, got %q and %q", firstCredential.ID, secondCredential.ID)
	}
	if firstCredential.Properties["secret_fingerprint"] != secondCredential.Properties["secret_fingerprint"] {
		t.Fatalf("expected same key to produce same fingerprint, got %q and %q", firstCredential.Properties["secret_fingerprint"], secondCredential.Properties["secret_fingerprint"])
	}
	if firstCredential.ID == thirdCredential.ID {
		t.Fatalf("expected different key to produce different credential ID %q", firstCredential.ID)
	}
}

func TestRunBloodHoundDefaultFingerprintKeyIsStable(t *testing.T) {
	t.Setenv("EXAMPLE_API_TOKEN", "ex_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")

	first := credentialNodeForTest(t, runBloodHoundForTest(t))
	second := credentialNodeForTest(t, runBloodHoundForTest(t))

	if first.ID != second.ID {
		t.Fatalf("expected default fingerprint key to be stable, got %q and %q", first.ID, second.ID)
	}
	if first.Properties["secret_fingerprint"] != second.Properties["secret_fingerprint"] {
		t.Fatalf("expected default fingerprint to be stable, got %q and %q", first.Properties["secret_fingerprint"], second.Properties["secret_fingerprint"])
	}
}

func TestRunBloodHoundEphemeralFingerprintKeyChangesCredentialID(t *testing.T) {
	t.Setenv("EXAMPLE_API_TOKEN", "ex_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")
	t.Setenv("CREDSHOUND_FINGERPRINT_KEY", "env-key-that-ephemeral-should-ignore")

	first := credentialNodeForTest(t, runBloodHoundForTest(t, "-ephemeral-fingerprint"))
	second := credentialNodeForTest(t, runBloodHoundForTest(t, "-ephemeral-fingerprint"))

	if first.ID == second.ID {
		t.Fatalf("expected ephemeral fingerprint key to change credential ID %q", first.ID)
	}
}

func TestRunBloodHoundFlag(t *testing.T) {
	t.Setenv("EXAMPLE_API_TOKEN", "ex_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := run([]string{"-t", "../../testdata/lolcreds-data", "-sources", "env", "-silent", "-bh"}, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}

	var payload struct {
		Graph struct {
			Nodes []struct {
				Kinds      []string          `json:"kinds"`
				Properties map[string]string `json:"properties"`
			} `json:"nodes"`
			Edges []struct {
				Kind  string `json:"kind"`
				Start struct {
					MatchBy string `json:"match_by"`
				} `json:"start"`
				End struct {
					MatchBy string `json:"match_by"`
				} `json:"end"`
			} `json:"edges"`
		} `json:"graph"`
		Metadata struct {
			SourceKind string `json:"source_kind"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("expected BloodHound JSON output: %v\n%s", err, stdout.String())
	}
	if payload.Metadata.SourceKind != "CredsHound" {
		t.Fatalf("unexpected source kind %q", payload.Metadata.SourceKind)
	}
	if len(payload.Graph.Nodes) != 4 {
		t.Fatalf("expected host, location, creds, and product nodes, got %+v", payload.Graph.Nodes)
	}
	if len(payload.Graph.Edges) != 3 {
		t.Fatalf("expected host->location, location->creds, and creds->product edges, got %+v", payload.Graph.Edges)
	}
	if !bloodHoundKindsContain(payload.Graph.Nodes, "CHExposure") {
		t.Fatalf("expected CHExposure node, got %+v", payload.Graph.Nodes)
	}
	if !bloodHoundKindsContain(payload.Graph.Nodes, "CHCredential") {
		t.Fatalf("expected CHCredential node, got %+v", payload.Graph.Nodes)
	}
	if !bloodHoundKindsContain(payload.Graph.Nodes, "CHService") {
		t.Fatalf("expected CHService node, got %+v", payload.Graph.Nodes)
	}
	if bloodHoundKindsContain(payload.Graph.Nodes, "CHDetector") {
		t.Fatalf("expected no CHDetector node, got %+v", payload.Graph.Nodes)
	}
	for _, node := range payload.Graph.Nodes {
		if _, exists := node.Properties["objectid"]; exists {
			t.Fatalf("expected no reserved objectid property, got %+v", payload.Graph.Nodes)
		}
	}
	if payload.Graph.Edges[0].Start.MatchBy != "id" || payload.Graph.Edges[0].End.MatchBy != "id" {
		t.Fatalf("expected id-matched endpoints, got %+v", payload.Graph.Edges)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr, got %q", stderr.String())
	}
}

type bloodHoundPayloadForTest struct {
	Graph struct {
		Nodes []struct {
			ID         string            `json:"id"`
			Kinds      []string          `json:"kinds"`
			Properties map[string]string `json:"properties"`
		} `json:"nodes"`
	} `json:"graph"`
}

func runBloodHoundForTest(t *testing.T, extraArgs ...string) bloodHoundPayloadForTest {
	t.Helper()
	args := []string{"-t", "../../testdata/lolcreds-data", "-sources", "env", "-silent", "-bh"}
	args = append(args, extraArgs...)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if err := run(args, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr, got %q", stderr.String())
	}

	var payload bloodHoundPayloadForTest
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("expected BloodHound JSON output: %v\n%s", err, stdout.String())
	}
	return payload
}

func credentialNodeForTest(t *testing.T, payload bloodHoundPayloadForTest) struct {
	ID         string            `json:"id"`
	Kinds      []string          `json:"kinds"`
	Properties map[string]string `json:"properties"`
} {
	t.Helper()
	for _, node := range payload.Graph.Nodes {
		for _, kind := range node.Kinds {
			if kind == "CHCredential" {
				return node
			}
		}
	}
	t.Fatalf("expected CHCredential node, got %+v", payload.Graph.Nodes)
	return struct {
		ID         string            `json:"id"`
		Kinds      []string          `json:"kinds"`
		Properties map[string]string `json:"properties"`
	}{}
}

func TestRunRejectsMultipleOutputFormats(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := run([]string{"-t", "../../testdata/lolcreds-data", "-j", "-bh"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected conflicting output formats to fail")
	}
	if !strings.Contains(err.Error(), "use only one output format") {
		t.Fatalf("unexpected error %v", err)
	}
}

func TestRunOutputFileFlag(t *testing.T) {
	t.Setenv("EXAMPLE_API_TOKEN", "ex_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")
	outPath := filepath.Join(t.TempDir(), "findings.txt")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := run([]string{"-t", "../../testdata/lolcreds-data", "-sources", "env", "-silent", "-nc", "-o", outPath}, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected findings to be written to file, got stdout %q", stdout.String())
	}
	b, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "[example-product:api-token-env]") {
		t.Fatalf("expected finding in output file, got:\n%s", string(b))
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr, got %q", stderr.String())
	}
}

func bloodHoundKindsContain(nodes []struct {
	Kinds      []string          `json:"kinds"`
	Properties map[string]string `json:"properties"`
}, kind string) bool {
	for _, node := range nodes {
		for _, nodeKind := range node.Kinds {
			if nodeKind == kind {
				return true
			}
		}
	}
	return false
}

func TestRunSilentSuppressesInfoFindings(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := run([]string{"-t", "../../testdata/lolcreds-data", "-sources", "file", "-recursive", "-silent", "-nc", "../../testdata/scan-root"}, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	got := stdout.String()
	if strings.Contains(got, "[info]") || strings.Contains(got, "path exists") || strings.Contains(got, "filesystem:interesting-location") {
		t.Fatalf("expected silent output to exclude info findings, got:\n%s", got)
	}
	if !strings.Contains(got, "[high]") {
		t.Fatalf("expected silent output to include credential finding, got:\n%s", got)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr, got %q", stderr.String())
	}
}

func TestRunNoColorShortFlag(t *testing.T) {
	originalDefaultInstallDir := defaultInstallDir
	t.Cleanup(func() { defaultInstallDir = originalDefaultInstallDir })
	defaultInstallDir = func() (string, error) {
		return filepath.Join(t.TempDir(), "missing-cache"), nil
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if err := run([]string{"-nc"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout.String(), "\x1b[") {
		t.Fatalf("expected no ANSI color output, got %q", stdout.String())
	}
}

func TestMissingTemplatesHighlightsCommandAndURL(t *testing.T) {
	var stdout bytes.Buffer

	printMissingTemplates(&stdout, "/tmp/credshound/templates", true)
	got := stdout.String()
	for _, want := range []string{
		whiteBold + "credshound -ut" + reset,
		linkBlue + updater.DefaultSourceURL + reset,
		whiteBold + "credshound -t /path/to/lolcreds-data-main.zip" + reset,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected highlighted %q in output:\n%q", want, got)
		}
	}
	if strings.Contains(got, "\x1b[90m/tmp/credshound/templates") {
		t.Fatalf("expected cache path to stay uncolored, got:\n%q", got)
	}
}

func TestRunSilentMissingTemplatesIsQuiet(t *testing.T) {
	originalDefaultInstallDir := defaultInstallDir
	t.Cleanup(func() { defaultInstallDir = originalDefaultInstallDir })
	defaultInstallDir = func() (string, error) {
		return filepath.Join(t.TempDir(), "missing-cache"), nil
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if err := run([]string{"-silent"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout, got %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr, got %q", stderr.String())
	}
}

func TestRunDefaultMissingTemplatesPrintsGuidance(t *testing.T) {
	originalDefaultInstallDir := defaultInstallDir
	t.Cleanup(func() { defaultInstallDir = originalDefaultInstallDir })
	defaultInstallDir = func() (string, error) {
		return filepath.Join(t.TempDir(), "missing-cache"), nil
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if err := run(nil, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	got := stdout.String()
	for _, want := range []string{"No LOLCreds templates found in cache", "download templates from", updater.DefaultSourceURL, "Offline scan:", "credshound -t /path/to/lolcreds-data-main.zip"} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected %q in output, got:\n%s", want, got)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr, got %q", stderr.String())
	}
}

func TestRunCachedTemplatesPrintsFreshAge(t *testing.T) {
	originalDefaultInstallDir := defaultInstallDir
	originalCurrentTime := currentTime
	t.Cleanup(func() {
		defaultInstallDir = originalDefaultInstallDir
		currentTime = originalCurrentTime
	})
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	currentTime = func() time.Time { return now }
	cacheDir := writeTemplateCache(t, now.Add(-72*time.Hour))
	defaultInstallDir = func() (string, error) {
		return cacheDir, nil
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if err := run([]string{"-nc"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	got := stdout.String()
	if !strings.Contains(got, "[INF] Templates last updated 3d ago") {
		t.Fatalf("expected fresh template age in output, got:\n%s", got)
	}
	if strings.Contains(got, "Templates are") {
		t.Fatalf("expected no stale warning, got:\n%s", got)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr, got %q", stderr.String())
	}
}

func TestRunCachedTemplatesPrintsStaleWarning(t *testing.T) {
	originalDefaultInstallDir := defaultInstallDir
	originalCurrentTime := currentTime
	t.Cleanup(func() {
		defaultInstallDir = originalDefaultInstallDir
		currentTime = originalCurrentTime
	})
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	currentTime = func() time.Time { return now }
	cacheDir := writeTemplateCache(t, now.Add(-14*24*time.Hour))
	defaultInstallDir = func() (string, error) {
		return cacheDir, nil
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if err := run([]string{"-nc"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	got := stdout.String()
	for _, want := range []string{
		"[WRN] Templates are 14d old. Run credshound -ut to update.",
		"[INF] Offline scan: credshound -t /path/to/lolcreds-data-main.zip",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected %q in output, got:\n%s", want, got)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr, got %q", stderr.String())
	}
}

func TestRunDisableUpdateCheckSuppressesTemplateAge(t *testing.T) {
	originalDefaultInstallDir := defaultInstallDir
	originalCurrentTime := currentTime
	t.Cleanup(func() {
		defaultInstallDir = originalDefaultInstallDir
		currentTime = originalCurrentTime
	})
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	currentTime = func() time.Time { return now }
	cacheDir := writeTemplateCache(t, now.Add(-14*24*time.Hour))
	defaultInstallDir = func() (string, error) {
		return cacheDir, nil
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if err := run([]string{"-nc", "-duc"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	got := stdout.String()
	if strings.Contains(got, "Templates are") || strings.Contains(got, "Templates last updated") {
		t.Fatalf("expected no template freshness output, got:\n%s", got)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr, got %q", stderr.String())
	}
}

func TestRunSilentCachedTemplatesDoesNotPrintAge(t *testing.T) {
	isolateHome(t)
	originalDefaultInstallDir := defaultInstallDir
	t.Cleanup(func() {
		defaultInstallDir = originalDefaultInstallDir
	})
	cacheDir := writeTemplateCache(t, time.Now().Add(-14*24*time.Hour))
	defaultInstallDir = func() (string, error) {
		return cacheDir, nil
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if err := run([]string{"-silent"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout, got %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr, got %q", stderr.String())
	}
}

func TestRunUpdateTemplatesDownloadFailurePrintsGuidanceWithoutError(t *testing.T) {
	originalDefaultInstallDir := defaultInstallDir
	originalUpdateTemplates := updateTemplates
	t.Cleanup(func() {
		defaultInstallDir = originalDefaultInstallDir
		updateTemplates = originalUpdateTemplates
	})
	defaultInstallDir = func() (string, error) {
		return filepath.Join(t.TempDir(), "templates"), nil
	}
	updateTemplates = func(ctx context.Context, opts updater.Options) (updater.Result, error) {
		return updater.Result{}, updater.DownloadError{
			Source: opts.SourceURL,
			Err:    errors.New("lookup github.com: no such host"),
		}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if err := run([]string{"-ut", "-nc"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	got := stdout.String()
	for _, want := range []string{
		"[WRN] Could not download LOLCreds templates",
		"Reason: could not download templates from " + updater.DefaultSourceURL,
		"Offline scan: credshound -t /path/to/lolcreds-data-main.zip",
		"Offline zip: " + updater.DefaultSourceURL,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected %q in output, got:\n%s", want, got)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr, got %q", stderr.String())
	}
}

func writeTemplateCache(t *testing.T, updatedAt time.Time) string {
	t.Helper()

	cacheDir := filepath.Join(t.TempDir(), "templates")
	entriesDir := filepath.Join(cacheDir, "entries")
	if err := os.MkdirAll(entriesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	template := "id: example\nname: Example\ncredentials: []\n"
	if err := os.WriteFile(filepath.Join(entriesDir, "example.yaml"), []byte(template), 0o644); err != nil {
		t.Fatal(err)
	}
	metadata, err := json.MarshalIndent(updater.Result{
		SourceURL:  updater.DefaultSourceURL,
		InstallDir: cacheDir,
		UpdatedAt:  updatedAt,
		Files:      1,
		Bytes:      int64(len(template)),
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cacheDir, "credshound-update.json"), append(metadata, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	return cacheDir
}

func isolateHome(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
}

func TestUpdateErrorIncludesOfflineGuidance(t *testing.T) {
	err := updateError(updater.DownloadError{
		Source: updater.DefaultSourceURL,
		Err:    errors.New("lookup github.com: no such host"),
	})
	got := err.Error()
	for _, want := range []string{"Run credshound -ut to download templates from " + updater.DefaultSourceURL, "Offline scan: credshound -t /path/to/lolcreds-data-main.zip"} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected %q in error, got %q", want, got)
		}
	}
}
