package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/haxxm0nkey/credshound/internal/templates"
)

func TestScanEnvironmentFinding(t *testing.T) {
	t.Setenv("EXAMPLE_API_TOKEN", "ex_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")

	findings, err := Scan(context.Background(), []templates.Entry{
		{
			ID:   "example-product",
			Name: "Example Product",
			Credentials: []templates.Credential{
				{
					ID:   "api-token-env",
					Name: "API token from environment variables",
					Type: "api_token",
					Location: []templates.Location{
						{Type: "environment", Path: "EXAMPLE_API_TOKEN"},
					},
					LooksLike: []templates.LooksLike{
						{Pattern: `ex_[A-Za-z0-9]{32,}`},
					},
				},
			},
		},
	}, Options{URLBase: "https://lolcreds.haxx.it"})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	finding := findings[0]
	if finding.Source != "env" {
		t.Fatalf("expected env source, got %q", finding.Source)
	}
	if finding.Origin != OriginTemplate {
		t.Fatalf("expected template origin, got %q", finding.Origin)
	}
	if finding.Confidence != "high" {
		t.Fatalf("expected high confidence, got %q", finding.Confidence)
	}
	if finding.Evidence != "ex_A****7890" {
		t.Fatalf("unexpected evidence %q", finding.Evidence)
	}
	if finding.URL != "https://lolcreds.haxx.it/example-product#api-token-env" {
		t.Fatalf("unexpected URL %q", finding.URL)
	}
}

func TestScanEnvironmentFindingMediumWhenPatternDoesNotMatch(t *testing.T) {
	t.Setenv("EXAMPLE_API_TOKEN", "not-a-template-token")

	findings, err := Scan(context.Background(), []templates.Entry{
		{
			ID:   "example-product",
			Name: "Example Product",
			Credentials: []templates.Credential{
				{
					ID:   "api-token-env",
					Name: "API token from environment variables",
					Type: "api_token",
					Location: []templates.Location{
						{Type: "environment", Path: "EXAMPLE_API_TOKEN"},
					},
					LooksLike: []templates.LooksLike{
						{Pattern: `ex_[A-Za-z0-9]{32,}`},
					},
				},
			},
		},
	}, Options{URLBase: "https://lolcreds.haxx.it"})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Confidence != "medium" {
		t.Fatalf("expected medium confidence, got %q", findings[0].Confidence)
	}
	if findings[0].Evidence != "not-****oken" {
		t.Fatalf("unexpected evidence %q", findings[0].Evidence)
	}
}

func TestScanFileFinding(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte(`api_key="abcd1234abcd1234"`), 0o600); err != nil {
		t.Fatal(err)
	}

	findings, err := Scan(context.Background(), []templates.Entry{
		{
			ID:   "example-product",
			Name: "Example Product",
			Credentials: []templates.Credential{
				{
					ID:   "project-api-token",
					Name: "Project API token",
					Type: "api_token",
					Location: []templates.Location{
						{Type: "config_file", Path: ".env"},
					},
					LooksLike: []templates.LooksLike{
						{Pattern: `(?i)api[_-]?key\s*[:=]\s*['"]?[A-Za-z0-9]{16,}['"]?`},
					},
				},
			},
		},
	}, Options{Roots: []string{root}, MaxFileSize: 1024, URLBase: "https://lolcreds.haxx.it"})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	info := findByConfidence(findings, "info")
	if info == nil {
		t.Fatalf("expected info path finding, got %+v", findings)
	}
	if info.Location != filepath.Join(root, ".env") {
		t.Fatalf("unexpected info location %q", info.Location)
	}
	if info.TemplateID != "filesystem" || info.CredentialID != "interesting-location" {
		t.Fatalf("expected synthetic interesting-location finding, got %s:%s", info.TemplateID, info.CredentialID)
	}
	if info.Origin != OriginObservation {
		t.Fatalf("expected observation origin, got %q", info.Origin)
	}
	if info.CredentialType != "config_file" {
		t.Fatalf("expected config_file type, got %q", info.CredentialType)
	}
	if info.Evidence != "path exists" {
		t.Fatalf("unexpected info evidence %q", info.Evidence)
	}
	if !sameStrings(info.References, []string{"example-product"}) {
		t.Fatalf("unexpected references %+v", info.References)
	}

	finding := findByConfidence(findings, "high")
	if finding == nil {
		t.Fatalf("expected high confidence finding, got %+v", findings)
	}
	if finding.Source != "file" {
		t.Fatalf("expected file source, got %q", finding.Source)
	}
	if finding.Origin != OriginTemplate {
		t.Fatalf("expected template origin, got %q", finding.Origin)
	}
	if finding.Location != filepath.Join(root, ".env")+":1" {
		t.Fatalf("unexpected location %q", finding.Location)
	}
	if finding.Evidence != "api_key=abcd****1234" {
		t.Fatalf("unexpected evidence %q", finding.Evidence)
	}
}

func TestScanRecursiveBareFileFinding(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "services", "api")
	skipped := filepath.Join(root, "node_modules", "pkg")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(skipped, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, ".env"), []byte("api_key=nestedsecret1234\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skipped, ".env"), []byte("api_key=skippedsecret123\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	findings, err := Scan(context.Background(), []templates.Entry{
		{
			ID:   "example-product",
			Name: "Example Product",
			Credentials: []templates.Credential{
				{
					ID:   "project-api-token",
					Name: "Project API token",
					Type: "api_token",
					Location: []templates.Location{
						{Type: "config_file", Path: ".env"},
					},
					LooksLike: []templates.LooksLike{
						{Pattern: `(?i)api[_-]?key\s*[:=]\s*['"]?[A-Za-z0-9]{16,}['"]?`},
					},
				},
			},
		},
	}, Options{
		Roots:       []string{root},
		MaxFileSize: 1024,
		Recursive:   true,
		MaxDepth:    4,
		URLBase:     "https://lolcreds.haxx.it",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %+v", len(findings), findings)
	}
	wantLocation := filepath.Join(nested, ".env") + ":1"
	high := findByConfidence(findings, "high")
	if high == nil {
		t.Fatalf("expected high confidence finding, got %+v", findings)
	}
	if high.Location != wantLocation {
		t.Fatalf("expected location %q, got %q", wantLocation, high.Location)
	}
}

func TestScanEnvNameInDefaultCredentialFile(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("EXAMPLE_API_TOKEN=\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	findings, err := Scan(context.Background(), []templates.Entry{
		{
			ID:   "example-product",
			Name: "Example Product",
			Credentials: []templates.Credential{
				{
					ID:   "api-token-env",
					Name: "API token from environment variables",
					Type: "api_token",
					Location: []templates.Location{
						{Type: "environment", Path: "EXAMPLE_API_TOKEN"},
					},
				},
			},
		},
	}, Options{
		Roots:       []string{root},
		MaxFileSize: 1024,
		URLBase:     "https://lolcreds.haxx.it",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	finding := findings[0]
	if finding.Confidence != "info" {
		t.Fatalf("expected info confidence, got %q", finding.Confidence)
	}
	if finding.TemplateID != "filesystem" || finding.CredentialID != "env-name-reference" {
		t.Fatalf("expected synthetic env-name-reference finding, got %s:%s", finding.TemplateID, finding.CredentialID)
	}
	if finding.Origin != OriginObservation {
		t.Fatalf("expected observation origin, got %q", finding.Origin)
	}
	if finding.CredentialType != "environment" {
		t.Fatalf("expected environment type, got %q", finding.CredentialType)
	}
	if finding.Location != filepath.Join(root, ".env") {
		t.Fatalf("unexpected location %q", finding.Location)
	}
	if finding.Evidence != "env var name referenced" {
		t.Fatalf("unexpected evidence %q", finding.Evidence)
	}
	if !sameStrings(finding.References, []string{"example-product"}) {
		t.Fatalf("unexpected references %+v", finding.References)
	}
}

func TestScanEnvNameInGenericConfigFile(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "config")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "credentials"), []byte("EXAMPLE_API_TOKEN=\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	findings, err := Scan(context.Background(), []templates.Entry{
		{
			ID:   "example-product",
			Name: "Example Product",
			Credentials: []templates.Credential{
				{
					ID:   "api-token-env",
					Name: "API token from environment variables",
					Type: "api_token",
					Location: []templates.Location{
						{Type: "environment", Path: "EXAMPLE_API_TOKEN"},
					},
				},
			},
		},
	}, Options{
		Roots:       []string{root},
		MaxFileSize: 1024,
		URLBase:     "https://lolcreds.haxx.it",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Location != filepath.Join(configDir, "credentials") {
		t.Fatalf("unexpected location %q", findings[0].Location)
	}
}

func TestScanAggregatesEnvNameReferenceLines(t *testing.T) {
	root := t.TempDir()
	content := "EXAMPLE_API_TOKEN=\nother=true\nEXAMPLE_API_TOKEN=\n"
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	findings, err := Scan(context.Background(), []templates.Entry{
		{
			ID:   "example-product",
			Name: "Example Product",
			Credentials: []templates.Credential{
				{
					ID:   "api-token-env",
					Name: "API token from environment variables",
					Type: "api_token",
					Location: []templates.Location{
						{Type: "environment", Path: "EXAMPLE_API_TOKEN"},
					},
				},
			},
		},
	}, Options{
		Roots:       []string{root},
		MaxFileSize: 1024,
		URLBase:     "https://lolcreds.haxx.it",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Location != filepath.Join(root, ".env") {
		t.Fatalf("unexpected location %q", findings[0].Location)
	}
	if findings[0].Evidence != "env var name referenced" {
		t.Fatalf("unexpected evidence %q", findings[0].Evidence)
	}
}

func TestScanCompactsManyEnvNameReferences(t *testing.T) {
	root := t.TempDir()
	content := strings.Join([]string{
		"FIRST_TOKEN=",
		"SECOND_TOKEN=",
		"THIRD_TOKEN=",
		"FOURTH_TOKEN=",
		"FIFTH_TOKEN=",
	}, "\n")
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	findings, err := Scan(context.Background(), []templates.Entry{
		{
			ID:   "example-product",
			Name: "Example Product",
			Credentials: []templates.Credential{
				{
					ID:   "api-token-env",
					Name: "API token from environment variables",
					Type: "api_token",
					Location: []templates.Location{
						{Type: "environment", Path: "FIRST_TOKEN, SECOND_TOKEN, THIRD_TOKEN, FOURTH_TOKEN, FIFTH_TOKEN"},
					},
				},
			},
		},
	}, Options{
		Roots:       []string{root},
		MaxFileSize: 1024,
		URLBase:     "https://lolcreds.haxx.it",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 compacted finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Location != filepath.Join(root, ".env") {
		t.Fatalf("unexpected location %q", findings[0].Location)
	}
	if findings[0].Evidence != "env var name referenced" {
		t.Fatalf("unexpected evidence %q", findings[0].Evidence)
	}
}

func TestScanAggregatesPathInfoReferences(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("empty=true\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	findings, err := Scan(context.Background(), []templates.Entry{
		{
			ID:   "product-a",
			Name: "Product A",
			Credentials: []templates.Credential{
				{
					ID:   "token-a",
					Name: "Token A",
					Type: "token",
					Location: []templates.Location{
						{Type: "config_file", Path: ".env"},
					},
				},
			},
		},
		{
			ID:   "product-b",
			Name: "Product B",
			Credentials: []templates.Credential{
				{
					ID:   "token-b",
					Name: "Token B",
					Type: "token",
					Location: []templates.Location{
						{Type: "config_file", Path: ".env"},
					},
				},
			},
		},
	}, Options{
		Roots:       []string{root},
		MaxFileSize: 1024,
		URLBase:     "https://lolcreds.haxx.it",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 aggregated finding, got %d: %+v", len(findings), findings)
	}
	finding := findings[0]
	if finding.TemplateID != "filesystem" || finding.CredentialID != "interesting-location" {
		t.Fatalf("expected synthetic interesting-location finding, got %s:%s", finding.TemplateID, finding.CredentialID)
	}
	if finding.Location != filepath.Join(root, ".env") {
		t.Fatalf("unexpected location %q", finding.Location)
	}
	if !sameStrings(finding.References, []string{"product-a", "product-b"}) {
		t.Fatalf("unexpected references %+v", finding.References)
	}
}

func TestScanSuppressesMegaGenericPathExists(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("empty=true\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var entries []templates.Entry
	for i := 0; i < maxInterestingLocationReferences+1; i++ {
		id := "product-" + strconv.Itoa(i)
		entries = append(entries, templates.Entry{
			ID:   id,
			Name: id,
			Credentials: []templates.Credential{
				{
					ID:   "token",
					Name: "Token",
					Type: "token",
					Location: []templates.Location{
						{Type: "config_file", Path: ".env"},
					},
				},
			},
		})
	}

	findings, err := Scan(context.Background(), entries, Options{
		Roots:       []string{root},
		MaxFileSize: 1024,
		URLBase:     "https://lolcreds.haxx.it",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected mega-generic path exists observation to be suppressed, got %+v", findings)
	}
}

func TestScanSuppressesLowSignalPathExists(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".zshrc"), []byte("export EXAMPLE=true\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	findings, err := Scan(context.Background(), []templates.Entry{
		{
			ID:   "shell-product",
			Name: "Shell Product",
			Credentials: []templates.Credential{
				{
					ID:   "shell-config",
					Name: "Shell Config",
					Type: "token",
					Location: []templates.Location{
						{Type: "config_file", Path: ".zshrc"},
					},
				},
			},
		},
	}, Options{
		Roots:       []string{root},
		MaxFileSize: 1024,
		URLBase:     "https://lolcreds.haxx.it",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected low-signal path exists observation to be suppressed, got %+v", findings)
	}
}

func TestDefaultCredentialFilePathsAreVendorAgnostic(t *testing.T) {
	paths := strings.Join(defaultCredentialFilePaths(), "\n")
	for _, disallowed := range []string{
		".aws",
		".azure",
		".docker",
		".kube",
		".npmrc",
		".pypirc",
		".terraform",
		"docker-compose",
		"gcloud",
		"NuGet",
		"terraform",
	} {
		if strings.Contains(paths, disallowed) {
			t.Fatalf("default credential paths should stay vendor-agnostic; found %q in:\n%s", disallowed, paths)
		}
	}
}

func TestScanSourceFilter(t *testing.T) {
	t.Setenv("EXAMPLE_API_TOKEN", "ex_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")

	findings, err := Scan(context.Background(), []templates.Entry{
		{
			ID:   "example-product",
			Name: "Example Product",
			Credentials: []templates.Credential{
				{
					ID:   "api-token-env",
					Name: "API token from environment variables",
					Type: "api_token",
					Location: []templates.Location{
						{Type: "environment", Path: "EXAMPLE_API_TOKEN"},
					},
					LooksLike: []templates.LooksLike{
						{Pattern: `ex_[A-Za-z0-9]{32,}`},
					},
				},
			},
		},
	}, Options{
		URLBase:        "https://lolcreds.haxx.it",
		IncludeSources: map[string]bool{"file": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected env finding to be filtered out, got %d findings", len(findings))
	}
}

func TestBuiltinSSHPrivateKeyTakesPrecedenceOverTemplateFindings(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(sshDir, "id_rsa")
	keyContent := "-----BEGIN OPENSSH PRIVATE KEY-----\nredacted\n-----END OPENSSH PRIVATE KEY-----\n"
	if err := os.WriteFile(keyPath, []byte(keyContent), 0o600); err != nil {
		t.Fatal(err)
	}

	entries := []templates.Entry{
		{
			ID:   "product-a",
			Name: "Product A",
			Credentials: []templates.Credential{
				{
					ID:   "ssh-private-key",
					Name: "SSH private key",
					Type: "key_pair",
					Location: []templates.Location{
						{Type: "config_file", Path: "~/.ssh/id_rsa"},
					},
					LooksLike: []templates.LooksLike{
						{Pattern: `-----BEGIN OPENSSH PRIVATE KEY-----`},
					},
				},
			},
		},
		{
			ID:   "product-b",
			Name: "Product B",
			Credentials: []templates.Credential{
				{
					ID:   "ssh-private-key",
					Name: "SSH private key",
					Type: "key_pair",
					Location: []templates.Location{
						{Type: "config_file", Path: "~/.ssh/id_rsa"},
					},
					LooksLike: []templates.LooksLike{
						{Pattern: `-----BEGIN OPENSSH PRIVATE KEY-----`},
					},
				},
			},
		},
	}

	findings, err := Scan(context.Background(), entries, Options{
		MaxFileSize:    1024,
		URLBase:        "https://lolcreds.haxx.it",
		EnableBuiltins: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected builtin info and high findings, got %d: %+v", len(findings), findings)
	}
	info := findings[0]
	if info.TemplateID != "filesystem" || info.CredentialID != "interesting-location" {
		t.Fatalf("expected builtin interesting-location finding, got %s:%s", info.TemplateID, info.CredentialID)
	}
	if info.Location != keyPath {
		t.Fatalf("unexpected info location %q", info.Location)
	}
	if info.Evidence != "path exists" {
		t.Fatalf("unexpected info evidence %q", info.Evidence)
	}
	finding := findings[1]
	if finding.TemplateID != "filesystem" || finding.CredentialID != "ssh-private-key" {
		t.Fatalf("expected builtin ssh finding, got %s:%s", finding.TemplateID, finding.CredentialID)
	}
	if finding.Origin != OriginBuiltin {
		t.Fatalf("expected builtin origin, got %q", finding.Origin)
	}
	if finding.Location != keyPath+":1" {
		t.Fatalf("unexpected location %q", finding.Location)
	}
	if finding.CredentialType != "private_key" {
		t.Fatalf("unexpected credential type %q", finding.CredentialType)
	}
	if finding.Evidence != "----****----" {
		t.Fatalf("unexpected evidence %q", finding.Evidence)
	}
}

func TestBuiltinSSHPrivateKeyGlobFindsCustomKeyNames(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}

	customKey := filepath.Join(sshDir, "acme-prod")
	writeTestFile(t, customKey, "-----BEGIN ENCRYPTED PRIVATE KEY-----\nredacted\n-----END ENCRYPTED PRIVATE KEY-----\n")
	writeTestFile(t, filepath.Join(sshDir, "acme-prod.pub"), "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakePublicKey\n")
	writeTestFile(t, filepath.Join(sshDir, "config"), "Host prod\n  IdentityFile ~/.ssh/acme-prod\n")
	writeTestFile(t, filepath.Join(sshDir, "known_hosts"), "github.com ssh-ed25519 AAAAC3NzaFakeHostKey\n")

	findings, err := Scan(context.Background(), nil, Options{
		MaxFileSize:    1024,
		EnableBuiltins: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	var customKeyFindings []Finding
	for _, finding := range findings {
		if finding.CredentialID == "ssh-private-key" {
			customKeyFindings = append(customKeyFindings, finding)
		}
		if strings.Contains(finding.Location, ".pub") || strings.HasSuffix(finding.Location, string(filepath.Separator)+"config") || strings.Contains(finding.Location, "known_hosts") {
			t.Fatalf("expected SSH metadata files to be skipped, got %+v", finding)
		}
	}
	if len(customKeyFindings) != 1 {
		t.Fatalf("expected one custom SSH private key finding, got %+v", findings)
	}
	if customKeyFindings[0].Location != customKey+":1" {
		t.Fatalf("unexpected custom key location %q", customKeyFindings[0].Location)
	}
}

func TestBuiltinCommonCredentialFiles(t *testing.T) {
	home := t.TempDir()
	root := t.TempDir()
	t.Setenv("HOME", home)

	writeTestFile(t, filepath.Join(home, ".netrc"), "machine example.com login alice password netrcsecret12345\n")
	writeTestFile(t, filepath.Join(home, ".kube", "config"), "users:\n- user:\n    token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signature\n")
	writeTestFile(t, filepath.Join(home, ".pgpass"), "localhost:5432:db:user:pgsecret12345\n")
	writeTestFile(t, filepath.Join(home, ".my.cnf"), "[client]\npassword=mysqlsecret12345\n")
	writeTestFile(t, filepath.Join(home, ".docker", "config.json"), `{"auths":{"registry.example.com":{"auth":"YWxpY2U6c2VjcmV0cGFzc3dvcmQ="}}}`)
	writeTestFile(t, filepath.Join(root, ".git", "config"), "[remote \"origin\"]\nurl = https://alice:ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890@github.com/acme/repo\n")
	writeTestFile(t, filepath.Join(root, ".env"), "SESSION_TOKEN=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signaturevalue123\n")
	writeTestFile(t, filepath.Join(root, "serviceAccountKey.json"), `{"private_key":"-----BEGIN PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----\n"}`)
	writeTestFile(t, filepath.Join(root, "server.key"), "-----BEGIN PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----\n")

	findings, err := Scan(context.Background(), nil, Options{
		Roots:          []string{root},
		MaxFileSize:    4096,
		EnableBuiltins: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	highIDs := highFindingIDs(findings)
	for _, want := range []string{
		"docker-auth-config",
		"generic-private-key",
		"git-credential-url",
		"jwt-token",
		"kubernetes-credential",
		"mysql-option-password",
		"netrc-credential",
		"postgres-pgpass",
		"service-account-private-key",
	} {
		if !highIDs[want] {
			t.Fatalf("expected builtin %q high finding, got ids %+v from findings %+v", want, highIDs, findings)
		}
	}
}

func TestBuiltinPEASSCredentialFiles(t *testing.T) {
	home := t.TempDir()
	root := t.TempDir()
	t.Setenv("HOME", home)

	writeTestFile(t, filepath.Join(home, ".bash_history"), "mysql -u root --password=hunter2\n")
	writeTestFile(t, filepath.Join(root, ".htpasswd"), "admin:$apr1$abcdefghijklmnopqrstuv\n")
	writeTestFile(t, filepath.Join(root, "rsyncd.secrets"), "backup:rsyncSecret123\n")
	writeTestFile(t, filepath.Join(root, "unattend.xml"), "<AdministratorPassword><Value>AdminPass123!</Value></AdministratorPassword>\n")
	writeTestFile(t, filepath.Join(root, "Groups.xml"), `<User name="localadmin" cpassword="AABBCCDDEEFF001122334455" />`)
	writeTestFile(t, filepath.Join(root, "RDCMan.settings"), "<logonCredentials><userName>alice</userName><password>rdpSecret123</password></logonCredentials>\n")

	findings, err := Scan(context.Background(), nil, Options{
		Roots:          []string{root},
		MaxFileSize:    4096,
		EnableBuiltins: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	highIDs := highFindingIDs(findings)
	for _, want := range []string{
		"htpasswd-entry",
		"rdcman-credential",
		"rsync-secret",
		"shell-history-credential",
		"windows-gpp-cpassword",
		"windows-unattended-password",
	} {
		if !highIDs[want] {
			t.Fatalf("expected builtin %q high finding, got ids %+v from findings %+v", want, highIDs, findings)
		}
	}
}

func TestTemplatesCrossCheckMarkedBuiltinFiles(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	historyPath := filepath.Join(home, ".bash_history")
	writeTestFile(t, historyPath, strings.Join([]string{
		"export OPENAI_API_KEY=sk-testvalue1234567890",
		"git clone https://x-access-token:ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890@github.com/acme/repo",
		"git clone https://x-access-token:ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890@github.com/acme/repo",
	}, "\n"))

	findings, err := Scan(context.Background(), []templates.Entry{
		{
			ID:   "github",
			Name: "GitHub",
			Credentials: []templates.Credential{
				{
					ID:   "classic-personal-access-token",
					Name: "Classic personal access token",
					Type: "token",
					LooksLike: []templates.LooksLike{
						{Pattern: `ghp_[A-Za-z0-9]{36,}`},
					},
				},
			},
		},
		{
			ID:   "openai",
			Name: "OpenAI",
			Credentials: []templates.Credential{
				{
					ID:   "api-key",
					Name: "API key",
					Type: "api_key",
					Location: []templates.Location{
						{Type: "environment", Path: "OPENAI_API_KEY"},
					},
				},
			},
		},
	}, Options{
		MaxFileSize:    4096,
		URLBase:        "https://lolcreds.haxx.it",
		EnableBuiltins: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	var githubFinding *Finding
	githubCount := 0
	var envReference *Finding
	for i := range findings {
		if findings[i].TemplateID == "github" && findings[i].CredentialID == "classic-personal-access-token" {
			githubFinding = &findings[i]
			githubCount++
		}
		if findings[i].TemplateID == "filesystem" && findings[i].CredentialID == "env-name-reference" && findings[i].Location == historyPath {
			envReference = &findings[i]
		}
	}
	if githubCount != 1 {
		t.Fatalf("expected duplicate GitHub token to be deduped to 1 finding, got %d from %+v", githubCount, findings)
	}
	if githubFinding == nil {
		t.Fatalf("expected GitHub template finding from builtin cross-check, got %+v", findings)
	}
	if githubFinding.Location != historyPath+":2" {
		t.Fatalf("unexpected GitHub finding location %q", githubFinding.Location)
	}
	if githubFinding.URL != "https://lolcreds.haxx.it/github#classic-personal-access-token" {
		t.Fatalf("unexpected GitHub finding URL %q", githubFinding.URL)
	}
	if envReference == nil {
		t.Fatalf("expected env-name reference from builtin cross-check, got %+v", findings)
	}
	if envReference.Evidence != "env var name referenced" {
		t.Fatalf("unexpected env reference evidence %q", envReference.Evidence)
	}
	if envReference.URL != "https://lolcreds.haxx.it/openai#api-key" {
		t.Fatalf("unexpected env reference URL %q", envReference.URL)
	}
}

func TestPowerShellHistoryBuiltinFindings(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	historyPath := filepath.Join(root, "ConsoleHost_history.txt")
	writeTestFile(t, historyPath, strings.Join([]string{
		`Invoke-RestMethod -Uri https://api.example.test -ApiKey "ps-history-key-123456"`,
		`$env:EXAMPLE_API_TOKEN = "ex_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"`,
		`ConvertTo-SecureString "P@ssw0rd!12345" -AsPlainText -Force`,
		`Invoke-RestMethod -Headers @{ Authorization = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.signature" }`,
	}, "\n"))

	findings, err := Scan(context.Background(), nil, Options{
		Roots:          []string{root},
		MaxFileSize:    4096,
		EnableBuiltins: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	count := countFinding(findings, "filesystem", "shell-history-credential")
	if count < 4 {
		t.Fatalf("expected PowerShell history builtins to find at least 4 secrets, got %d from %+v", count, findings)
	}
	for _, finding := range findings {
		if finding.TemplateID == "filesystem" && finding.CredentialID == "shell-history-credential" && !strings.HasPrefix(finding.Location, historyPath+":") {
			t.Fatalf("expected PowerShell history location, got %+v", finding)
		}
	}
}

func TestPowerShellHistoryTemplateCrossCheck(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	historyPath := filepath.Join(root, "ConsoleHost_history.txt")
	writeTestFile(t, historyPath, strings.Join([]string{
		`$env:OPENAI_API_KEY = "sk-testvalue1234567890abcdefghijklmnopqrstuvwxyz"`,
		`gh auth login --with-token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890`,
	}, "\n"))

	findings, err := Scan(context.Background(), []templates.Entry{
		{
			ID:   "github",
			Name: "GitHub",
			Credentials: []templates.Credential{
				{
					ID:   "classic-personal-access-token",
					Name: "Classic personal access token",
					Type: "token",
					LooksLike: []templates.LooksLike{
						{Pattern: `ghp_[A-Za-z0-9]{36,}`},
					},
				},
			},
		},
		{
			ID:   "openai",
			Name: "OpenAI",
			Credentials: []templates.Credential{
				{
					ID:   "api-key",
					Name: "API key",
					Type: "api_key",
					Location: []templates.Location{
						{Type: "environment", Path: "OPENAI_API_KEY"},
					},
				},
			},
		},
	}, Options{
		Roots:          []string{root},
		MaxFileSize:    4096,
		URLBase:        "https://lolcreds.haxx.it",
		EnableBuiltins: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	github := findingByID(findings, "github", "classic-personal-access-token")
	if github == nil {
		t.Fatalf("expected GitHub token finding from PowerShell history cross-check, got %+v", findings)
	}
	if github.Location != historyPath+":2" {
		t.Fatalf("unexpected GitHub finding location %q", github.Location)
	}

	envReference := findingByID(findings, "filesystem", "env-name-reference")
	if envReference == nil {
		t.Fatalf("expected env-name reference from PowerShell history, got %+v", findings)
	}
	if envReference.Location != historyPath {
		t.Fatalf("unexpected env reference location %q", envReference.Location)
	}
	if envReference.URL != "https://lolcreds.haxx.it/openai#api-key" {
		t.Fatalf("unexpected env reference URL %q", envReference.URL)
	}
}

func TestBuiltinJWTScansTemplateDiscoveredCredentialFiles(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	authPath := filepath.Join(home, ".hermes", "auth.json")
	writeTestFile(t, authPath, `{
  "version": 1,
  "providers": {
    "openai-codex": {
      "tokens": {
        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikhlcm1lcyJ9.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30"
      }
    }
  }
}`)

	findings, err := Scan(context.Background(), []templates.Entry{
		{
			ID:   "hermes-agent",
			Name: "Hermes Agent",
			Credentials: []templates.Credential{
				{
					ID:   "oauth-credential-pool",
					Name: "OAuth Credential Pool Token",
					Type: "token",
					Location: []templates.Location{
						{Type: "config_file", Path: "~/.hermes/auth.json"},
					},
				},
			},
		},
	}, Options{
		MaxFileSize:    4096,
		URLBase:        "https://lolcreds.haxx.it",
		EnableBuiltins: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	jwtFinding := findingByID(findings, "filesystem", "jwt-token")
	if jwtFinding == nil {
		t.Fatalf("expected builtin JWT finding in template-discovered Hermes auth file, got %+v", findings)
	}
	if !strings.HasPrefix(jwtFinding.Location, authPath+":") {
		t.Fatalf("unexpected JWT finding location %q", jwtFinding.Location)
	}
	if jwtFinding.Origin != OriginBuiltin {
		t.Fatalf("expected builtin origin, got %q", jwtFinding.Origin)
	}
	if jwtFinding.CredentialType != "token" {
		t.Fatalf("expected token type, got %q", jwtFinding.CredentialType)
	}
	infoFinding := findingByID(findings, "filesystem", "interesting-location")
	if infoFinding == nil {
		t.Fatalf("expected template path observation to remain, got %+v", findings)
	}
	if infoFinding.URL != "https://lolcreds.haxx.it/hermes-agent#oauth-credential-pool" {
		t.Fatalf("expected Hermes path observation URL, got %q", infoFinding.URL)
	}
}

func TestTemplatesCrossCheckSkipsBroadPatterns(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	historyPath := filepath.Join(home, ".zsh_history")
	writeTestFile(t, historyPath, strings.Join([]string{
		"TOKEN=dckr_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
		"--token=dckr_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
		"curl http://localhost:3000/api",
	}, "\n"))

	findings, err := Scan(context.Background(), []templates.Entry{
		{
			ID:   "broad-token-product",
			Name: "Broad Token Product",
			Credentials: []templates.Credential{
				{
					ID:   "opaque-token",
					Name: "Opaque token",
					Type: "token",
					LooksLike: []templates.LooksLike{
						{Pattern: `[A-Za-z0-9+/]{20,}={0,2}`},
						{Pattern: `Authorization:\s*Bearer\s+[^\s]+`},
						{Pattern: `(password|passphrase|token|accessKey|secretKey)`},
					},
				},
			},
		},
		{
			ID:   "broad-login-product",
			Name: "Broad Login Product",
			Credentials: []templates.Credential{
				{
					ID:   "local-user-admin-password",
					Name: "Local user admin password",
					Type: "username_password",
					LooksLike: []templates.LooksLike{
						{Pattern: `[^\s:@]+:[^\s:]+`},
					},
				},
			},
		},
	}, Options{
		MaxFileSize:    4096,
		URLBase:        "https://lolcreds.haxx.it",
		EnableBuiltins: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	if countFinding(findings, "broad-token-product", "opaque-token") != 0 {
		t.Fatalf("expected broad token template to be skipped during builtin cross-check, got %+v", findings)
	}
	if countFinding(findings, "broad-login-product", "local-user-admin-password") != 0 {
		t.Fatalf("expected username/password template to be skipped during builtin cross-check, got %+v", findings)
	}
	if countFinding(findings, "filesystem", "shell-history-credential") != 1 {
		t.Fatalf("expected repeated shell history secret to be deduped to 1 finding, got %+v", findings)
	}
}

func TestDedupeHighFindingsBySecretPrefersTemplateFinding(t *testing.T) {
	findings := dedupeHighFindingsBySecret([]Finding{
		{
			TemplateID:     "filesystem",
			CredentialID:   "shell-history-credential",
			Source:         "file",
			Confidence:     "high",
			CredentialType: "secret_value",
			Evidence:       "TOKEN=ghp_****7890",
		},
		{
			TemplateID:     "github",
			CredentialID:   "classic-personal-access-token",
			Source:         "file",
			Confidence:     "high",
			CredentialType: "token",
			Evidence:       "ghp_****7890",
			URL:            "https://lolcreds.haxx.it/github#classic-personal-access-token",
		},
	})

	if len(findings) != 1 {
		t.Fatalf("expected 1 deduped finding, got %+v", findings)
	}
	if findings[0].TemplateID != "github" {
		t.Fatalf("expected template finding to win over filesystem finding, got %+v", findings[0])
	}
}

func TestEmbeddedBuiltinChecksLoad(t *testing.T) {
	checks, err := loadBuiltinFileChecks(builtinChecksYAML)
	if err != nil {
		t.Fatal(err)
	}
	ids := make(map[string]bool)
	for _, check := range checks {
		ids[check.ID] = true
		if check.Name == "" {
			t.Fatalf("builtin check %q has empty name", check.ID)
		}
		if check.CredentialType == "" {
			t.Fatalf("builtin check %q has empty type", check.ID)
		}
		if len(check.Paths) == 0 {
			t.Fatalf("builtin check %q has no paths", check.ID)
		}
		if len(check.Patterns) == 0 {
			t.Fatalf("builtin check %q has no patterns", check.ID)
		}
	}
	for _, want := range []string{
		"docker-auth-config",
		"generic-private-key",
		"git-credential-url",
		"htpasswd-entry",
		"jwt-token",
		"kubernetes-credential",
		"mysql-option-password",
		"netrc-credential",
		"postgres-pgpass",
		"rdcman-credential",
		"rsync-secret",
		"service-account-private-key",
		"shell-history-credential",
		"ssh-private-key",
		"windows-gpp-cpassword",
		"windows-unattended-password",
	} {
		if !ids[want] {
			t.Fatalf("expected embedded builtin check %q, got ids %+v", want, ids)
		}
	}
	if !builtinCheckByID(checks, "shell-history-credential").TemplateCrossCheck {
		t.Fatalf("expected shell history builtin to enable template cross-checking")
	}
	shellHistoryCheck := builtinCheckByID(checks, "shell-history-credential")
	if !containsString(shellHistoryCheck.Paths, `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`) {
		t.Fatalf("expected shell history builtin to include PSReadLine APPDATA path, got %+v", shellHistoryCheck.Paths)
	}
	if !containsString(shellHistoryCheck.Paths, `%APPDATA%\Microsoft\PowerShell\PSReadLine\ConsoleHost_history.txt`) {
		t.Fatalf("expected shell history builtin to include PowerShell 7 APPDATA path, got %+v", shellHistoryCheck.Paths)
	}
	if !builtinCheckByID(checks, "jwt-token").TemplateLocationCrossCheck {
		t.Fatalf("expected JWT builtin to scan template-discovered credential files")
	}
	if !builtinCheckByID(checks, "git-credential-url").TemplateCrossCheck {
		t.Fatalf("expected git credential builtin to enable template cross-checking")
	}
	sshCheck := builtinCheckByID(checks, "ssh-private-key")
	if !sameStrings(sshCheck.GlobPaths, []string{"~/.ssh/*"}) {
		t.Fatalf("expected SSH private key builtin glob path, got %+v", sshCheck.GlobPaths)
	}
	if len(sshCheck.ExcludeNames) == 0 {
		t.Fatalf("expected SSH private key builtin exclude names")
	}
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func highFindingIDs(findings []Finding) map[string]bool {
	ids := make(map[string]bool)
	for _, finding := range findings {
		if finding.TemplateID == "filesystem" && finding.Confidence == "high" {
			ids[finding.CredentialID] = true
		}
	}
	return ids
}

func countFinding(findings []Finding, templateID, credentialID string) int {
	count := 0
	for _, finding := range findings {
		if finding.TemplateID == templateID && finding.CredentialID == credentialID {
			count++
		}
	}
	return count
}

func findingByID(findings []Finding, templateID, credentialID string) *Finding {
	for i := range findings {
		if findings[i].TemplateID == templateID && findings[i].CredentialID == credentialID {
			return &findings[i]
		}
	}
	return nil
}

func builtinCheckByID(checks []builtinFileCheck, id string) builtinFileCheck {
	for _, check := range checks {
		if check.ID == id {
			return check
		}
	}
	return builtinFileCheck{}
}

func findByConfidence(findings []Finding, confidence string) *Finding {
	for i := range findings {
		if findings[i].Confidence == confidence {
			return &findings[i]
		}
	}
	return nil
}

func sameStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestScanWithStats(t *testing.T) {
	result, err := ScanWithStats(context.Background(), []templates.Entry{
		{
			ID:   "example-product",
			Name: "Example Product",
			Credentials: []templates.Credential{
				{
					ID:   "token",
					Name: "Token",
					Type: "api_token",
					LooksLike: []templates.LooksLike{
						{Pattern: `[A-Z]{6,1024}`},
						{Pattern: `[`},
					},
				},
			},
		},
	}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Stats.Templates != 1 || result.Stats.Credentials != 1 {
		t.Fatalf("unexpected stats: %+v", result.Stats)
	}
	if result.Stats.Patterns != 1 || result.Stats.SkippedPatterns != 1 {
		t.Fatalf("unexpected pattern stats: %+v", result.Stats)
	}
}

func TestExpandWindowsEnv(t *testing.T) {
	t.Setenv("APPDATA", `C:\Users\alice\AppData\Roaming`)

	got := expandWindowsEnv(`%APPDATA%\Example\config.yml`)
	want := `C:\Users\alice\AppData\Roaming\Example\config.yml`
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestNormalizeLargeRepeatCounts(t *testing.T) {
	got := normalizeLargeRepeatCounts(`[A-Za-z0-9._~+/=-]{6,1024}`)
	want := `[A-Za-z0-9._~+/=-]{6,}`
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}
