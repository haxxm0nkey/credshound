package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/haxxm0nkey/credshound/internal/scanner"
)

func TestWriteTextNoColor(t *testing.T) {
	var out bytes.Buffer
	err := WriteText(&out, []scanner.Finding{
		{
			TemplateID:     "example-product",
			CredentialID:   "api-token-env",
			Source:         "env",
			Confidence:     "high",
			Location:       "EXAMPLE_API_TOKEN",
			CredentialType: "api_token",
			Evidence:       "ex_A****7890",
			URL:            "https://lolcreds.haxx.it/example-product#api-token-env",
		},
	}, TextOptions{})
	if err != nil {
		t.Fatal(err)
	}

	got := out.String()
	if strings.Contains(got, "\x1b[") {
		t.Fatalf("expected plain output, got %q", got)
	}
	if !strings.Contains(got, "[example-product:api-token-env] [env] [high]") {
		t.Fatalf("unexpected output %q", got)
	}
	want := "[example-product:api-token-env] [env] [high] [EXAMPLE_API_TOKEN] [api_token] [ex_A****7890] [https://lolcreds.haxx.it/example-product#api-token-env]\n"
	if got != want {
		t.Fatalf("unexpected plain output\nwant %q\n got %q", want, got)
	}
}

func TestWriteTextColor(t *testing.T) {
	var out bytes.Buffer
	err := WriteText(&out, []scanner.Finding{
		{
			TemplateID:     "example-product",
			CredentialID:   "api-token-env",
			Source:         "env",
			Confidence:     "high",
			Location:       "EXAMPLE_API_TOKEN",
			CredentialType: "api_token",
			Evidence:       "ex_A****7890",
			URL:            "https://lolcreds.haxx.it/example-product#api-token-env",
		},
	}, TextOptions{Color: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "\x1b[") {
		t.Fatalf("expected ANSI color output, got %q", out.String())
	}
	if !strings.Contains(out.String(), whiteBold+"[ex_A****7890]"+reset) {
		t.Fatalf("expected evidence to use neutral emphasis, got %q", out.String())
	}
	if !strings.Contains(out.String(), pathColor+"[EXAMPLE_API_TOKEN]"+reset) {
		t.Fatalf("expected location to use distinct high-contrast bracket color, got %q", out.String())
	}
	if !strings.Contains(out.String(), linkBlue+"[https://lolcreds.haxx.it/example-product#api-token-env]"+reset) {
		t.Fatalf("expected URL to use high-contrast link color, got %q", out.String())
	}
}

func TestWriteTextReferences(t *testing.T) {
	var out bytes.Buffer
	err := WriteText(&out, []scanner.Finding{
		{
			TemplateID:     "filesystem",
			CredentialID:   "interesting-location",
			Source:         "file",
			Confidence:     "info",
			Location:       "/tmp/.env",
			CredentialType: "config_file",
			Evidence:       "path exists",
			References:     []string{"github", "atlassian-bitbucket"},
		},
	}, TextOptions{})
	if err != nil {
		t.Fatal(err)
	}
	want := "[filesystem:interesting-location] [file] [info] [/tmp/.env] [config_file] [path exists] [referenced by 2 templates]\n"
	if out.String() != want {
		t.Fatalf("unexpected output\nwant %q\n got %q", want, out.String())
	}
}

func TestWriteTextProcEnvironmentReferences(t *testing.T) {
	var out bytes.Buffer
	err := WriteText(&out, []scanner.Finding{
		{
			TemplateID:     "process",
			CredentialID:   "environment-variable",
			Source:         "proc",
			Confidence:     "medium",
			Location:       "pid=1460 comm=python env=DB_PASSWORD",
			CredentialType: "password",
			Evidence:       "chan****word",
			References:     []string{"microsoft-sql-server", "wikijs"},
		},
	}, TextOptions{})
	if err != nil {
		t.Fatal(err)
	}
	want := "[process:environment-variable] [proc] [medium] [pid=1460 comm=python env=DB_PASSWORD] [password] [chan****word] [referenced by 2 templates]\n"
	if out.String() != want {
		t.Fatalf("unexpected output\nwant %q\n got %q", want, out.String())
	}
}

func TestWriteTextOmitsEmptyTail(t *testing.T) {
	var out bytes.Buffer
	err := WriteText(&out, []scanner.Finding{
		{
			TemplateID:     "filesystem",
			CredentialID:   "ssh-private-key",
			Source:         "file",
			Confidence:     "high",
			Location:       "/tmp/id_rsa:1",
			CredentialType: "private_key",
			Evidence:       "----****----",
		},
	}, TextOptions{})
	if err != nil {
		t.Fatal(err)
	}
	want := "[filesystem:ssh-private-key] [file] [high] [/tmp/id_rsa:1] [private_key] [----****----]\n"
	if out.String() != want {
		t.Fatalf("unexpected output\nwant %q\n got %q", want, out.String())
	}
}

func TestWriteTextSingleReferenceUsesURL(t *testing.T) {
	var out bytes.Buffer
	err := WriteText(&out, []scanner.Finding{
		{
			TemplateID:     "filesystem",
			CredentialID:   "interesting-location",
			Source:         "file",
			Confidence:     "info",
			Location:       "/tmp/.env",
			CredentialType: "config_file",
			Evidence:       "path exists",
			URL:            "https://lolcreds.haxx.it/pagerduty#rest-api-key",
			References:     []string{"pagerduty"},
		},
	}, TextOptions{})
	if err != nil {
		t.Fatal(err)
	}
	want := "[filesystem:interesting-location] [file] [info] [/tmp/.env] [config_file] [path exists] [https://lolcreds.haxx.it/pagerduty#rest-api-key]\n"
	if out.String() != want {
		t.Fatalf("unexpected output\nwant %q\n got %q", want, out.String())
	}
}

func TestWriteTextCapsReferences(t *testing.T) {
	var out bytes.Buffer
	err := WriteText(&out, []scanner.Finding{
		{
			TemplateID:     "filesystem",
			CredentialID:   "interesting-location",
			Source:         "file",
			Confidence:     "info",
			Location:       "/tmp/.env",
			CredentialType: "config_file",
			Evidence:       "path exists",
			References:     []string{"a", "b", "c", "d", "e", "f", "g"},
		},
	}, TextOptions{})
	if err != nil {
		t.Fatal(err)
	}
	want := "[filesystem:interesting-location] [file] [info] [/tmp/.env] [config_file] [path exists] [referenced by 7 templates]\n"
	if out.String() != want {
		t.Fatalf("unexpected output\nwant %q\n got %q", want, out.String())
	}
}
