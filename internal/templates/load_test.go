package templates

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadZipTemplates(t *testing.T) {
	root := t.TempDir()
	zipPath := filepath.Join(root, "lolcreds-data-main.zip")
	writeTemplateZip(t, zipPath, map[string]string{
		"lolcreds-data-main/entries/example.yaml": "id: example\nname: Example\ncredentials:\n  - name: API Token\n    type: api_token\n",
	})

	entries, err := Load(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].ID != "example" {
		t.Fatalf("expected example ID, got %q", entries[0].ID)
	}
	if entries[0].Credentials[0].ID != "api-token" {
		t.Fatalf("expected generated credential ID, got %q", entries[0].Credentials[0].ID)
	}
}

func writeTemplateZip(t *testing.T, path string, files map[string]string) {
	t.Helper()

	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	writer := zip.NewWriter(file)
	defer writer.Close()

	for name, content := range files {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
}
