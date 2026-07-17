package updater

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestUpdateDownloadsExtractsAndInstallsTemplates(t *testing.T) {
	archive := testArchive(t, map[string]string{
		"lolcreds-data-main/entries/example.yaml": "id: example\nname: Example\n",
		"lolcreds-data-main/README.md":            "# example\n",
	})
	root := t.TempDir()
	source := writeArchive(t, root, archive)

	result, err := Update(context.Background(), Options{
		SourceURL:  "file://" + source,
		InstallDir: filepath.Join(root, "templates"),
		TempDir:    root,
	})
	if err != nil {
		t.Fatal(err)
	}

	if result.Files != 2 {
		t.Fatalf("expected 2 extracted files, got %d", result.Files)
	}
	if !HasTemplates(result.InstallDir) {
		t.Fatalf("expected installed templates at %s", result.InstallDir)
	}
	if _, err := os.Stat(filepath.Join(result.InstallDir, "entries", "example.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(result.InstallDir, "credshound-update.json")); err != nil {
		t.Fatal(err)
	}
	metadata, err := ReadMetadata(result.InstallDir)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.SourceURL != "file://"+source {
		t.Fatalf("expected metadata source %q, got %q", "file://"+source, metadata.SourceURL)
	}
	if metadata.Files != 2 {
		t.Fatalf("expected metadata file count 2, got %d", metadata.Files)
	}
}

func TestUpdateAcceptsPlainLocalZipPath(t *testing.T) {
	archive := testArchive(t, map[string]string{
		"lolcreds-data-main/entries/example.yaml": "id: example\nname: Example\n",
	})
	root := t.TempDir()
	source := writeArchive(t, root, archive)

	result, err := Update(context.Background(), Options{
		SourceURL:  source,
		InstallDir: filepath.Join(root, "templates"),
		TempDir:    root,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !HasTemplates(result.InstallDir) {
		t.Fatalf("expected installed templates at %s", result.InstallDir)
	}
}

func TestUpdateRejectsZipSlip(t *testing.T) {
	archive := testArchive(t, map[string]string{
		"lolcreds-data-main/../../evil": "nope",
	})
	root := t.TempDir()
	source := writeArchive(t, root, archive)

	_, err := Update(context.Background(), Options{
		SourceURL:  "file://" + source,
		InstallDir: filepath.Join(root, "templates"),
		TempDir:    root,
	})
	if err == nil {
		t.Fatal("expected zip-slip archive to be rejected")
	}
}

func TestLocalArchivePathExpandsHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip(err)
	}
	got, err := localArchivePath("~/Downloads/lolcreds-data-main.zip")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(home, "Downloads", "lolcreds-data-main.zip")
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func writeArchive(t *testing.T, root string, archive []byte) string {
	t.Helper()

	path := filepath.Join(root, "templates.zip")
	if err := os.WriteFile(path, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func testArchive(t *testing.T, files map[string]string) []byte {
	t.Helper()

	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for name, content := range files {
		file, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
