package templates

import (
	"archive/zip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

func Load(path string) ([]Entry, error) {
	if strings.HasSuffix(strings.ToLower(path), ".zip") {
		return loadZip(path)
	}

	entriesDir := path
	if st, err := os.Stat(filepath.Join(path, "entries")); err == nil && st.IsDir() {
		entriesDir = filepath.Join(path, "entries")
	}

	var files []string
	if err := filepath.WalkDir(entriesDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		name := strings.ToLower(d.Name())
		if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			files = append(files, path)
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("load templates: %w", err)
	}
	sort.Strings(files)

	entries := make([]Entry, 0, len(files))
	for _, file := range files {
		entry, err := loadFile(file)
		if err != nil {
			return nil, err
		}
		normalizeEntry(&entry)
		if entry.ID != "" {
			entries = append(entries, entry)
		}
	}

	return entries, nil
}

func loadZip(path string) ([]Entry, error) {
	reader, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("open template zip: %w", err)
	}
	defer reader.Close()

	files := make([]*zip.File, 0)
	for _, file := range reader.File {
		if file.FileInfo().IsDir() {
			continue
		}
		name := strings.ToLower(filepath.ToSlash(file.Name))
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		if !strings.Contains(name, "/entries/") && !strings.HasPrefix(name, "entries/") {
			continue
		}
		files = append(files, file)
	}
	sort.Slice(files, func(i, j int) bool {
		return files[i].Name < files[j].Name
	})

	entries := make([]Entry, 0, len(files))
	for _, file := range files {
		entry, err := loadZipFile(file)
		if err != nil {
			return nil, err
		}
		normalizeEntry(&entry)
		if entry.ID != "" {
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

func loadFile(path string) (Entry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Entry{}, fmt.Errorf("read %s: %w", path, err)
	}

	var entry Entry
	if err := yaml.Unmarshal(b, &entry); err != nil {
		return Entry{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return entry, nil
}

func loadZipFile(file *zip.File) (Entry, error) {
	rc, err := file.Open()
	if err != nil {
		return Entry{}, fmt.Errorf("open %s: %w", file.Name, err)
	}
	defer rc.Close()

	b, err := io.ReadAll(io.LimitReader(rc, 10*1024*1024+1))
	if err != nil {
		return Entry{}, fmt.Errorf("read %s: %w", file.Name, err)
	}
	if len(b) > 10*1024*1024 {
		return Entry{}, fmt.Errorf("read %s: template file exceeds 10485760 bytes", file.Name)
	}

	var entry Entry
	if err := yaml.Unmarshal(b, &entry); err != nil {
		return Entry{}, fmt.Errorf("parse %s: %w", file.Name, err)
	}
	return entry, nil
}

func normalizeEntry(entry *Entry) {
	if entry.ID == "" {
		entry.ID = slug(entry.Name)
	}
	for i := range entry.Credentials {
		if entry.Credentials[i].ID == "" {
			entry.Credentials[i].ID = slug(entry.Credentials[i].Name)
		}
	}
}

func slug(s string) string {
	var b strings.Builder
	lastDash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
			lastDash = false
		case r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash && b.Len() > 0 {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}
