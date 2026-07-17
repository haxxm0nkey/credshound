package updater

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const DefaultSourceURL = "https://github.com/haxxm0nkey/lolcreds-data/archive/refs/heads/main.zip"

type DownloadError struct {
	Source string
	Err    error
}

func (e DownloadError) Error() string {
	return fmt.Sprintf("could not download templates from %s: %v", e.Source, e.Err)
}

func (e DownloadError) Unwrap() error {
	return e.Err
}

type Options struct {
	SourceURL       string
	InstallDir      string
	TempDir         string
	MaxArchiveBytes int64
	MaxFileBytes    int64
	MaxFiles        int
}

type Result struct {
	SourceURL  string    `json:"source"`
	InstallDir string    `json:"install_dir"`
	UpdatedAt  time.Time `json:"updated_at"`
	Files      int       `json:"files"`
	Bytes      int64     `json:"bytes"`
}

func DefaultInstallDir() (string, error) {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		home, homeErr := os.UserHomeDir()
		if homeErr != nil {
			return "", err
		}
		cacheDir = filepath.Join(home, ".cache")
	}
	return filepath.Join(cacheDir, "credshound", "templates"), nil
}

func HasTemplates(path string) bool {
	if path == "" {
		return false
	}
	st, err := os.Stat(filepath.Join(path, "entries"))
	return err == nil && st.IsDir()
}

func ReadMetadata(installDir string) (Result, error) {
	b, err := os.ReadFile(filepath.Join(installDir, "credshound-update.json"))
	if err != nil {
		return Result{}, err
	}
	var result Result
	if err := json.Unmarshal(b, &result); err != nil {
		return Result{}, err
	}
	return result, nil
}

func Update(ctx context.Context, opts Options) (Result, error) {
	opts = withDefaults(opts)

	if opts.SourceURL == "" {
		return Result{}, errors.New("empty source URL")
	}
	if opts.InstallDir == "" {
		return Result{}, errors.New("empty install directory")
	}

	if err := os.MkdirAll(filepath.Dir(opts.InstallDir), 0o755); err != nil {
		return Result{}, err
	}

	archivePath, bytesWritten, err := download(ctx, opts)
	if err != nil {
		return Result{}, DownloadError{Source: opts.SourceURL, Err: err}
	}
	defer os.Remove(archivePath)

	staging, err := os.MkdirTemp(opts.TempDir, "credshound-templates-extract-*")
	if err != nil {
		return Result{}, err
	}
	defer os.RemoveAll(staging)

	files, err := extractZip(archivePath, staging, opts)
	if err != nil {
		return Result{}, err
	}
	if !HasTemplates(staging) {
		return Result{}, errors.New("downloaded archive does not contain an entries directory")
	}

	if err := install(staging, opts.InstallDir); err != nil {
		return Result{}, err
	}

	result := Result{
		SourceURL:  opts.SourceURL,
		InstallDir: opts.InstallDir,
		UpdatedAt:  time.Now().UTC(),
		Files:      files,
		Bytes:      bytesWritten,
	}
	if err := writeMetadata(result); err != nil {
		return Result{}, err
	}
	return result, nil
}

func withDefaults(opts Options) Options {
	if opts.SourceURL == "" {
		opts.SourceURL = DefaultSourceURL
	}
	if opts.InstallDir == "" {
		if installDir, err := DefaultInstallDir(); err == nil {
			opts.InstallDir = installDir
		}
	}
	if opts.MaxArchiveBytes == 0 {
		opts.MaxArchiveBytes = 50 * 1024 * 1024
	}
	if opts.MaxFileBytes == 0 {
		opts.MaxFileBytes = 10 * 1024 * 1024
	}
	if opts.MaxFiles == 0 {
		opts.MaxFiles = 10000
	}
	return opts
}

func download(ctx context.Context, opts Options) (string, int64, error) {
	if isLocalArchiveSource(opts.SourceURL) {
		return copyLocalArchive(opts)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, opts.SourceURL, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", "credshound/"+time.Now().Format("20060102"))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", 0, fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}

	file, err := os.CreateTemp(opts.TempDir, "credshound-templates-*.zip")
	if err != nil {
		return "", 0, err
	}
	defer file.Close()

	written, err := io.Copy(file, io.LimitReader(resp.Body, opts.MaxArchiveBytes+1))
	if err != nil {
		os.Remove(file.Name())
		return "", 0, err
	}
	if written > opts.MaxArchiveBytes {
		os.Remove(file.Name())
		return "", 0, fmt.Errorf("archive exceeds maximum size of %d bytes", opts.MaxArchiveBytes)
	}
	return file.Name(), written, nil
}

func copyLocalArchive(opts Options) (string, int64, error) {
	srcPath, err := localArchivePath(opts.SourceURL)
	if err != nil {
		return "", 0, err
	}

	src, err := os.Open(srcPath)
	if err != nil {
		return "", 0, err
	}
	defer src.Close()

	file, err := os.CreateTemp(opts.TempDir, "credshound-templates-*.zip")
	if err != nil {
		return "", 0, err
	}
	defer file.Close()

	written, err := io.Copy(file, io.LimitReader(src, opts.MaxArchiveBytes+1))
	if err != nil {
		os.Remove(file.Name())
		return "", 0, err
	}
	if written > opts.MaxArchiveBytes {
		os.Remove(file.Name())
		return "", 0, fmt.Errorf("archive exceeds maximum size of %d bytes", opts.MaxArchiveBytes)
	}
	return file.Name(), written, nil
}

func isLocalArchiveSource(source string) bool {
	if strings.HasPrefix(source, "file://") {
		return true
	}
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		return false
	}
	return true
}

func localArchivePath(source string) (string, error) {
	if strings.HasPrefix(source, "file://") {
		parsed, err := url.Parse(source)
		if err != nil {
			return "", err
		}
		if parsed.Path == "" {
			return "", errors.New("empty file URL path")
		}
		return parsed.Path, nil
	}
	return expandLocalPath(source), nil
}

func expandLocalPath(path string) string {
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

func extractZip(archivePath, dest string, opts Options) (int, error) {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return 0, err
	}
	defer reader.Close()

	files := 0
	for _, file := range reader.File {
		if file.FileInfo().IsDir() {
			continue
		}
		files++
		if files > opts.MaxFiles {
			return files, fmt.Errorf("archive exceeds maximum file count of %d", opts.MaxFiles)
		}
		if file.UncompressedSize64 > uint64(opts.MaxFileBytes) {
			return files, fmt.Errorf("archive file %q exceeds maximum size of %d bytes", file.Name, opts.MaxFileBytes)
		}

		rel, ok := safeArchivePath(file.Name)
		if !ok {
			return files, fmt.Errorf("unsafe archive path %q", file.Name)
		}
		if rel == "" {
			continue
		}

		target := filepath.Join(dest, rel)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return files, err
		}
		if err := extractOne(file, target, opts.MaxFileBytes); err != nil {
			return files, err
		}
	}
	return files, nil
}

func safeArchivePath(name string) (string, bool) {
	name = strings.ReplaceAll(name, "\\", "/")
	if strings.HasPrefix(name, "/") {
		return "", false
	}
	clean := filepath.ToSlash(filepath.Clean(name))
	if clean == "." || clean == "" {
		return "", true
	}
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", false
	}

	parts := strings.SplitN(clean, "/", 2)
	if len(parts) == 1 {
		return "", true
	}
	rel := parts[1]
	if rel == "" || rel == "." {
		return "", true
	}
	if rel == ".." || strings.HasPrefix(rel, "../") {
		return "", false
	}
	return rel, true
}

func extractOne(file *zip.File, target string, maxBytes int64) error {
	src, err := file.Open()
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer dst.Close()

	written, err := io.Copy(dst, io.LimitReader(src, maxBytes+1))
	if err != nil {
		return err
	}
	if written > maxBytes {
		return fmt.Errorf("archive file %q exceeds maximum size of %d bytes", file.Name, maxBytes)
	}
	return nil
}

func install(staging, installDir string) error {
	parent := filepath.Dir(installDir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	next, err := os.MkdirTemp(parent, filepath.Base(installDir)+".next-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(next)

	if err := copyDir(staging, next); err != nil {
		return err
	}

	backup := installDir + ".old"
	_ = os.RemoveAll(backup)
	if _, err := os.Stat(installDir); err == nil {
		if err := os.Rename(installDir, backup); err != nil {
			return err
		}
	}
	if err := os.Rename(next, installDir); err != nil {
		if _, statErr := os.Stat(backup); statErr == nil {
			_ = os.Rename(backup, installDir)
		}
		return err
	}
	_ = os.RemoveAll(backup)
	return nil
}

func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return err
		}
		defer out.Close()
		_, err = io.Copy(out, in)
		return err
	})
}

func writeMetadata(result Result) error {
	b, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(result.InstallDir, "credshound-update.json"), append(b, '\n'), 0o644)
}
