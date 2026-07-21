package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

const defaultProcRoot = "/proc"

func scanProcEnviron(ctx context.Context, compiled []compiledCredential, opts Options) ([]Finding, error) {
	procRoot := strings.TrimSpace(opts.ProcRoot)
	if procRoot == "" {
		if runtime.GOOS != "linux" {
			return nil, nil
		}
		procRoot = defaultProcRoot
	}

	processes, err := procProcesses(procRoot)
	if err != nil {
		if isSkippableProcError(err) {
			return nil, nil
		}
		return nil, err
	}

	envCredentials := procEnvironmentCredentials(compiled)
	if len(envCredentials) == 0 {
		return nil, nil
	}

	var findings []Finding
	for _, process := range processes {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		values, err := readProcEnvironment(process.EnvironPath, opts)
		if err != nil {
			if isSkippableProcError(err) {
				continue
			}
			return findings, err
		}
		if len(values) == 0 {
			continue
		}

		for _, envCredential := range envCredentials {
			value, ok := values[envCredential.Name]
			if !ok || strings.TrimSpace(value) == "" {
				continue
			}
			location := procEnvironmentLocation(process, envCredential.Name)
			findings = append(findings, environmentValueFinding(envCredential.Item, "proc", location, value, opts))
		}
	}
	return findings, nil
}

type procProcess struct {
	PID         int
	Name        string
	EnvironPath string
}

type procEnvCredential struct {
	Name string
	Item compiledCredential
}

func procProcesses(procRoot string) ([]procProcess, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, err
	}

	processes := make([]procProcess, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, ok := parseProcPID(entry.Name())
		if !ok {
			continue
		}
		processDir := filepath.Join(procRoot, entry.Name())
		processes = append(processes, procProcess{
			PID:         pid,
			Name:        readProcComm(filepath.Join(processDir, "comm")),
			EnvironPath: filepath.Join(processDir, "environ"),
		})
	}
	sort.Slice(processes, func(i, j int) bool {
		return processes[i].PID < processes[j].PID
	})
	return processes, nil
}

func parseProcPID(name string) (int, bool) {
	if name == "" {
		return 0, false
	}
	for _, r := range name {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	pid, err := strconv.Atoi(name)
	if err != nil || pid <= 0 {
		return 0, false
	}
	return pid, true
}

func readProcComm(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func procEnvironmentCredentials(compiled []compiledCredential) []procEnvCredential {
	var out []procEnvCredential
	for _, item := range compiled {
		for _, name := range environmentVariableNames(item) {
			out = append(out, procEnvCredential{Name: name, Item: item})
		}
	}
	return out
}

func readProcEnvironment(path string, opts Options) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	limit := opts.MaxFileSize
	if limit <= 0 {
		limit = 1024 * 1024
	}
	b, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, nil
	}
	return parseProcEnvironment(b), nil
}

func isSkippableProcError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
		return true
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "no such process")
}

func parseProcEnvironment(data []byte) map[string]string {
	values := make(map[string]string)
	for _, raw := range strings.Split(string(data), "\x00") {
		if raw == "" {
			continue
		}
		name, value, ok := strings.Cut(raw, "=")
		if !ok || name == "" {
			continue
		}
		values[name] = value
	}
	return values
}

func procEnvironmentLocation(process procProcess, envName string) string {
	if process.Name == "" {
		return fmt.Sprintf("pid=%d env=%s", process.PID, envName)
	}
	return fmt.Sprintf("pid=%d comm=%s env=%s", process.PID, process.Name, envName)
}
