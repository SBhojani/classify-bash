package logging

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// logRecord mirrors the on-disk JSON shape for assertions. Pointers/omitempty
// let tests distinguish "field absent" from "field present and zero".
type logRecord struct {
	TS      string `json:"ts"`
	Kind    string `json:"kind"`
	Command string `json:"command"`
	Reason  string `json:"reason"`
	OrigLen int    `json:"orig_len"`
}

// readOneRecord reads exactly one JSON line from path and decodes it.
func readOneRecord(t *testing.T, path string) logRecord {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("want exactly 1 record, got %d: %q", len(lines), string(b))
	}
	var rec logRecord
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("decode record %q: %v", lines[0], err)
	}
	return rec
}

func TestParseLogFlagsValid(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", "/tmp/xdg")

	cases := []struct {
		name    string
		args    []string
		enabled bool
		sink    string
		file    string
	}{
		{"default off", nil, false, "auto", "/tmp/xdg/classify-bash/log"},
		{"enabled file sink", []string{"--log", "--log-to=file", "--log-file=/x/y"}, true, "file", "/x/y"},
		{"enabled journal", []string{"--log", "--log-to=journal"}, true, "journal", "/tmp/xdg/classify-bash/log"},
		{"log-to defaults auto", []string{"--log"}, true, "auto", "/tmp/xdg/classify-bash/log"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := parseLogFlags(c.args)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.enabled != c.enabled || cfg.sink != c.sink || cfg.file != c.file {
				t.Fatalf("got %+v, want enabled=%v sink=%q file=%q", *cfg, c.enabled, c.sink, c.file)
			}
		})
	}
}

// Strict parsing: a bad flag or unknown sink must return an error (main turns it
// into a failLoud), never silently disable logging.
func TestParseLogFlagsStrict(t *testing.T) {
	cases := [][]string{
		{"--nope"},                   // unknown flag
		{"--log", "--log-to=banana"}, // unknown sink value
		{"--log-to=banana"},          // bad sink even when logging is off
	}
	for _, args := range cases {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			if _, err := parseLogFlags(args); err == nil {
				t.Fatalf("args %q: want error, got nil", args)
			}
		})
	}
}

func TestDefaultLogFile(t *testing.T) {
	t.Run("XDG_STATE_HOME wins", func(t *testing.T) {
		t.Setenv("XDG_STATE_HOME", "/tmp/state")
		if got := defaultLogFile(); got != "/tmp/state/classify-bash/log" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("falls back to HOME/.local/state", func(t *testing.T) {
		t.Setenv("XDG_STATE_HOME", "")
		t.Setenv("HOME", "/tmp/home")
		if got := defaultLogFile(); got != "/tmp/home/.local/state/classify-bash/log" {
			t.Fatalf("got %q", got)
		}
	})
}

func TestLogNonAllowFileSink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "log") // parent dir does not exist yet
	cfg := &logConfig{enabled: true, sink: "file", file: path}

	logNonAllow(cfg, "fallthrough", "ls -la /etc", "")

	rec := readOneRecord(t, path)
	if rec.Kind != "fallthrough" || rec.Command != "ls -la /etc" {
		t.Fatalf("got %+v", rec)
	}
	if rec.Reason != "" || rec.OrigLen != 0 {
		t.Fatalf("reason/orig_len should be absent for an untruncated fall-through: %+v", rec)
	}
	if rec.TS == "" {
		t.Fatalf("ts missing: %+v", rec)
	}
}

func TestLogNonAllowFailloudRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	cfg := &logConfig{enabled: true, sink: "file", file: path}

	logNonAllow(cfg, "failloud", "git frobnicate", "unknown git subcommand \"frobnicate\"")

	rec := readOneRecord(t, path)
	if rec.Kind != "failloud" || rec.Command != "git frobnicate" {
		t.Fatalf("got %+v", rec)
	}
	if rec.Reason == "" {
		t.Fatalf("failloud record must carry a reason: %+v", rec)
	}
}

func TestLogNonAllowTruncation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	cfg := &logConfig{enabled: true, sink: "file", file: path}

	long := strings.Repeat("a", maxLoggedCommand+500)
	logNonAllow(cfg, "fallthrough", long, "")

	rec := readOneRecord(t, path)
	if rec.OrigLen != len(long) {
		t.Fatalf("orig_len = %d, want %d", rec.OrigLen, len(long))
	}
	if !strings.HasSuffix(rec.Command, "…[truncated]") {
		t.Fatalf("truncated command should carry the marker: %q...", rec.Command[:32])
	}
}

func TestLogNonAllowDisabled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	cfg := &logConfig{enabled: false, sink: "file", file: path}

	logNonAllow(cfg, "fallthrough", "ls", "")
	logNonAllow(nil, "fallthrough", "ls", "") // nil config must also be a no-op

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("disabled logging must not create the file (stat err = %v)", err)
	}
}

// A logging-write failure must be swallowed: no panic, no file. Here MkdirAll
// fails because a parent path component is a regular file, not a directory.
func TestLogNonAllowWriteErrorSwallowed(t *testing.T) {
	dir := t.TempDir()
	notADir := filepath.Join(dir, "afile")
	if err := os.WriteFile(notADir, []byte("x"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}
	path := filepath.Join(notADir, "log") // notADir is a file, so MkdirAll fails
	cfg := &logConfig{enabled: true, sink: "file", file: path}

	logNonAllow(cfg, "fallthrough", "ls", "") // must not panic

	// The write must have been swallowed: nothing readable at path. The exact
	// errno varies (ENOENT vs ENOTDIR since a parent component is a file), so we
	// only require that the record was not successfully written.
	if _, err := os.ReadFile(path); err == nil {
		t.Fatalf("a record was written under an unwritable path, want none")
	}
}
