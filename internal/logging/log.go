package logging

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Logging is an opt-in, best-effort audit trail of commands that did NOT classify
// allow — the fall-through cases and the failLoud (contract-violation) cases. It
// is observability bolted onto the side of the classifier, split into two failure
// classes with deliberately different strictness:
//
//   - Log WRITES are best-effort: every error is swallowed. A write must never
//     change the allow/fall-through decision and never failLoud, or it would
//     become a path that can block a tool call — breaking the "a bug can at worst
//     fail to accelerate" asymmetry the whole design rests on.
//   - Log CONFIG (the flags) is validated strictly: a bad flag failLouds (exit 2),
//     the same posture as the strict JSON decoder. A typo in the registration-site
//     flags is a deterministic operator error we want to hear about immediately,
//     not silently swallow into "logging looks on but isn't."
//
// Configuration is by CLI flag at the registration site (the hook command in
// settings.json), not by environment, so the config is explicit where the hook is
// wired up rather than relying on env propagation:
//
//	--log              enable logging (default OFF — preserves the silent contract)
//	--log-to=auto      auto | journal | file
//	--log-file=PATH    file path for sink=file, and the fallback target for auto
//	                   (default: $XDG_STATE_HOME/classify-bash/log, then ~/.local/state)
//
// sink=auto writes to the local syslog/journal socket if reachable and falls back
// to the file otherwise. sink=journal is strict (journal or drop). sink=file
// always writes the file. On systemd systems the journal sink lands in the journal
// via /dev/log; query with `journalctl -t classify-bash` and grep the MESSAGE (we
// log a plain line, not indexed journald fields).

// maxLoggedCommand caps the command length we record. Real commands are tiny; the
// cap only bites pathological inputs (giant blobs, embedded here-docs) you don't
// need verbatim, and it keeps each record to a single write() syscall.
const maxLoggedCommand = 4096

// logConfig is the resolved logging configuration for one invocation.
type logConfig struct {
	enabled bool
	sink    string // "auto" | "journal" | "file"
	file    string // resolved destination / auto-fallback path ("" if unresolvable)
}

// parseLogFlags resolves logging configuration from the process arguments. It is
// strict: any parse error or unknown --log-to value is returned as an error, which
// main turns into a failLoud. Returning the error (rather than exiting here) keeps
// the parsing logic unit-testable.
func parseLogFlags(args []string) (*logConfig, error) {
	fs := flag.NewFlagSet("classify-bash", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // we own the error message via failLoud, not flag's

	enabled := fs.Bool("log", false, "enable best-effort logging of non-allowed commands")
	sink := fs.String("log-to", "auto", "log sink: auto, journal, or file")
	file := fs.String("log-file", "", "log file path (sink=file and auto fallback)")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	switch *sink {
	case "auto", "journal", "file":
	default:
		return nil, fmt.Errorf("unknown --log-to %q (want auto, journal, or file)", *sink)
	}

	cfg := &logConfig{enabled: *enabled, sink: *sink, file: *file}
	if cfg.file == "" {
		cfg.file = defaultLogFile()
	}
	return cfg, nil
}

// defaultLogFile resolves the conventional state-dir path at runtime from the
// environment, so no home path is ever hardcoded (portability + the repo's privacy
// invariant). Returns "" when neither XDG_STATE_HOME nor HOME is set; the file sink
// then no-ops.
func defaultLogFile() string {
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return ""
		}
		base = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(base, "classify-bash", "log")
}

// logNonAllow records one non-allowed event. kind is "fallthrough" or "failloud";
// reason is the failLoud message (empty for fall-throughs). Every error is
// intentionally swallowed; the caller proceeds regardless.
func logNonAllow(cfg *logConfig, kind, command, reason string) {
	if cfg == nil || !cfg.enabled {
		return
	}
	line := formatRecord(kind, command, reason)
	if line == "" {
		return
	}
	switch cfg.sink {
	case "journal":
		_ = writeJournal(line)
	case "file":
		_ = writeFile(cfg.file, line)
	case "auto":
		if writeJournal(line) != nil {
			_ = writeFile(cfg.file, line)
		}
	}
}

// formatRecord builds a single-line JSON record. json.Marshal guarantees the
// command/reason are escaped and newline-free, keeping each record to one line.
// reason is omitted when empty; orig_len is present only when the command was
// truncated (its presence is the truncation signal).
func formatRecord(kind, command, reason string) string {
	origLen := 0
	if len(command) > maxLoggedCommand {
		origLen = len(command)
		command = command[:maxLoggedCommand] + "…[truncated]"
	}
	rec := struct {
		TS      string `json:"ts"`
		Kind    string `json:"kind"`
		Command string `json:"command"`
		Reason  string `json:"reason,omitempty"`
		OrigLen int    `json:"orig_len,omitempty"`
	}{
		TS:      time.Now().UTC().Format(time.RFC3339),
		Kind:    kind,
		Command: command,
		Reason:  reason,
		OrigLen: origLen,
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return ""
	}
	return string(b)
}

// writeJournal sends the record to the local syslog/journal socket. It is defined
// per-platform: journal_unix.go uses log/syslog (Linux/macOS/BSD), journal_other.go
// is a stub on Windows/Plan9 where log/syslog does not exist — there it returns an
// error so sink=auto falls back to the file and sink=journal drops.

// writeFile appends the record with a single O_APPEND write — atomic across
// concurrent hooks on Linux (the inode lock serializes whole write() calls; the
// maxLoggedCommand cap keeps it to one syscall). Creates the parent dir
// best-effort.
func writeFile(path, line string) error {
	if path == "" || line == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(line + "\n")
	return err
}
