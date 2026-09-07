package logging

import "fmt"

// Public surface for the binary. The implementation and its tests stay
// unexported and unchanged.

// NewConfig builds a config directly, for callers that own their own flag
// parsing (the subcommands, which need the log flags alongside their own).
// Validation matches ParseLogFlags: an unknown sink is an error, and an empty
// file falls back to the conventional state-dir path.
func NewConfig(enabled bool, sink, file string) (*Config, error) {
	switch sink {
	case "auto", "journal", "file":
	default:
		return nil, fmt.Errorf("unknown --log-to %q (want auto, journal, or file)", sink)
	}
	cfg := &logConfig{enabled: enabled, sink: sink, file: file}
	if cfg.file == "" {
		cfg.file = defaultLogFile()
	}
	return cfg, nil
}

// Config is the resolved logging configuration for one invocation. It is an
// alias rather than a wrapper so the existing unexported implementation and its
// white-box tests need no edits.
type Config = logConfig

// ParseLogFlags resolves logging configuration from the process arguments.
// Strict: any parse error or unknown --log-to value is returned as an error,
// which the caller turns into a fail-loud exit. A typo in the registration-site
// flags is a deterministic operator error, not harness drift, so it stays loud.
func ParseLogFlags(args []string) (*Config, error) { return parseLogFlags(args) }

// LogNonAllow records one non-allowed event. Best-effort: every error is
// swallowed, because a logging failure must never change the decision.
func LogNonAllow(cfg *Config, kind, command, reason string) {
	logNonAllow(cfg, kind, command, reason)
}
