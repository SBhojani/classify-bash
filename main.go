// classify-bash is a Claude Code PreToolUse hook for the Bash tool. It reads a
// single PreToolUse event from stdin, classifies the embedded shell command
// against a strict whitelist of read-only commands and flags, and emits an
// "allow" permission decision when the command is unambiguously safe.
//
// Failure modes:
//   - Bash parse failure or unsafe command: exit 0 with no stdout (fall through
//     to Claude Code's normal permission prompt).
//   - Undecodable or unusable event (malformed JSON, wrong event/tool, missing
//     command): fail OPEN — log an "undecodable" record and exit 0 with no
//     stdout. An unrecognized FIELD is not a violation at all: it is recorded as
//     a "schema_drift" record and otherwise ignored.
//   - Bad --log-* flag: exit 2. This is an operator error at the registration
//     site, not harness drift, so it stays loud.
//   - Unknown AST node kind from mvdan/sh that the classifier does not handle:
//     exit 2. Means the classifier is out of date and must be extended before
//     the upgrade can be trusted. NOTE: this is the last remaining path that can
//     block a tool call, and a mvdan/sh bump could trip it; making it
//     configurable is tracked as future work.
package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	// Resolve logging config first, before anything that can failLoud, so the
	// global is in place. Strict: a bad flag failLouds (exit 2).
	cfg, err := parseLogFlags(os.Args[1:])
	if err != nil {
		failLoud("bad flag: %v", err)
	}
	logCfg = cfg

	ev, drift, err := decodeEvent(os.Stdin)
	// Record schema drift before acting on the error: a payload can be both
	// undecodable and carry new fields, and the drift is the more useful signal.
	if len(drift) > 0 {
		logNonAllow(logCfg, "schema_drift", "", strings.Join(drift, ", "))
	}
	if err != nil {
		failOpen("%v", err)
	}
	currentCommand = ev.ToolInput.Command

	if classifyCommand(ev.ToolInput.Command) == decisionAllow {
		emitAllow()
	}
	// Fall-through: best-effort log, then silent exit 0.
	logNonAllow(logCfg, "fallthrough", ev.ToolInput.Command, "")
}

// logCfg and currentCommand are process-global because failLoud — reachable from
// deep in the classifier, before main regains control — needs them to record a
// failloud event. Both stay zero (nil / "") until main resolves them, so any
// failLoud that fires earlier (e.g. a bad flag) simply logs nothing.
var (
	logCfg         *logConfig
	currentCommand string
)

// failLoud prints "classify-bash: <msg>" to stderr and exits with code 2.
// Used for every contract violation we want to be noisy about so we hear
// about it rather than silently ship a stale classifier. It also best-effort
// logs a failloud record (a no-op unless logging is configured and enabled).
func failLoud(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	logNonAllow(logCfg, "failloud", currentCommand, msg)
	fmt.Fprintf(os.Stderr, "classify-bash: %s\n", msg)
	os.Exit(2)
}

// failOpen records an event we could not use and exits 0 with empty stdout, so
// the host falls through to its normal permission flow.
//
// Nothing is written to stderr: on a non-blocking exit the host may surface it
// as noise, and the log is the intended channel for this. The rule it enforces
// is the one the whole design rests on — a bug here can at worst fail to
// accelerate, never block. Contrast failLoud, which is reserved for operator
// error at the registration site (a bad flag), where being noisy is correct
// because nothing upstream can cause it.
func failOpen(format string, args ...any) {
	logNonAllow(logCfg, "undecodable", currentCommand, fmt.Sprintf(format, args...))
	os.Exit(0)
}

// emitAllow writes the PreToolUse allow JSON to stdout and exits 0.
func emitAllow() {
	// Hand-written to avoid pulling encoding/json into the hot path for a
	// fixed response. Stable across schema additions because we only emit
	// the fields Claude Code currently requires.
	const out = `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}` + "\n"
	if _, err := os.Stdout.WriteString(out); err != nil {
		failLoud("write stdout: %v", err)
	}
	os.Exit(0)
}
