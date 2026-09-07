package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/shabbir-genetech/classify-bash/internal/adapter/claude"
	"github.com/shabbir-genetech/classify-bash/internal/engine"
	"github.com/shabbir-genetech/classify-bash/internal/logging"
)

// logCfg and currentCommand are process-global because failLoud — reachable
// before the caller regains control — needs them to record a failloud event.
// Both stay zero until resolved, so any failLoud that fires earlier (e.g. a bad
// flag) simply logs nothing.
var (
	logCfg         *logging.Config
	currentCommand string
)

// runHook implements the Claude Code PreToolUse adapter.
//
// legacy selects the pre-subcommand invocation: flags only, no `hook` word.
// That path exists so the binary can be deployed before the host's registration
// is updated, and vice versa. Without it the two have to change atomically, and
// getting that wrong means needing the Bash tool to repair the Bash tool.
func runHook(args []string, legacy bool) int {
	var s strictness

	if legacy {
		// Preserve exactly what this binary did before subcommands existed —
		// notably NEITHER named preset: tolerate a new harness field, stay loud
		// about a stale classifier.
		s = legacyStrictness
		cfg, err := logging.ParseLogFlags(args)
		if err != nil {
			failLoud("bad flag: %v", err)
		}
		logCfg = cfg
		logging.LogNonAllow(logCfg, "deprecated_invocation", "",
			"bare invocation; update the registration to: classify-bash hook --mode=claude-strict")
	} else {
		fs := flag.NewFlagSet("hook", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		mode := fs.String("mode", "", "claude-strict | claude-lenient")
		overrideField := fs.String("on-unknown-field", "", "fail | log | ignore (overrides --mode)")
		overrideAST := fs.String("on-unknown-ast", "", "fail | fallthrough (overrides --mode)")
		enabled := fs.Bool("log", false, "enable best-effort logging of non-allowed commands")
		sink := fs.String("log-to", "auto", "log sink: auto, journal, or file")
		file := fs.String("log-file", "", "log file path (sink=file and auto fallback)")

		if err := fs.Parse(args); err != nil {
			fmt.Fprintf(os.Stderr, "classify-bash hook: %v\n", err)
			return exitMalfunction
		}
		if *mode == "" {
			fmt.Fprintln(os.Stderr, "classify-bash hook: --mode is required (claude-strict or claude-lenient)")
			return exitMalfunction
		}
		resolved, err := resolveMode(*mode)
		if err != nil {
			fmt.Fprintf(os.Stderr, "classify-bash hook: %v\n", err)
			return exitMalfunction
		}
		s = resolved
		if *overrideField != "" {
			s.onUnknownField = *overrideField
		}
		if *overrideAST != "" {
			s.onUnknownAST = *overrideAST
		}
		if err := validateStrictness(s); err != nil {
			fmt.Fprintf(os.Stderr, "classify-bash hook: %v\n", err)
			return exitMalfunction
		}
		cfg, err := logging.NewConfig(*enabled, *sink, *file)
		if err != nil {
			failLoud("bad flag: %v", err)
		}
		logCfg = cfg
	}

	return classifyEvent(s)
}

// classifyEvent is the hook body: decode, apply the strictness policy, classify,
// and either emit an allow or fall through silently.
func classifyEvent(s strictness) int {
	ev, drift, err := claude.DecodeEvent(os.Stdin)

	// Handle drift before the decode error: a payload can be both undecodable
	// and carry new fields, and the drift is the more useful signal.
	if len(drift) > 0 {
		switch s.onUnknownField {
		case "fail":
			failLoud("unknown field(s): %s", strings.Join(drift, ", "))
		case "log":
			logging.LogNonAllow(logCfg, "schema_drift", "", strings.Join(drift, ", "))
		}
	}
	if err != nil {
		failOpen("%v", err)
	}
	currentCommand = ev.ToolInput.Command

	res := engine.Classify(ev.ToolInput.Command)
	if res.Class == engine.Unparseable && s.onUnknownAST == "fail" {
		failLoud("%v", res.Err)
	}
	if res.Class == engine.ReadOnly {
		emitAllow()
	}
	logging.LogNonAllow(logCfg, "fallthrough", ev.ToolInput.Command, "")
	return 0
}

// failLoud prints "classify-bash: <msg>" to stderr and exits with code 2.
//
// Exit 2 BLOCKS the tool call, so this is reserved for the two things nothing
// upstream can trigger: operator error at the registration site (a bad flag),
// and a strictness policy the operator explicitly asked to be loud about.
func failLoud(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	logging.LogNonAllow(logCfg, "failloud", currentCommand, msg)
	fmt.Fprintf(os.Stderr, "classify-bash: %s\n", msg)
	os.Exit(2)
}

// failOpen records an event we could not use and exits 0 with empty stdout, so
// the host falls through to its normal permission flow.
//
// Nothing is written to stderr: on a non-blocking exit the host may surface it
// as noise, and the log is the intended channel. The rule it enforces is the one
// the whole design rests on — a bug here can at worst fail to accelerate, never
// block.
func failOpen(format string, args ...any) {
	logging.LogNonAllow(logCfg, "undecodable", currentCommand, fmt.Sprintf(format, args...))
	os.Exit(0)
}

// emitAllow writes the PreToolUse allow JSON to stdout and exits 0.
func emitAllow() {
	// Hand-written to avoid pulling encoding/json into the hot path for a fixed
	// response. Stable across schema additions because we only emit the fields
	// Claude Code currently requires.
	const out = `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}` + "\n"
	if _, err := os.Stdout.WriteString(out); err != nil {
		failLoud("write stdout: %v", err)
	}
	os.Exit(0)
}
