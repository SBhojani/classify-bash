package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/shabbir-genetech/classify-bash/internal/engine"
)

// Exit codes for `check`. These are the shim contract, so they are part of the
// public interface and must not be renumbered.
const (
	exitReadOnly    = 0 // safe to auto-allow
	exitNotReadOnly = 1 // not safe, or could not be determined
	exitMalfunction = 2 // this binary is broken or misused; NOT a verdict
)

// checkVerdict is the --json shape. Field presence never varies with the
// verdict, so a TypeScript consumer can type it once; reason is "" rather than
// absent when there is nothing to say.
type checkVerdict struct {
	Class  string `json:"class"`  // read_only | not_read_only | unparseable
	Reason string `json:"reason"` // human-readable, safe to ignore
}

// runCheck implements the host-agnostic entry point: a command in, a verdict
// out. Every shim is built on this rather than on a host wire format, which is
// what keeps hosts we have never heard of integrable.
func runCheck(args []string) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	useStdin := fs.Bool("stdin", false, "read the command verbatim from stdin instead of argv")
	asJSON := fs.Bool("json", false, "emit a JSON verdict on stdout")
	onUnknownAST := fs.String("on-unknown-ast", "fallthrough", "fail | fallthrough")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "classify-bash check: %v\n", err)
		return exitMalfunction
	}
	s := strictness{onUnknownField: "ignore", onUnknownAST: *onUnknownAST}
	if err := validateStrictness(s); err != nil {
		fmt.Fprintf(os.Stderr, "classify-bash check: %v\n", err)
		return exitMalfunction
	}

	cmd, err := checkInput(fs.Args(), *useStdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "classify-bash check: %v\n", err)
		return exitMalfunction
	}

	res := engine.Classify(cmd)
	if res.Class == engine.Unparseable && s.onUnknownAST == "fail" {
		fmt.Fprintf(os.Stderr, "classify-bash check: %v\n", res.Err)
		return exitMalfunction
	}

	if *asJSON {
		v := checkVerdict{Class: className(res.Class)}
		if res.Err != nil {
			v.Reason = res.Err.Error()
		}
		b, err := json.Marshal(v)
		if err != nil {
			fmt.Fprintf(os.Stderr, "classify-bash check: %v\n", err)
			return exitMalfunction
		}
		fmt.Println(string(b))
	}

	if res.Class == engine.ReadOnly {
		return exitReadOnly
	}
	return exitNotReadOnly
}

// checkInput resolves the command from argv or stdin. stdin is the integration
// contract for shims: no ARG_MAX ceiling, no shell-escaping round trip, and the
// command never appears in the process table or a shell history.
func checkInput(rest []string, useStdin bool) (string, error) {
	if useStdin {
		if len(rest) > 0 {
			return "", fmt.Errorf("--stdin takes the command on stdin; do not also pass it as an argument")
		}
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", fmt.Errorf("read stdin: %w", err)
		}
		return string(b), nil
	}
	switch len(rest) {
	case 0:
		return "", fmt.Errorf("no command given (pass one argument, or --stdin)")
	case 1:
		return rest[0], nil
	default:
		// Refuse rather than join: joining with spaces would silently reclassify
		// a differently-quoted command from the one the caller meant.
		return "", fmt.Errorf("expected one command argument, got %d — quote it as a single argument", len(rest))
	}
}

func className(c engine.Class) string {
	switch c {
	case engine.ReadOnly:
		return "read_only"
	case engine.Unparseable:
		return "unparseable"
	default:
		return "not_read_only"
	}
}

// looksLikeLegacyHook reports whether this invocation is the pre-subcommand
// registration line (flags only, JSON arriving on stdin).
//
// This exists so the binary and the host's registration do not have to be
// updated atomically. Getting that wrong is how you end up needing the Bash
// tool to fix the Bash tool.
func looksLikeLegacyHook(args []string) bool {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			return false // a subcommand, or a stray operand
		}
	}
	// Flags alone are ambiguous between "old hook line" and "misuse". Stdin
	// decides: a hook is always fed an event on a pipe, never a terminal.
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice == 0
}
