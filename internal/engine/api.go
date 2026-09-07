package engine

import "fmt"

// This file is the engine's only public surface. Everything else in this
// package stays unexported so the whitelist internals cannot be depended on
// from outside — and so the existing white-box tests keep working unchanged.

// Class is what the engine concludes about a command. It is deliberately NOT a
// permission decision: what "not read-only" should cost a user is the host's
// business, not the classifier's, and the three hosts we target disagree about
// it (one can only grant, one can only block, one adjusts an approval tier).
type Class int

const (
	// NotReadOnly is the zero value on purpose: a forgotten branch, a partially
	// built Result, or a future bug degrades to the safe answer rather than to
	// an allow.
	NotReadOnly Class = iota
	// ReadOnly means the command is unambiguously free of write, exec, network
	// and privileged side effects, judged against the strict whitelist.
	ReadOnly
	// Unparseable means the classifier met a construct it does not understand —
	// an AST node kind from a newer mvdan/sh or goawk, or an internal flagStyle
	// with no case. It is NOT the same as a shell syntax error, which is simply
	// NotReadOnly: this says the classifier is stale, not that the input is bad.
	Unparseable
)

// Result is one classification. Err is non-nil only alongside Unparseable, and
// carries which construct defeated the classifier so a caller can log it.
//
// Callers that do not care about staleness can treat Unparseable exactly like
// NotReadOnly — that is the fail-open reading and it is always safe.
type Result struct {
	Class Class
	Err   error
}

// unknownConstructError is panicked from deep inside the recursive walk. Using
// a panic rather than threading an error return through ~15 mutually recursive
// bool-returning helpers keeps the five call sites, and every helper signature,
// untouched. The panic never escapes this package: Classify recovers it.
type unknownConstructError struct{ what string }

func (e unknownConstructError) Error() string { return "unknown " + e.what }

// failLoud is the name the five call sites in classify.go, spec.go and awk.go
// have always used. Its body is now the only thing that changed: instead of
// exiting the process it aborts the walk, and Classify decides what that means.
//
// The engine must never terminate the process. A PreToolUse hook that exits 2
// BLOCKS the tool it was meant to accelerate, which is how a stale classifier
// used to take the whole Bash tool down.
func failLoud(format string, args ...any) {
	panic(unknownConstructError{what: fmt.Sprintf(format, args...)})
}

// Classify reports what the engine can conclude about cmd. It never panics on
// an unknown construct and never exits.
func Classify(cmd string) Result {
	return recoverUnknown(func() decision { return classifyCommand(cmd) })
}

// recoverUnknown runs f and converts an aborted walk into a Result. It is a
// separate function purely so the re-panic path is testable.
//
// Only unknownConstructError is absorbed. Anything else is a real bug and is
// re-panicked: silently swallowing it would turn a crash we need to see into a
// permanent, invisible "nothing is ever read-only".
func recoverUnknown(f func() decision) (result Result) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		if e, ok := r.(unknownConstructError); ok {
			result = Result{Class: Unparseable, Err: e}
			return
		}
		panic(r)
	}()

	if f() == decisionAllow {
		return Result{Class: ReadOnly}
	}
	return Result{Class: NotReadOnly}
}
