package engine

// This file is the engine's only public surface. Everything else in this
// package stays unexported so the whitelist internals cannot be depended on
// from outside — and so the existing white-box tests keep working unchanged.

// OnUnknownConstruct is invoked when the classifier meets a construct it does
// not recognise: an AST node kind from a newer mvdan/sh or goawk, or an
// internal flagStyle value with no case. The binary installs a handler; if none
// is installed the classifier simply treats the construct as not-safe.
//
// TRANSITIONAL. This exists so the package split is behaviour-preserving: the
// binary assigns its existing fail-loud handler here, so an unknown construct
// still exits 2 exactly as before. It is replaced in the next stage by a
// recovered panic surfaced through the classification result, which is what
// lets the caller choose via --on-unknown-ast. Do not build on it.
var OnUnknownConstruct func(format string, args ...any)

// failLoud keeps the five call sites in classify.go/spec.go/awk.go textually
// unchanged across the package split. Each of those sites is followed by
// `return false`, so if no handler is installed — or a handler returns instead
// of exiting — the construct degrades to "not read-only", never to "allow".
func failLoud(format string, args ...any) {
	if OnUnknownConstruct != nil {
		OnUnknownConstruct(format, args...)
	}
}

// ClassifyCommand reports whether cmd is unambiguously read-only and therefore
// safe to auto-allow. False means "not safe, or could not be determined" — the
// caller must treat those identically.
func ClassifyCommand(cmd string) bool {
	return classifyCommand(cmd) == decisionAllow
}
