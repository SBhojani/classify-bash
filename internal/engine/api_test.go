package engine

import (
	"strings"
	"testing"
)

func TestClassifyReadOnly(t *testing.T) {
	if got := Classify("ls -la /tmp"); got.Class != ReadOnly || got.Err != nil {
		t.Fatalf("Classify(ls) = %+v, want ReadOnly with no error", got)
	}
}

func TestClassifyNotReadOnly(t *testing.T) {
	if got := Classify("rm -rf /tmp/x"); got.Class != NotReadOnly || got.Err != nil {
		t.Fatalf("Classify(rm) = %+v, want NotReadOnly with no error", got)
	}
}

// A shell syntax error is NOT Unparseable — that value is reserved for "the
// classifier is stale", not "the input is malformed".
func TestClassifySyntaxErrorIsNotReadOnly(t *testing.T) {
	if got := Classify("ls |"); got.Class != NotReadOnly || got.Err != nil {
		t.Fatalf("Classify(syntax error) = %+v, want NotReadOnly with no error", got)
	}
}

// An unknown construct must abort the walk and surface as Unparseable rather
// than terminating the process, which is what it used to do.
func TestRecoverUnknownYieldsUnparseable(t *testing.T) {
	got := recoverUnknown(func() decision {
		failLoud("command kind: %T", struct{}{})
		return decisionAllow // unreachable
	})
	if got.Class != Unparseable {
		t.Fatalf("Class = %v, want Unparseable", got.Class)
	}
	if got.Err == nil || !strings.Contains(got.Err.Error(), "command kind") {
		t.Fatalf("Err = %v, want it to name the construct", got.Err)
	}
}

// The failure mode this guards against: a broad recover() would swallow a real
// bug and turn it into a permanent, silent "nothing is ever read-only".
func TestRecoverUnknownRepanicsOtherPanics(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("an unrelated panic must propagate, not be absorbed")
		}
		if s, ok := r.(string); !ok || s != "boom" {
			t.Fatalf("re-panicked value = %v, want the original \"boom\"", r)
		}
	}()
	recoverUnknown(func() decision { panic("boom") })
}
