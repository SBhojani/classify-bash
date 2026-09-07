package main

import (
	"strings"
	"testing"
)

const bashEvent = `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls /tmp"}}`

// The regression this whole change exists for: a field the harness added after
// this binary was built must NOT stop us classifying. Under the old strict
// decoder `scratchpad_dir` rejected the entire event, which blocked every Bash
// call for whole sessions.
func TestDecodeEventToleratesNewHarnessFields(t *testing.T) {
	in := `{"hook_event_name":"PreToolUse","tool_name":"Bash",` +
		`"tool_input":{"command":"ls /tmp"},"scratchpad_dir":"/tmp/x","totally_new":1}`

	ev, drift, err := decodeEvent(strings.NewReader(in))
	if err != nil {
		t.Fatalf("unknown fields must not fail decoding: %v", err)
	}
	if ev.ToolInput.Command != "ls /tmp" {
		t.Fatalf("command not decoded: %q", ev.ToolInput.Command)
	}
	// scratchpad_dir is enumerated in the struct now, so only the genuinely
	// unknown field is drift.
	if len(drift) != 1 || drift[0] != "totally_new" {
		t.Fatalf("drift = %v, want [totally_new]", drift)
	}
}

func TestDecodeEventReportsToolInputDrift(t *testing.T) {
	in := `{"hook_event_name":"PreToolUse","tool_name":"Bash",` +
		`"tool_input":{"command":"ls /tmp","brand_new_knob":true}}`

	_, drift, err := decodeEvent(strings.NewReader(in))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(drift) != 1 || drift[0] != "tool_input.brand_new_knob" {
		t.Fatalf("drift = %v, want [tool_input.brand_new_knob]", drift)
	}
}

func TestDecodeEventNoDriftOnKnownPayload(t *testing.T) {
	in := `{"hook_event_name":"PreToolUse","tool_name":"Bash","session_id":"s","cwd":"/tmp",` +
		`"prompt_id":"p","scratchpad_dir":"/tmp/x",` +
		`"tool_input":{"command":"ls /tmp","description":"d","timeout":1,` +
		`"dangerouslyDisableSandbox":false}}`

	if _, drift, err := decodeEvent(strings.NewReader(in)); err != nil || len(drift) != 0 {
		t.Fatalf("drift = %v, err = %v; want none", drift, err)
	}
}

// Type drift on a field we never read must stay silent — that was true of the
// original design and is worth keeping.
func TestDecodeEventIgnoresTypeChangeOnUnreadField(t *testing.T) {
	in := `{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":{"path":"/tmp"},` +
		`"tool_input":{"command":"ls /tmp"}}`

	if _, drift, err := decodeEvent(strings.NewReader(in)); err != nil || len(drift) != 0 {
		t.Fatalf("drift = %v, err = %v; want none", drift, err)
	}
}

func TestDecodeEventRejectsUnusableInput(t *testing.T) {
	for name, in := range map[string]string{
		"malformed":     `{"hook_event_name":`,
		"trailing data": bashEvent + ` {"another":1}`,
		"wrong event":   `{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`,
		"wrong tool":    `{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"command":"ls"}}`,
		"empty command": `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"  "}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := decodeEvent(strings.NewReader(in)); err == nil {
				t.Fatal("want error, got nil")
			}
		})
	}
}
