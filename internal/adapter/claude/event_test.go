package claude

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

// ---------------------------------------------------------------------------
// The three tests below moved here from classify_test.go during the package
// split: they exercise decodeEvent, which now lives in this package. They
// overlap with the TestDecodeEvent* tests above (pre-existing duplication, not
// introduced by the split). They are kept verbatim rather than merged because
// their per-case comments are incident history -- each names a harness field
// that once blocked every Bash call -- and a dedupe that silently dropped one
// would re-open exactly the outage class this package exists to prevent.
// ---------------------------------------------------------------------------

// TestEventDecodeContractViolations: every case must produce a non-nil error
// from decodeEvent. main.go converts that into a fail-OPEN exit (0, no stdout);
// here we just verify the error contract.
//
// Unknown fields are deliberately absent from this list — they are no longer a
// contract violation. See TestEventDecodeToleratesUnknownFields below.
func TestEventDecodeContractViolations(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"malformed JSON", `not json`},
		{"truncated", `{"foo":`},
		{"wrong event name", `{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`},
		{"wrong tool name", `{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"command":"ls"}}`},
		{"missing command", `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{}}`},
		{"empty command", `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":""}}`},
		{"whitespace command", `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"   \t\n"}}`},
		{"trailing data", `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}{"extra":true}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := decodeEvent(strings.NewReader(c.body))
			if err == nil {
				t.Fatalf("decodeEvent(%q): want error, got nil", c.body)
			}
			if strings.TrimSpace(err.Error()) == "" {
				t.Errorf("decodeEvent(%q): error message is empty", c.body)
			}
		})
	}
}

// TestEventDecodeToleratesUnknownFields: the cases that used to sit in the
// rejection list above. A field the harness adds after this binary was built
// must decode normally and be reported as drift, never rejected — rejecting
// them blocked every Bash call for entire sessions, twice.
func TestEventDecodeToleratesUnknownFields(t *testing.T) {
	cases := []struct {
		name      string
		body      string
		wantDrift string
	}{
		{
			"unknown top-level field",
			`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"},"extra":1}`,
			"extra",
		},
		{
			"unknown nested field",
			`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls","extra":1}}`,
			"tool_input.extra",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev, drift, err := decodeEvent(strings.NewReader(c.body))
			if err != nil {
				t.Fatalf("decodeEvent(%q): unexpected error %v", c.body, err)
			}
			if ev.ToolInput.Command != "ls" {
				t.Errorf("decodeEvent(%q): command = %q, want ls", c.body, ev.ToolInput.Command)
			}
			if len(drift) != 1 || drift[0] != c.wantDrift {
				t.Errorf("decodeEvent(%q): drift = %v, want [%s]", c.body, drift, c.wantDrift)
			}
		})
	}
}

// TestEventDecodeAccepts: valid events round-trip successfully, including the
// full real-world event shape with all known Claude Code context fields, and
// report no schema drift.
//
// The per-case comments below describe the harness additions historically, when
// an unenumerated field meant exit 2. That is no longer the consequence — an
// unknown field is now reported as drift and ignored — but each field is still
// enumerated so it does not show up as drift on every call.
func TestEventDecodeAccepts(t *testing.T) {
	cases := []string{
		// Minimal valid event (every required field, no context fields).
		`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`,
		`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git status -s"}}`,
		// Real Claude Code v2.1.119 event shape (captured from a live session).
		`{"session_id":"abc-uuid","transcript_path":"/path/to/transcript.jsonl","cwd":"/home/user/repo","permission_mode":"default","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls","description":"List files"},"tool_use_id":"toolu_xyz"}`,
		// With Bash tool's optional timeout / run_in_background fields.
		`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"sleep 5","timeout":10000,"run_in_background":false}}`,
		// Newer Claude Code adds an optional model-supplied per-call effort
		// field in tool_input (alongside description/timeout/run_in_background).
		// Without it enumerated, the strict decoder exits 2 and blocks the call.
		`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls","effort":"high"}}`,
		// With "effortLevel" set in settings.json, the harness also attaches a
		// per-call effort field at the TOP LEVEL of the event (not just inside
		// tool_input). Without it enumerated on `event`, the strict decoder
		// exits 2 and blocks EVERY Bash call.
		`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"},"effort":"high"}`,
		// Sub-agent Bash calls include agent_id + agent_type fields; without
		// these in the schema the strict decoder exits 2 on every sub-agent
		// tool call.
		`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"},"agent_id":"ad50092edde64eaef","agent_type":"Explore"}`,
		// Newer Claude Code attaches a top-level prompt_id correlating the call
		// to the originating prompt. Without it enumerated on `event`, the strict
		// decoder exits 2 and blocks EVERY Bash call.
		`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"},"prompt_id":"p_abc123"}`,
		// Sandbox-disabled Bash calls carry a dangerouslyDisableSandbox flag
		// inside tool_input. Without it enumerated, the strict decoder exits 2
		// and blocks every sandbox-disabled call.
		`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls","dangerouslyDisableSandbox":true}}`,
		// The harness attaches a top-level scratchpad_dir to every event. Under
		// the strict decoder this blocked every Bash call for whole sessions —
		// the incident that motivated tolerating unknown fields entirely.
		`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"},"scratchpad_dir":"/tmp/scratch"}`,
	}
	for _, body := range cases {
		ev, drift, err := decodeEvent(strings.NewReader(body))
		if err != nil {
			t.Errorf("decodeEvent(%q): unexpected error %v", body, err)
			continue
		}
		if ev.HookEventName != "PreToolUse" || ev.ToolName != "Bash" {
			t.Errorf("decodeEvent(%q): wrong fields %+v", body, ev)
		}
		if len(drift) != 0 {
			t.Errorf("decodeEvent(%q): unexpected drift %v (enumerate the field on the struct)", body, drift)
		}
	}
}
