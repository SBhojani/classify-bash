package claude

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"
)

// event captures every top-level field we have seen in a Claude Code PreToolUse
// payload. We only act on HookEventName, ToolName, and ToolInput.Command.
//
// The other fields are enumerated purely as DOCUMENTATION and as the source of
// truth for schema-drift detection (see unknownFields). They are NOT a
// validation gate: an unrecognized field is reported and ignored, never
// rejected.
//
// This is a deliberate reversal of the original design, which set
// DisallowUnknownFields so that a new harness field would "fail loud". That
// turned every harmless upstream addition into a total Bash outage — twice
// (`dangerouslyDisableSandbox`, then `scratchpad_dir`), the second lasting whole
// sessions because the field ships on every event. A hook that only ever ADDS
// an allow must never be able to block; the signal belongs in the log, not on
// the exit code.
//
// Captured fields use json.RawMessage rather than concrete types so that type
// changes to ignored fields (e.g. cwd switching from string to object) cannot
// trip the decoder either.
type event struct {
	HookEventName string    `json:"hook_event_name"`
	ToolName      string    `json:"tool_name"`
	ToolInput     toolInput `json:"tool_input"`

	SessionID      json.RawMessage `json:"session_id"`
	TranscriptPath json.RawMessage `json:"transcript_path"`
	CWD            json.RawMessage `json:"cwd"`
	PermissionMode json.RawMessage `json:"permission_mode"`
	ToolUseID      json.RawMessage `json:"tool_use_id"`
	AgentID        json.RawMessage `json:"agent_id"`
	AgentType      json.RawMessage `json:"agent_type"`
	Effort         json.RawMessage `json:"effort"`
	// PromptID correlates the call to the originating prompt.
	PromptID json.RawMessage `json:"prompt_id"`
	// ScratchpadDir is the session's scratchpad directory. Added by the harness
	// on every PreToolUse event; it caused the 2026-09-06/07 outages under the
	// old strict decoder.
	ScratchpadDir json.RawMessage `json:"scratchpad_dir"`
}

// toolInput is the Bash tool's input shape. command is the only field we
// classify on; the others are enumerated for the same reason as the top-level
// context fields.
type toolInput struct {
	Command string `json:"command"`

	Description     json.RawMessage `json:"description"`
	Timeout         json.RawMessage `json:"timeout"`
	RunInBackground json.RawMessage `json:"run_in_background"`
	Effort          json.RawMessage `json:"effort"`

	// DangerouslyDisableSandbox: the harness attaches this when a Bash call
	// opts out of the sandbox. The decision to run outside the sandbox is the
	// permission flow's concern, not ours — we still only ever ADD an allow.
	DangerouslyDisableSandbox json.RawMessage `json:"dangerouslyDisableSandbox"`
}

// knownEventFields / knownToolInputFields are derived from the struct tags
// above so there is exactly one source of truth: adding a field to the struct
// automatically stops it being reported as drift.
var (
	knownEventFields     = jsonFieldNames(reflect.TypeOf(event{}))
	knownToolInputFields = jsonFieldNames(reflect.TypeOf(toolInput{}))
)

func jsonFieldNames(t reflect.Type) map[string]bool {
	names := make(map[string]bool, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		if name != "" && name != "-" {
			names[name] = true
		}
	}
	return names
}

// decodeEvent reads exactly one JSON event from r and validates the parts of the
// contract we actually depend on. It returns the event, the sorted list of field
// names we did not recognize (schema drift — informational only), and an error
// for input we genuinely cannot use.
//
// Callers must treat that error as fall-through, not as a block: see failOpen in
// main.go.
func decodeEvent(r io.Reader) (*event, []string, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, fmt.Errorf("read stdin: %w", err)
	}

	var ev event
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&ev); err != nil {
		return nil, nil, fmt.Errorf("decode stdin: %w", err)
	}
	// Reject trailing data: the hook contract is exactly one event per invocation.
	if dec.More() {
		return nil, nil, fmt.Errorf("decode stdin: unexpected trailing data after event")
	}

	drift := unknownFields(data)

	if ev.HookEventName != "PreToolUse" {
		return nil, drift, fmt.Errorf("unexpected hook_event_name %q (want PreToolUse)", ev.HookEventName)
	}
	if ev.ToolName != "Bash" {
		return nil, drift, fmt.Errorf("unexpected tool_name %q (want Bash)", ev.ToolName)
	}
	if strings.TrimSpace(ev.ToolInput.Command) == "" {
		return nil, drift, fmt.Errorf("tool_input.command is empty")
	}
	return &ev, drift, nil
}

// unknownFields lists payload keys absent from the structs above, at the top
// level and inside tool_input. Best-effort: input we cannot re-parse as an
// object simply reports no drift, since the decode error is the real signal.
func unknownFields(data []byte) []string {
	var top map[string]json.RawMessage
	if json.Unmarshal(data, &top) != nil {
		return nil
	}
	var out []string
	for key, raw := range top {
		if !knownEventFields[key] {
			out = append(out, key)
			continue
		}
		if key != "tool_input" {
			continue
		}
		var input map[string]json.RawMessage
		if json.Unmarshal(raw, &input) != nil {
			continue
		}
		for inner := range input {
			if !knownToolInputFields[inner] {
				out = append(out, "tool_input."+inner)
			}
		}
	}
	sort.Strings(out)
	return out
}
