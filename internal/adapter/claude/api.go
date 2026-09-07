package claude

import (
	"io"
	"sort"
)

// Polarity records which direction this adapter can move friction in its host.
// It is documentation with teeth: an accelerator may only ever remove a prompt,
// so if it is absent or broken the user gets MORE friction, never less. Any
// change here that lets the adapter block is a change to the project's central
// invariant, not a feature.
const Polarity = "accelerator"

// VerifiedAgainst names the host version whose event shape the field manifest
// below was last checked against. It is informational: unknown fields are
// tolerated, so being out of date costs a schema_drift log line, not an outage.
const VerifiedAgainst = "Claude Code 2.1.260"

// KnownFields returns the enumerated event field names, sorted. tool_input
// fields are prefixed, matching how drift is reported.
func KnownFields() []string {
	out := make([]string, 0, len(knownEventFields)+len(knownToolInputFields))
	for k := range knownEventFields {
		out = append(out, k)
	}
	for k := range knownToolInputFields {
		out = append(out, "tool_input."+k)
	}
	sort.Strings(out)
	return out
}

// Public surface for the binary. The decoder and its tests stay unexported and
// unchanged.

// Event is one decoded PreToolUse payload. Alias rather than wrapper so the
// existing implementation and its white-box tests need no edits.
type Event = event

// DecodeEvent reads exactly one event from r and validates the parts of the
// contract we depend on. It returns the event, the sorted list of field names
// we did not recognise (schema drift — informational only), and an error for
// input we genuinely cannot use.
//
// Callers must treat that error as fall-through, never as a block.
func DecodeEvent(r io.Reader) (*Event, []string, error) { return decodeEvent(r) }
