package claude

import "io"

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
