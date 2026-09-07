package main

import (
	"strings"
	"testing"
	"time"
)

// The bug this guards against: doctor warned "the hook is still registered with
// the pre-subcommand invocation" on the strength of ONE deprecation record left
// over from before the registration was updated. Reporting history as an
// outstanding problem sends the reader to fix something already fixed.
func TestRegistrationStaleOnlyWhenDeprecationIsNewest(t *testing.T) {
	cases := map[string]struct {
		records []record
		want    bool
	}{
		"deprecation then newer activity: registration has moved on": {
			records: []record{
				{TS: "2026-09-07T18:25:52Z", Kind: "deprecated_invocation"},
				{TS: "2026-09-07T18:26:13Z", Kind: "fallthrough"},
			},
			want: false,
		},
		"deprecation is the newest thing: still stale": {
			records: []record{
				{TS: "2026-09-07T18:00:00Z", Kind: "fallthrough"},
				{TS: "2026-09-07T18:25:52Z", Kind: "deprecated_invocation"},
			},
			want: true,
		},
		"never deprecated": {
			records: []record{{TS: "2026-09-07T18:00:00Z", Kind: "fallthrough"}},
			want:    false,
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := registrationLooksStale(summarise(c.records, "")); got != c.want {
				t.Fatalf("registrationLooksStale = %v, want %v", got, c.want)
			}
		})
	}
}

// Old incidents must count toward all-time but never toward the window, which
// is what keeps a fixed outage from reading as a live one.
func TestSummariseSeparatesWindowFromHistory(t *testing.T) {
	records := []record{
		{TS: "2026-06-21T10:00:00Z", Kind: "failloud", Reason: "unknown field \"old\""},
		{TS: "2026-09-07T10:00:00Z", Kind: "failloud", Reason: "unknown field \"new\""},
		{TS: "2026-09-07T11:00:00Z", Kind: "fallthrough"},
	}
	st := summarise(records, "2026-09-01T00:00:00Z")

	if st.allTime["failloud"] != 2 || st.inWindow["failloud"] != 1 {
		t.Fatalf("failloud all-time=%d window=%d, want 2 and 1",
			st.allTime["failloud"], st.inWindow["failloud"])
	}
	if st.lastSeen["failloud"] != "2026-09-07T10:00:00Z" {
		t.Fatalf("lastSeen = %q", st.lastSeen["failloud"])
	}
	if _, ok := st.reasonsInWindow["failloud"]["unknown field \"old\""]; ok {
		t.Fatal("a reason from outside the window leaked into the actionable set")
	}
	if st.reasonsInWindow["failloud"]["unknown field \"new\""] != 1 {
		t.Fatal("the in-window reason is missing")
	}
}

func TestResolveWindow(t *testing.T) {
	if cutoff, _, err := resolveWindow("all"); err != nil || cutoff != "" {
		t.Fatalf(`resolveWindow("all") = %q, %v; want "" and no error`, cutoff, err)
	}

	// A duration must land in the past, and be comparable against RFC3339 UTC
	// timestamps as a plain string — that is the whole filtering mechanism.
	cutoff, _, err := resolveWindow("7d")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := time.Now().UTC().Add(-7 * 24 * time.Hour).Format(time.RFC3339)
	if cutoff[:10] != want[:10] {
		t.Fatalf("7d cutoff date = %q, want %q", cutoff[:10], want[:10])
	}
	if cutoff >= time.Now().UTC().Format(time.RFC3339) {
		t.Fatal("cutoff must be in the past")
	}

	if cutoff, _, err := resolveWindow("2026-09-01"); err != nil || cutoff != "2026-09-01" {
		t.Fatalf("date prefix not passed through: %q, %v", cutoff, err)
	}
	if _, _, err := resolveWindow("banana"); err == nil {
		t.Fatal("want an error for a non-date, non-duration --since")
	}
}

func TestParseRecordsSkipsNonJSONFraming(t *testing.T) {
	in := `-- Boot 1234 --
{"ts":"2026-09-07T10:00:00Z","kind":"fallthrough","command":"rm -rf /x"}
not json at all
{"ts":"2026-09-07T10:00:01Z","kind":"schema_drift","reason":"surprise"}`

	recs, err := parseRecords(strings.NewReader(in))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2 (journald framing must be skipped)", len(recs))
	}
}
