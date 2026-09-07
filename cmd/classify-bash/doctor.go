package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/shabbir-genetech/classify-bash/internal/adapter/claude"
)

// defaultWindow is how far back "current" reaches. The log is append-only and
// spans months, so without a window every incident ever recorded reads as a
// live problem — which is precisely the mistake this report exists to prevent.
const defaultWindow = 30 * 24 * time.Hour

// runDoctor reports what the log says about host schema drift, and what this
// binary currently enumerates. It exists so schema drift is discoverable
// without being fatal: the signal that used to live on the exit code — where it
// could block the Bash tool — lives here instead.
//
// Everything actionable is scoped to a time window. Records outside it are
// summarised as history, never as something to fix: a failloud from a bug that
// was fixed weeks ago is not a reason to go looking now.
func runDoctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	logFile := fs.String("log-file", "", "read records from this file instead of the journal")
	since := fs.String("since", "", "window: a date prefix (2026-09-01), a duration (7d, 24h), or all")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "classify-bash doctor: %v\n", err)
		return exitMalfunction
	}
	cutoff, windowLabel, err := resolveWindow(*since)
	if err != nil {
		fmt.Fprintf(os.Stderr, "classify-bash doctor: %v\n", err)
		return exitMalfunction
	}

	fmt.Printf("adapter:          claude-code (%s)\n", claude.Polarity)
	fmt.Printf("verified against: %s\n", claude.VerifiedAgainst)
	fmt.Printf("enumerated fields: %s\n\n", strings.Join(claude.KnownFields(), " "))

	records, source, err := readRecords(*logFile)
	if err != nil {
		fmt.Printf("log:              unavailable (%v)\n", err)
		fmt.Println("\nNothing to report without a log. Enable it on the hook registration:")
		fmt.Println("  classify-bash hook --mode=… --log --log-to=auto")
		return exitReadOnly
	}

	st := summarise(records, cutoff)
	fmt.Printf("log source:       %s (%d records)\n", source, len(records))
	fmt.Printf("window:           %s\n\n", windowLabel)

	fmt.Printf("  %-22s %8s %9s  %s\n", "kind", "window", "all-time", "last seen")
	for _, kind := range sortedKeys(st.allTime) {
		fmt.Printf("  %-22s %8d %9d  %s\n",
			kind, st.inWindow[kind], st.allTime[kind], st.lastSeen[kind])
	}

	acted := false

	// Only warn when the drift is inside the window: a field enumerated weeks
	// ago still has records, and reporting those as outstanding would send the
	// reader to fix something already fixed.
	if drift := st.reasonsInWindow["schema_drift"]; len(drift) > 0 {
		acted = true
		fmt.Println("\nUnenumerated fields seen in window (add to event.go to silence):")
		for _, r := range sortedKeys(drift) {
			fmt.Printf("  %-40s ×%d\n", r, drift[r])
		}
	}

	if registrationLooksStale(st) {
		acted = true
		fmt.Println("\nThe hook appears to still use the pre-subcommand invocation.")
		fmt.Println("Update it to:  classify-bash hook --mode=claude-strict --log --log-to=auto")
	}

	if fl := st.reasonsInWindow["failloud"]; len(fl) > 0 {
		acted = true
		fmt.Println("\nBLOCKED calls in window (these exited 2 and stopped a tool call):")
		for _, r := range sortedKeys(fl) {
			fmt.Printf("  %-40s ×%d\n", r, fl[r])
		}
	}

	// History, stated as history.
	if n := st.allTime["failloud"] - st.inWindow["failloud"]; n > 0 {
		fmt.Printf("\n%d older failloud record(s) predate the window (most recent %s).\n",
			n, st.lastSeen["failloud"])
		fmt.Println("Those are history, not an outstanding problem — re-run with --since=all to inspect.")
	}

	if !acted {
		fmt.Println("\nNothing to act on in this window.")
	}
	return exitReadOnly
}

// registrationLooksStale answers "is the hook STILL registered with the
// pre-subcommand invocation?".
//
// A count cannot answer that: a single record from before the registration was
// updated would warn forever, sending the reader to fix something already
// fixed. The question is whether the newest hook activity of any kind is that
// deprecation — if anything newer was logged, the registration has moved on.
func registrationLooksStale(st stats) bool {
	last := st.lastSeen["deprecated_invocation"]
	return last != "" && last >= st.lastActivity
}

type stats struct {
	allTime         map[string]int
	inWindow        map[string]int
	lastSeen        map[string]string
	reasonsInWindow map[string]map[string]int
	lastActivity    string // newest ts across every kind
}

func summarise(records []record, cutoff string) stats {
	st := stats{
		allTime:         map[string]int{},
		inWindow:        map[string]int{},
		lastSeen:        map[string]string{},
		reasonsInWindow: map[string]map[string]int{},
	}
	for _, r := range records {
		st.allTime[r.Kind]++
		if r.TS > st.lastSeen[r.Kind] {
			st.lastSeen[r.Kind] = r.TS
		}
		if r.TS > st.lastActivity {
			st.lastActivity = r.TS
		}
		if r.TS < cutoff {
			continue
		}
		st.inWindow[r.Kind]++
		if r.Kind == "fallthrough" || r.Reason == "" {
			continue
		}
		if st.reasonsInWindow[r.Kind] == nil {
			st.reasonsInWindow[r.Kind] = map[string]int{}
		}
		st.reasonsInWindow[r.Kind][r.Reason]++
	}
	return st
}

var durationRe = regexp.MustCompile(`^([0-9]+)([dh])$`)

// resolveWindow accepts a duration (7d, 24h), a literal timestamp prefix
// (2026-09-01), or "all". Timestamps are RFC3339 in UTC, so a lexicographic
// compare against a prefix is a correct date filter — the same convention the
// triage harness uses.
func resolveWindow(since string) (cutoff, label string, err error) {
	switch since {
	case "all":
		return "", "all records", nil
	case "":
		c := time.Now().UTC().Add(-defaultWindow).Format(time.RFC3339)
		return c, fmt.Sprintf("since %s (default 30d; --since=DATE|Nd|all)", c[:10]), nil
	}
	if m := durationRe.FindStringSubmatch(since); m != nil {
		n, convErr := strconv.Atoi(m[1])
		if convErr != nil {
			return "", "", fmt.Errorf("bad --since %q", since)
		}
		unit := time.Hour
		if m[2] == "d" {
			unit = 24 * time.Hour
		}
		c := time.Now().UTC().Add(-time.Duration(n) * unit).Format(time.RFC3339)
		return c, fmt.Sprintf("since %s (%s)", c[:19], since), nil
	}
	if len(since) < 4 || since[0] < '0' || since[0] > '9' {
		return "", "", fmt.Errorf("bad --since %q (want a date like 2026-09-01, a duration like 7d, or all)", since)
	}
	return since, fmt.Sprintf("since %s", since), nil
}

type record struct {
	TS     string `json:"ts"`
	Kind   string `json:"kind"`
	Reason string `json:"reason"`
}

// readRecords prefers the journal, because that is where the deployed
// registration sends them (--log-to=auto). A file is used when asked for
// explicitly, or when journalctl is unavailable.
func readRecords(file string) ([]record, string, error) {
	if file != "" {
		f, err := os.Open(file)
		if err != nil {
			return nil, "", err
		}
		defer f.Close()
		recs, err := parseRecords(f)
		return recs, file, err
	}
	path, err := exec.LookPath("journalctl")
	if err != nil {
		return nil, "", fmt.Errorf("no --log-file given and journalctl not found")
	}
	out, err := exec.Command(path, "-t", "classify-bash", "--no-pager", "-o", "cat").Output()
	if err != nil {
		return nil, "", fmt.Errorf("journalctl: %w", err)
	}
	recs, err := parseRecords(strings.NewReader(string(out)))
	return recs, "journalctl -t classify-bash", err
}

// parseRecords skips anything that is not one of our JSON lines: journald
// framing and boot markers share the stream.
func parseRecords(r io.Reader) ([]record, error) {
	var out []record
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		var rec record
		if json.Unmarshal(sc.Bytes(), &rec) != nil || rec.Kind == "" {
			continue
		}
		out = append(out, rec)
	}
	return out, sc.Err()
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
