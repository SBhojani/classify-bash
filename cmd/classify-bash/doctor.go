package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/shabbir-genetech/classify-bash/internal/adapter/claude"
)

// runDoctor reports what the log says about host schema drift, and what this
// binary currently enumerates. It exists so schema drift is discoverable
// without being fatal: the signal that used to live on the exit code — where it
// could block the Bash tool — lives here instead.
func runDoctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	logFile := fs.String("log-file", "", "read records from this file instead of the journal")
	if err := fs.Parse(args); err != nil {
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
	fmt.Printf("log source:       %s (%d records)\n\n", source, len(records))

	counts := map[string]int{}
	reasons := map[string]map[string]int{}
	for _, r := range records {
		counts[r.Kind]++
		if r.Kind == "fallthrough" || r.Reason == "" {
			continue
		}
		if reasons[r.Kind] == nil {
			reasons[r.Kind] = map[string]int{}
		}
		reasons[r.Kind][r.Reason]++
	}

	for _, kind := range sortedKeys(counts) {
		fmt.Printf("  %-22s %d\n", kind, counts[kind])
	}

	// The two that mean "act on me": a field we do not enumerate, and a
	// registration still using the pre-subcommand invocation.
	if drift := reasons["schema_drift"]; len(drift) > 0 {
		fmt.Println("\nUnenumerated fields seen (add to event.go to silence):")
		for _, r := range sortedKeys(drift) {
			fmt.Printf("  %-40s ×%d\n", r, drift[r])
		}
	}
	if counts["deprecated_invocation"] > 0 {
		fmt.Println("\nThe hook is still registered with the pre-subcommand invocation.")
		fmt.Println("Update it to:  classify-bash hook --mode=claude-strict --log --log-to=auto")
	}
	if fl := reasons["failloud"]; len(fl) > 0 {
		fmt.Println("\nBLOCKED calls (these exited 2 and stopped a tool call):")
		for _, r := range sortedKeys(fl) {
			fmt.Printf("  %-40s ×%d\n", r, fl[r])
		}
	}
	return exitReadOnly
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
