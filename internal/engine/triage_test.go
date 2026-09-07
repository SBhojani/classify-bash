package engine

// Log-corpus triage harness.
//
// This exists because inferring *why* a logged command fell through by reading
// or regex-matching the log string has produced wrong answers on every pass that
// tried it (2026-06-09 blamed the `cd` prefix, then statement sequencing;
// 2026-07-27 blamed `cd` again, plus a batch of specs that were never the
// blocker). The blocker is almost never the command your eye lands on. The only
// reliable classifier of a log record is the classifier itself, so these tests
// call classifyCommand / safeCommands directly and never pattern-match a command
// string.
//
// Usage (from `nix develop`):
//
//	journalctl -t classify-bash -o cat > /tmp/corpus.jsonl
//	CORPUS=/tmp/corpus.jsonl go test -run TestTriage -v .
//
// Optional:
//
//	SINCE=2026-06-12   drop records older than this ts prefix. Set it to the date
//	                   commands.go last changed: older records were judged by a
//	                   different whitelist and their verdicts are stale, which is
//	                   what makes a raw corpus read overstate the gaps.
//	SHOW=tag,tag       print verbatim examples for blame tags with this prefix,
//	                   so a finding can be eyeballed and re-tested by hand.
//
// Both tests skip when CORPUS is unset, so `go test ./...` stays unaffected.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

// logRecord mirrors the on-disk JSON record shape written by the logging
// package's formatRecord. It is duplicated here rather than imported because
// the engine deliberately does not depend on the logging package — the corpus
// is just JSON that happens to have been produced by it. Keep in sync with
// formatRecord if the record shape changes; a mismatched field only means a
// blank column in the triage report, never a wrong verdict, since every record
// is re-classified by the live classifier rather than trusted.

type logRecord struct {
	TS      string `json:"ts"`
	Kind    string `json:"kind"`
	Command string `json:"command"`
	Reason  string `json:"reason"`
	OrigLen int    `json:"orig_len"`
}

// readCorpus returns the records in the file named by $CORPUS, skipping the test
// if unset. Non-JSON lines (journald framing, boot markers) are ignored.
func readCorpus(t *testing.T) []logRecord {
	t.Helper()
	path := os.Getenv("CORPUS")
	if path == "" {
		t.Skip("set CORPUS=<file of log records> to run triage")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open corpus: %v", err)
	}
	defer f.Close()

	since := os.Getenv("SINCE")
	var out []logRecord
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var r logRecord
		if json.Unmarshal([]byte(line), &r) != nil {
			continue
		}
		if since != "" && r.TS < since {
			continue
		}
		out = append(out, r)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	return out
}

// TestTriage is the whole triage pass: health check, staleness split, and a
// per-record attribution of the single construct that blocked each fall-through.
func TestTriage(t *testing.T) {
	recs := readCorpus(t)

	// 1. Health. The signal that matters is any failloud: those mean the
	// classifier went stale (unknown AST node, or a harness field the strict
	// decoder rejects) and they BLOCK calls. Fall-throughs never block.
	var failloud, fallthroughs int
	reasons := map[string]int{}
	for _, r := range recs {
		switch r.Kind {
		case "failloud":
			failloud++
			reasons[r.Reason]++
		case "fallthrough":
			fallthroughs++
		}
	}
	fmt.Printf("corpus: %d records  (fallthrough=%d, failloud=%d)\n", len(recs), fallthroughs, failloud)
	if failloud > 0 {
		fmt.Printf("\n!! %d failloud records — classifier staleness, these BLOCKED calls:\n", failloud)
		printCounts(reasons, 10)
	}

	// 2. Staleness. Records logged before the last whitelist change were judged
	// by an older binary; any that allow now are already-fixed noise, not gaps.
	// Reporting this split stops a stale corpus from inflating the findings.
	var stale int
	var live []logRecord
	for _, r := range recs {
		if r.Kind != "fallthrough" || r.Command == "" {
			continue
		}
		if classifyCommand(r.Command) == decisionAllow {
			stale++
			continue
		}
		live = append(live, r)
	}
	fmt.Printf("\nreplay against the CURRENT whitelist:\n")
	fmt.Printf("  would allow now (already fixed, ignore): %d\n", stale)
	fmt.Printf("  still fall through (the real corpus):    %d\n", len(live))

	// 3. Attribution: one blocker per record, found by descending the same
	// structure classifyStmt walks.
	parser := syntax.NewParser()
	blame := map[string]int{}
	for _, r := range live {
		blame[blameCommand(parser, r.Command)]++
	}
	fmt.Printf("\n=== primary blocker per still-falling record ===\n")
	printCounts(blame, 40)

	if show := os.Getenv("SHOW"); show != "" {
		printExamples(parser, live, strings.Split(show, ","))
	}
}

// blameCommand returns a tag naming the first construct that blocks cmd.
func blameCommand(parser *syntax.Parser, cmd string) string {
	f, err := parser.Parse(strings.NewReader(cmd), "")
	if err != nil {
		return "<unparseable by mvdan/sh>"
	}
	for _, st := range f.Stmts {
		if !classifyStmt(st) {
			return blameStmt(st)
		}
	}
	return "<no blocker found — classifier and triage disagree, investigate>"
}

// blameStmt mirrors classifyStmt's checks in the same order and names the first
// failure. It only ever descends into a child that classifyStmt itself rejects,
// so the tag it returns is the actual blocker rather than a co-occurring
// innocent command earlier in the line.
func blameStmt(st *syntax.Stmt) string {
	if st.Background {
		return "<background &>"
	}
	if st.Coprocess {
		return "<coprocess>"
	}
	if st.Negated {
		return "<negated !>"
	}
	for _, r := range st.Redirs {
		if !safeRedirect(r) {
			if target, ok := wordLiteral(r.Word); ok {
				return "<write redirect to " + target + ">"
			}
			return "<redirect to an expansion>"
		}
	}
	return blameCmd(st.Cmd)
}

func blameCmd(cmd syntax.Command) string {
	switch c := cmd.(type) {
	case *syntax.CallExpr:
		return blameCall(c)
	case *syntax.BinaryCmd:
		// Descend only into the side that actually fails.
		if !classifyStmt(c.X) {
			return blameStmt(c.X)
		}
		return blameStmt(c.Y)
	case *syntax.Subshell:
		for _, s := range c.Stmts {
			if !classifyStmt(s) {
				return blameStmt(s)
			}
		}
		return "<empty subshell>"
	case *syntax.ForClause:
		return "<for/while loop>"
	case *syntax.WhileClause:
		return "<for/while loop>"
	case *syntax.IfClause:
		return "<if>"
	case *syntax.CaseClause:
		return "<case>"
	case *syntax.Block:
		return "<block { }>"
	case *syntax.FuncDecl:
		return "<function decl>"
	case *syntax.TestClause:
		return "<test [[ ]]>"
	case *syntax.DeclClause:
		return "<declare/local/export>"
	case *syntax.ArithmCmd:
		return "<arithmetic (( ))>"
	case *syntax.TimeClause:
		return "<time>"
	case *syntax.LetClause:
		return "<let>"
	case nil:
		return "<bare redirect>"
	default:
		return fmt.Sprintf("<unhandled node %T>", c)
	}
}

// blameCall names why one simple command failed, distinguishing the three cases
// that call for different fixes: the command is absent from the whitelist
// (add-a-command), it is present but its spec rejected these args (extend-a-spec,
// and the tag carries the flag that is most likely responsible), or an operand
// carried an expansion the classifier will not accept (a classifier feature).
func blameCall(c *syntax.CallExpr) string {
	if len(c.Args) == 0 {
		if len(c.Assigns) > 0 {
			return "<variable assignment>"
		}
		return "<empty call>"
	}
	if len(c.Assigns) > 0 {
		return "<env-prefix assignment>"
	}
	name, ok := wordLiteral(c.Args[0])
	if !ok {
		return "<expanded command name>"
	}
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	spec, ok := safeCommands[name]
	if !ok {
		return "MISSING-CMD " + name
	}
	toks, ok := argTokens(c.Args[1:])
	if !ok {
		return "EXPANSION-ARG " + name
	}
	if spec.match(toks) {
		return "<spec accepts this call — blocker is elsewhere>"
	}
	// Narrow the rejection to a single operand by bisecting: find the shortest
	// prefix of args that the spec already rejects, and report its last token.
	// That is the operand that tipped it, which beats guessing from position.
	//
	// The tipping token alone is not enough to act on. A global flag that must
	// precede a subcommand (`jj -R <path> …`) tips the prefix at `-R` for BOTH
	// `jj -R p log` (a genuine gap) and `jj -R p commit` (a correct rejection),
	// so the tag also carries the first non-flag word — the subcommand — which
	// is what decides whether the record is a miss or the intended outcome.
	tipped := ""
	for i := 1; i <= len(toks); i++ {
		if !spec.match(toks[:i]) {
			tipped = tokenLabel(toks[i-1])
			break
		}
	}
	if tipped == "" {
		return "SPEC-REJECT " + name + " <full argv>"
	}
	tag := "SPEC-REJECT " + name + " @ " + tipped
	if sub := firstWordOperand(spec, toks); sub != "" && sub != tipped {
		tag += " [sub: " + sub + "]"
	}
	return tag
}

// firstWordOperand returns the first literal operand that is neither flag-shaped
// nor the *value* of a preceding TakesArg flag — for a subcommand-style spec that
// is the subcommand, the word that decides whether the record was read-only or
// mutating. Consulting the spec's own flag table matters: skipping it made
// `jj -R <path> log` report the path as the subcommand, splitting one finding
// into a bucket per repository path.
func firstWordOperand(spec *commandSpec, toks []argToken) string {
	for i := 0; i < len(toks); i++ {
		tk := toks[i]
		if tk.subst || tk.lit == "" {
			continue
		}
		if strings.HasPrefix(tk.lit, "-") && tk.lit != "-" && tk.lit != "--" {
			// Skip this flag's separate value. A flag in the spec's table tells
			// us directly. A flag that is NOT in the table is the rejected one,
			// and the very gap being diagnosed is often a global flag missing
			// from a parent spec (`jj`'s top-level spec has Flags: nil, so `-R`
			// is unknown here) — for those, assume a path-like following word is
			// its value, or we would report that path as the subcommand.
			if !strings.Contains(tk.lit, "=") {
				known := flagTakesArg(spec, tk.lit)
				if known || (i+1 < len(toks) && looksLikeFlagValue(toks[i+1])) {
					i++
				}
			}
			continue
		}
		return tk.lit
	}
	return ""
}

// looksLikeFlagValue reports whether tk is plausibly a flag's value rather than a
// subcommand: a path, or anything that is not a bare lowercase word. Subcommands
// are bare words, so this stays conservative — a wrong guess only degrades a
// blame label, never a classification.
func looksLikeFlagValue(tk argToken) bool {
	if tk.subst {
		return true
	}
	s := tk.lit
	if s == "" {
		return false
	}
	if strings.ContainsAny(s, "/~.=") {
		return true
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r == '-') {
			return true
		}
	}
	return false
}

// flagTakesArg reports whether tok names a flag in spec's table that consumes a
// following word. Unknown flags return false: the token is what got rejected, so
// there is no value to skip.
func flagTakesArg(spec *commandSpec, tok string) bool {
	if spec == nil {
		return false
	}
	name := strings.TrimLeft(tok, "-")
	long := strings.HasPrefix(tok, "--")
	for _, f := range spec.Flags {
		if !f.TakesArg {
			continue
		}
		if long && f.Long == name {
			return true
		}
		if !long && f.Short == name {
			return true
		}
	}
	return false
}

func tokenLabel(tk argToken) string {
	if tk.subst {
		return `"$(...)"`
	}
	return tk.lit
}

func printExamples(parser *syntax.Parser, recs []logRecord, want []string) {
	const perTag = 4
	shown := map[string]int{}
	fmt.Printf("\n=== verbatim examples ===\n")
	for _, r := range recs {
		tag := blameCommand(parser, r.Command)
		for _, w := range want {
			w = strings.TrimSpace(w)
			if w == "" || !strings.HasPrefix(tag, w) || shown[w] >= perTag {
				continue
			}
			shown[w]++
			oneline := strings.Join(strings.Fields(r.Command), " ")
			if len(oneline) > 240 {
				oneline = oneline[:240] + "…"
			}
			fmt.Printf("\n[%s]\n  %s\n", tag, oneline)
		}
	}
}

func printCounts(m map[string]int, limit int) {
	type kv struct {
		k string
		v int
	}
	xs := make([]kv, 0, len(m))
	for k, v := range m {
		xs = append(xs, kv{k, v})
	}
	sort.Slice(xs, func(i, j int) bool {
		if xs[i].v != xs[j].v {
			return xs[i].v > xs[j].v
		}
		return xs[i].k < xs[j].k
	})
	for i, x := range xs {
		if i >= limit {
			fmt.Printf("  … %d more\n", len(xs)-limit)
			break
		}
		fmt.Printf("%6d  %s\n", x.v, x.k)
	}
}
