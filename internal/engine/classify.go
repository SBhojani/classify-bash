package engine

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// decision is the classifier's outcome for one command.
type decision int

const (
	decisionFallThrough decision = iota // exit 0 no JSON; user gets the normal prompt
	decisionAllow                       // emit allow JSON
)

// classifyCommand parses cmd as bash and returns decisionAllow only when every
// statement, every nested construct, every redirect, every word, and every flag
// matches an entry in our strict whitelist. Any uncertainty returns
// decisionFallThrough. Unrecognized mvdan/sh AST node kinds call failLoud.
func classifyCommand(cmd string) decision {
	r := strings.NewReader(cmd)
	f, err := syntax.NewParser().Parse(r, "")
	if err != nil {
		// Parse failure is expected for unusual but legitimate bash. Fall through.
		return decisionFallThrough
	}
	if classifyFile(f) {
		return decisionAllow
	}
	return decisionFallThrough
}

func classifyFile(f *syntax.File) bool {
	if len(f.Stmts) == 0 {
		return false
	}
	for _, stmt := range f.Stmts {
		if !classifyStmt(stmt) {
			return false
		}
	}
	return true
}

func classifyStmt(stmt *syntax.Stmt) bool {
	if stmt.Background || stmt.Coprocess || stmt.Negated {
		return false
	}
	for _, r := range stmt.Redirs {
		if !safeRedirect(r) {
			return false
		}
	}
	return classifyCmd(stmt.Cmd)
}

func classifyCmd(cmd syntax.Command) bool {
	switch c := cmd.(type) {
	case *syntax.CallExpr:
		return classifyCall(c)
	case *syntax.BinaryCmd:
		// && and || — both sides must be safe. Pipelines are *syntax.BinaryCmd
		// with Op == Pipe in mvdan/sh.
		if !classifyStmt(c.X) {
			return false
		}
		return classifyStmt(c.Y)
	case *syntax.Subshell:
		// ( … ) — recurse into the inner statements. Each must classify safe
		// on its own; same rule as && / ||. Parens are just a scope boundary,
		// not a bypass. The empty-Stmts guard mirrors classifyFile.
		if len(c.Stmts) == 0 {
			return false
		}
		for _, s := range c.Stmts {
			if !classifyStmt(s) {
				return false
			}
		}
		return true
	case *syntax.Block,
		*syntax.IfClause, *syntax.ForClause, *syntax.WhileClause, *syntax.CaseClause,
		*syntax.FuncDecl, *syntax.LetClause, *syntax.TimeClause, *syntax.CoprocClause,
		*syntax.TestClause, *syntax.DeclClause, *syntax.ArithmCmd:
		// Out of scope for v1: too easy to hide writes inside these.
		return false
	case nil:
		// A bare redirect like `> file` parses as a Stmt with nil Cmd. Treat as
		// fall-through (it's a write).
		return false
	default:
		// Any new AST node kind from a future mvdan/sh release lands here.
		// Fail loud so we notice and extend the classifier rather than
		// silently treating it as unsafe.
		failLoud("unknown command kind: %T", c)
		return false // unreachable
	}
}

// classifyCall checks a single command invocation against the whitelist.
func classifyCall(c *syntax.CallExpr) bool {
	// Assignments-only statements (`FOO=bar`) parse as CallExpr with empty Args
	// and non-empty Assigns. We don't whitelist any of these — they mutate the
	// shell env in ways we'd rather not auto-allow.
	if len(c.Assigns) > 0 {
		return false
	}
	if len(c.Args) == 0 {
		return false
	}
	// The command name must be a literal so we know which spec applies; a
	// substituted name like `$(echo ls)` is rejected here.
	name, ok := wordLiteral(c.Args[0])
	if !ok {
		return false
	}
	spec, ok := safeCommands[name]
	if !ok {
		return false
	}
	toks, ok := argTokens(c.Args[1:])
	if !ok {
		return false
	}
	return spec.match(toks)
}

// safeRedirect returns true for redirects that cannot cause a write (or that
// write only to /dev/null, which is observationally inert).
func safeRedirect(r *syntax.Redirect) bool {
	if r == nil || r.Word == nil {
		return false
	}
	target, ok := wordLiteral(r.Word)
	if !ok {
		return false // e.g. `> $(...)` or `> $VAR`
	}
	switch r.Op {
	case syntax.RdrIn:
		// `< file` — pure read. Safe iff the source is a literal path.
		return true
	case syntax.RdrOut, syntax.AppOut, syntax.RdrAll, syntax.AppAll, syntax.ClbOut, syntax.RdrInOut:
		// Any write-capable redirect must target literal /dev/null.
		return target == "/dev/null"
	case syntax.Hdoc, syntax.DashHdoc, syntax.WordHdoc:
		// Heredocs only feed stdin to the command. The command itself still
		// needs to classify safe; the heredoc body is content, not a write.
		return true
	case syntax.DplIn, syntax.DplOut:
		// Duplicate-fd redirects (`2>&1`, `<&3`). These don't open new files,
		// so they're inert from a write-safety perspective.
		return true
	default:
		// Unknown redirect op (future mvdan/sh release). Be loud.
		failLoud("unknown redirect op: %v", r.Op)
		return false // unreachable
	}
}

// argTokens classifies each operand word as either a literal value or an opaque
// "substituted" operand — a quoted `$(...)` whose inner command classifies
// read-only safe. Returns (nil, false) if any word is neither: a `$VAR`, an
// unquoted `$(...)`, a process substitution, arithmetic, an extglob, or a quoted
// substitution whose inner command is not safe. The substituted bit travels with
// the token into the matchers, which accept it only as a positional and only for
// an ArgvDataSafe spec.
func argTokens(ws []*syntax.Word) ([]argToken, bool) {
	out := make([]argToken, 0, len(ws))
	for _, w := range ws {
		if s, ok := wordLiteral(w); ok {
			out = append(out, argToken{lit: s})
			continue
		}
		if wordQuotedSubst(w) {
			out = append(out, argToken{subst: true})
			continue
		}
		return nil, false
	}
	return out, true
}

// wordQuotedSubst reports whether w is a "quoted-substitution" word: literal text
// plus one or more `$(...)` command substitutions that appear ONLY inside double
// quotes, where every substitution's inner command classifies read-only safe. A
// bare (unquoted) `$(...)`, or any `$VAR` / `$((...))` / `<(...)` / extglob
// anywhere, makes it not a quoted-substitution word. Requiring double quotes pins
// the expansion to a single argv operand (no word-splitting, no globbing), so it
// can never inject extra argv words.
func wordQuotedSubst(w *syntax.Word) bool {
	if w == nil {
		return false
	}
	sawSubst := false
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit, *syntax.SglQuoted:
			// Literal text outside/inside single quotes — fine.
		case *syntax.DblQuoted:
			for _, inner := range p.Parts {
				switch ip := inner.(type) {
				case *syntax.Lit:
					// Literal text within the quotes — fine.
				case *syntax.CmdSubst:
					if !classifyCmdSubst(ip) {
						return false
					}
					sawSubst = true
				default:
					// ParamExp ($VAR), ArithmExp, ProcSubst, nested quotes, … reject.
					return false
				}
			}
		default:
			// Bare (unquoted) CmdSubst, ParamExp, ArithmExp, ProcSubst, ExtGlob.
			return false
		}
	}
	return sawSubst
}

// classifyCmdSubst reports whether a `$(...)` command substitution is read-only
// safe: every inner statement must itself classify safe — the same recursion as a
// pipe stage or subshell. The mksh `${ …;}` / `${|…;}` forms are rejected.
func classifyCmdSubst(cs *syntax.CmdSubst) bool {
	if cs == nil || len(cs.Stmts) == 0 {
		return false
	}
	if cs.TempFile || cs.ReplyVar {
		return false
	}
	for _, st := range cs.Stmts {
		if !classifyStmt(st) {
			return false
		}
	}
	return true
}

// wordLiteral returns the literal string value of a Word if and only if every
// part is a Lit, a SglQuoted (always literal), or a DblQuoted whose own parts
// are all Lit. Anything else (ParamExp, CmdSubst, ArithmExp, ProcSubst,
// ExtGlob) makes the word unclassifiable for our purposes.
func wordLiteral(w *syntax.Word) (string, bool) {
	if w == nil {
		return "", false
	}
	var b strings.Builder
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			b.WriteString(p.Value)
		case *syntax.SglQuoted:
			b.WriteString(p.Value)
		case *syntax.DblQuoted:
			for _, inner := range p.Parts {
				lit, ok := inner.(*syntax.Lit)
				if !ok {
					return "", false
				}
				b.WriteString(lit.Value)
			}
		default:
			// ParamExp ($VAR), CmdSubst ($(...)), ArithmExp ($((...))),
			// ProcSubst (<(...)), ExtGlob, etc. all land here.
			return "", false
		}
	}
	return b.String(), true
}
