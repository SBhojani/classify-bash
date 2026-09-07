package engine

import "strings"

// flagStyle controls how a CommandSpec interprets its Flags list.
type flagStyle int

const (
	// styleGNU: short flags are single letters that may be clustered (`-la`,
	// `-n5`); long flags use the `--name`/`--name=value` form. The standard
	// shape for ls, cat, grep, git, etc.
	styleGNU flagStyle = iota
	// styleFind: every flag is a `-name` form (single dash, full word), no
	// clustering, no `=value` syntax. Values follow as the next argument.
	// Used by find(1).
	styleFind
	// styleWrapper: command is a transparent wrapper that execs the argv after
	// a literal `--` separator. Pre-`--` segment matches GNU-style flags from
	// spec.Flags plus optional positionals (gated by AllowAnyPositional). The
	// wrapped command is looked up in safeCommands and matched recursively, so
	// safety is inherited rather than loosened. Used by `devenv shell --` and
	// `nix shell PKGS --`.
	styleWrapper
	// styleAwk: awk-shape command line `[flag…] PROGRAM [files…]`. Pre-program
	// flags are short-only (`-F sep`, `-v var=val`); all listed flags must take
	// arguments. The first non-flag positional is the awk program source,
	// classified by classifyAwkProgram (positive-whitelisted awk AST). Any
	// remaining positionals are file paths, accepted as-is (litArgs has
	// already rejected words with shell expansion). `--` ends flag parsing.
	styleAwk
	// styleXargs: stdin-append wrapper `xargs [flag…] CMD [INITIAL-ARG…]`. Unlike
	// styleWrapper there is NO `--` separator — the first non-flag token is the
	// wrapped command, and the rest are fixed initial-arguments. The wrapped
	// command is looked up in a CURATED subset (xargsWrappable), not the full
	// safeCommands, because xargs appends stdin tokens to the wrapped argv that
	// we cannot see at classify time; only commands with no write path under ANY
	// argv are safe to wrap. See matchXargs and DESIGN.md.
	styleXargs
)

// flagSpec describes one allowed flag for a command.
type flagSpec struct {
	Short       string // single letter (one rune); "" if long-only
	Long        string // full name without leading dashes; "" if short-only
	TakesArg    bool   // requires a value: consumes the next word if no `=value`
	OptionalArg bool   // accepts `--name=value` form but does NOT consume a separate next arg
	// Examples: ls --color (none) / --color=auto (with) — OptionalArg=true.
	// vs. git log --pretty=foo or git log --pretty foo — TakesArg=true.

	// DashValueOK lets an OptionalArg flag consume a FOLLOWING token starting with
	// `-`, but only when it is a bare signed integer (`-1`, `+2`). Exists for
	// `journalctl -b -1` ("the boot before last"), where the value is a ±offset and
	// so collides with flag syntax; `-b 0` and `-b all` never needed it, since
	// AllowAnyPositional already swallows a non-dash value.
	//
	// The digits-only rule is what keeps this safe — it can never consume a real
	// flag. Do not set it on a TakesArg flag (the value is consumed there anyway),
	// and do not widen it to non-numeric values without re-deriving that argument.
	DashValueOK bool
}

// isSignedInt reports whether tok is a bare signed integer like "-1" or "+2".
// Used only by DashValueOK; see the field comment for why it is this strict.
func isSignedInt(tok string) bool {
	if len(tok) < 2 || (tok[0] != '-' && tok[0] != '+') {
		return false
	}
	for _, c := range tok[1:] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// commandSpec is a strict whitelist for one command (or subcommand).
//
// Matching rules (styleGNU):
//   - Walk args; long flags `--x`/`--x=v` matched against Long, short flag
//     clusters `-abc`/`-n5` matched letter-by-letter against Short.
//   - A `--` token ends flag parsing; subsequent args are positional.
//   - The first non-flag arg either selects a Subcommand (if Subcommands is
//     non-nil) or is the first positional.
//   - Flags are validated by GNU getopt *permutation* (§8): a flag-shaped token is
//     checked against the spec even when it appears AFTER a positional, so an
//     unwhitelisted flag falls through wherever it lands (`gh repo view o/r --web`
//     → reject `--web`). The sole exception is an `ArgvDataSafe` command: it is safe
//     under any argv, flag-shaped tokens included, so its first positional closes
//     flag parsing and the rest is opaque data (`cat file -X` accepts `-X` as data).
//     This is why a reader whose only write/exec path is a flag (journalctl's
//     `--vacuum-*`) can set AllowAnyPositional yet stay safe: the flag is still
//     validated and rejected; it just must NOT be `ArgvDataSafe`.
//   - If Subcommands is non-nil and no subcommand is selected, fall through.
//   - If Subcommands is nil and AllowAnyPositional is false, any positional
//     causes fall-through.
//
// Matching rules (styleFind):
//   - Args may be positionals (paths, anything not starting with `-`) or
//     `-name`-style flags in any order. Unknown flag → fall through. No
//     clustering, no `=value`.
type commandSpec struct {
	Style              flagStyle
	Flags              []flagSpec
	Subcommands        map[string]*commandSpec
	AllowAnyPositional bool

	// ArgvDataSafe marks a command that has NO write/exec/network path under ANY
	// argv — safe to hand an opaque, attacker-controlled operand whose value we
	// cannot see at classify time, even one shaped like a flag (`-rf`, `--o=x`).
	// Two callers consult it: `classifyWrapped` (an xargs-wrapped command, fed
	// stdin tokens) and `handlePositionals` (a positional produced by a `$(...)`
	// command substitution). It is the single source of truth for that property —
	// there is no parallel list. Set it ONLY on leaf reader commands; never on a
	// command that has any output-file/exec flag (see commands.go).
	ArgvDataSafe bool
}

// argToken is one parsed argv word handed to the matchers. It is either a literal
// value, or an opaque "substituted" operand — a word containing a `$(...)` command
// substitution whose inner command already classified read-only (classify.go).
// A substituted token is NEVER a flag, never `--`, and never a flag's argument; it
// is acceptable only as a positional, and only for an ArgvDataSafe spec.
type argToken struct {
	lit   string // literal value; meaningful only when !subst
	subst bool
}

// litArgs returns the literal string values of args, or (nil, false) if any token
// is substituted. The non-GNU matchers (find/wrapper/xargs/awk) use it to reject
// substituted operands outright — only styleGNU + ArgvDataSafe accepts them in v1.
func litArgs(args []argToken) ([]string, bool) {
	out := make([]string, len(args))
	for i, a := range args {
		if a.subst {
			return nil, false
		}
		out[i] = a.lit
	}
	return out, true
}

// litToks wraps literal strings as non-substituted tokens, for the recursive
// matchers (wrapper/xargs) whose wrapped-command tails are already all-literal.
func litToks(ss []string) []argToken {
	out := make([]argToken, len(ss))
	for i, s := range ss {
		out[i] = argToken{lit: s}
	}
	return out
}

func (s *commandSpec) findShort(letter string) (flagSpec, bool) {
	for _, f := range s.Flags {
		if f.Short == letter {
			return f, true
		}
	}
	return flagSpec{}, false
}

func (s *commandSpec) findLong(name string) (flagSpec, bool) {
	for _, f := range s.Flags {
		if f.Long == name {
			return f, true
		}
	}
	return flagSpec{}, false
}

func (s *commandSpec) match(args []argToken) bool {
	switch s.Style {
	case styleGNU:
		return s.matchGNU(args)
	case styleFind:
		return s.matchFind(args)
	case styleWrapper:
		return s.matchWrapper(args)
	case styleXargs:
		return s.matchXargs(args)
	case styleAwk:
		return s.matchAwk(args)
	default:
		failLoud("unknown flag style: %d", s.Style)
		return false // unreachable
	}
}

func (s *commandSpec) matchGNU(args []argToken) bool {
	// GNU getopt permutation (FUTURE-WORK §8): positionals do NOT close the flag
	// section. We keep scanning and *validating* flags even after a positional has
	// appeared, so an unwhitelisted flag is rejected wherever it lands — closing the
	// hazard where a reader's only write/exec path is a flag (`gh repo view --web`,
	// `journalctl --vacuum-size`) that the operand carries in after its positional.
	// The one exception is an ArgvDataSafe command: it is safe under ANY argv,
	// flag-shaped tokens included, so once its first positional appears the rest is
	// opaque data and we stop validating (the fast path that preserves
	// `cat file --anything`). A literal `--` ends flag parsing for everyone.
	var positionals []argToken
	i := 0
	for i < len(args) {
		tok := args[i]

		// `--` ends flag parsing; everything after is positional (or, with
		// Subcommands, the subcommand name + its args).
		if !tok.subst && tok.lit == "--" {
			tail := args[i+1:]
			if s.Subcommands != nil {
				return s.dispatchSubcommand(tail)
			}
			return s.acceptPositionals(append(positionals, tail...))
		}

		// A substituted operand is never a flag — skip the flag checks; it is a
		// positional handled below.
		if !tok.subst {
			arg := tok.lit

			// Long flag: `--name` or `--name=value`. A long-flag name never starts
			// with another `-`, so tokens like `---` or `----foo` are NOT flags —
			// they are positionals (matches GNU getopt, e.g. `echo ---`).
			if strings.HasPrefix(arg, "--") && len(arg) > 2 && arg[2] != '-' {
				name, hasVal := arg[2:], false
				if eq := strings.IndexByte(name, '='); eq >= 0 {
					name = name[:eq]
					hasVal = true
				}
				f, ok := s.findLong(name)
				if !ok {
					return false
				}
				if hasVal {
					if !f.TakesArg && !f.OptionalArg {
						return false
					}
				} else if f.TakesArg {
					if i+1 >= len(args) {
						return false
					}
					if args[i+1].subst {
						return false // a flag's value must be literal, never substituted
					}
					i++ // consume required value
				} else if f.DashValueOK && i+1 < len(args) &&
					!args[i+1].subst && isSignedInt(args[i+1].lit) {
					// `--boot -1`: an OptionalArg flag whose ±offset value would
					// otherwise parse as an unknown flag. Digits only — see DashValueOK.
					i++
				}
				// !hasVal && !TakesArg: fine (OptionalArg or no-arg flag, both work)
				i++
				continue
			}

			// Short flag cluster: `-l`, `-la`, `-n5`, `-n` (with value next). A short
			// flag's first character is never `-`, so `---`/`-` fall through to
			// positional handling.
			if strings.HasPrefix(arg, "-") && len(arg) > 1 && arg[1] != '-' {
				cluster := arg[1:]
				consumedNext := false
				for j := 0; j < len(cluster); j++ {
					letter := string(cluster[j])
					f, ok := s.findShort(letter)
					if !ok {
						return false
					}
					if f.TakesArg {
						if j+1 < len(cluster) {
							// Rest of cluster is the value; nothing more to scan.
						} else {
							// Cluster ends with a value-taking flag; consume next arg.
							if i+1 >= len(args) {
								return false
							}
							if args[i+1].subst {
								return false // a flag's value must be literal, never substituted
							}
							consumedNext = true
						}
						break
					}
					if f.DashValueOK && j == len(cluster)-1 && i+1 < len(args) &&
						!args[i+1].subst && isSignedInt(args[i+1].lit) {
						// `-b -1`: only when this flag ENDS the cluster, so the offset
						// belongs to it and not to an earlier letter. Digits only.
						consumedNext = true
						break
					}
				}
				i++
				if consumedNext {
					i++
				}
				continue
			}
		}

		// Positional token (a non-flag literal, or a substituted operand).
		if s.Subcommands != nil {
			// The first positional selects the subcommand; everything after it is
			// re-parsed by the subcommand's own grammar (no permutation across the
			// boundary — the subcommand has its own flag set).
			return s.dispatchSubcommand(args[i:])
		}
		if s.ArgvDataSafe {
			// Safe under any argv: the rest is opaque data, stop validating flags.
			return s.acceptPositionals(append(positionals, args[i:]...))
		}
		// Non-ArgvDataSafe: record the positional and keep validating later flags.
		positionals = append(positionals, tok)
		i++
	}

	if s.Subcommands != nil {
		return false // subcommand required, none seen
	}
	return s.acceptPositionals(positionals)
}

// dispatchSubcommand selects and recurses into a subcommand. args[0] is the
// subcommand name (must be literal so we know which spec applies); args[1:] are
// re-parsed by that subcommand's spec.
func (s *commandSpec) dispatchSubcommand(args []argToken) bool {
	if len(args) == 0 {
		return false // subcommand required
	}
	if args[0].subst {
		return false // the subcommand name must be literal
	}
	sub, ok := s.Subcommands[args[0].lit]
	if !ok {
		return false
	}
	return sub.match(args[1:])
}

// acceptPositionals decides a leaf spec (no Subcommands) given its collected
// positionals. A substituted positional is opaque data, accepted only for an
// ArgvDataSafe command (safe under any argv); every ArgvDataSafe command also sets
// AllowAnyPositional, so the literal-positional gate below still applies.
func (s *commandSpec) acceptPositionals(positionals []argToken) bool {
	for _, a := range positionals {
		if a.subst && !s.ArgvDataSafe {
			return false
		}
	}
	if s.AllowAnyPositional {
		return true
	}
	return len(positionals) == 0
}

// matchWrapper accepts argv of the shape `[flag…] [positional…] -- CMD [ARG…]`.
// Pre-`--` flags must match spec.Flags (GNU style). Pre-`--` positionals are
// accepted iff spec.AllowAnyPositional is true. The `--` separator is REQUIRED:
// without it (or with no command after it) we fall through, since bare wrapper
// invocations like `devenv shell` open an interactive shell whose safety cannot
// be statically classified. The tail after `--` is looked up in safeCommands
// and matched recursively, so the wrapper inherits the wrapped command's safety
// rules verbatim — it never loosens them.
func (s *commandSpec) matchWrapper(tokens []argToken) bool {
	// A wrapper never accepts a substituted operand in v1: the wrapped command
	// name and its args must all be literal so we can recurse into safeCommands.
	args, ok := litArgs(tokens)
	if !ok {
		return false
	}
	i := 0
	for i < len(args) {
		arg := args[i]

		if arg == "--" {
			tail := args[i+1:]
			if len(tail) == 0 {
				return false // `devenv shell --` with no command
			}
			sub, ok := safeCommands[tail[0]]
			if !ok {
				return false
			}
			return sub.match(litToks(tail[1:]))
		}

		// Long flag: `--name` or `--name=value`. Same dash-prefix rule as
		// matchGNU — `---foo` is data, not a flag.
		if strings.HasPrefix(arg, "--") && len(arg) > 2 && arg[2] != '-' {
			name, hasVal := arg[2:], false
			if eq := strings.IndexByte(name, '='); eq >= 0 {
				name = name[:eq]
				hasVal = true
			}
			f, ok := s.findLong(name)
			if !ok {
				return false
			}
			if hasVal {
				if !f.TakesArg && !f.OptionalArg {
					return false
				}
			} else if f.TakesArg {
				if i+1 >= len(args) {
					return false
				}
				i++
			}
			i++
			continue
		}

		// Short flag cluster. Same dash-prefix rule as matchGNU.
		if strings.HasPrefix(arg, "-") && len(arg) > 1 && arg[1] != '-' {
			cluster := arg[1:]
			consumedNext := false
			for j := 0; j < len(cluster); j++ {
				letter := string(cluster[j])
				f, ok := s.findShort(letter)
				if !ok {
					return false
				}
				if f.TakesArg {
					if j+1 < len(cluster) {
						// rest of cluster is the value
					} else {
						if i+1 >= len(args) {
							return false
						}
						consumedNext = true
					}
					break
				}
			}
			i++
			if consumedNext {
				i++
			}
			continue
		}

		// Positional before `--`. Only allowed if the spec opts in.
		if !s.AllowAnyPositional {
			return false
		}
		i++
	}

	// No `--` encountered: wrapper invoked without an explicit command.
	return false
}

// matchXargs accepts argv of the shape `[flag…] CMD [INITIAL-ARG…]`. xargs's own
// flags (spec.Flags, GNU style) are parsed until the first non-flag token, which
// is the wrapped command name; the remainder are fixed initial-arguments. The
// command must be ArgvDataSafe (see classifyWrapped) and its initial-arguments are
// classified recursively.
//
// The ArgvDataSafe gate (not the full whitelist) is load-bearing: xargs appends
// stdin tokens to the wrapped argv, and those tokens are invisible here and are
// parsed by the wrapped program (including as flags). Recursing into a command
// that has any write path under some argv (e.g. `sort -o`, `git push`) would let
// stdin inject that path — a write the direct form would have prompted on. Only
// ArgvDataSafe commands have no write path under ANY argv. The replace-mode flags
// `-I`/`-i`/`--replace` are deliberately absent from xargsSpec, so they fall
// through here as unknown flags. xargs's own flags and the wrapped command name
// must be literal, so a substituted token anywhere makes litArgs reject.
func (s *commandSpec) matchXargs(tokens []argToken) bool {
	args, ok := litArgs(tokens)
	if !ok {
		return false
	}
	i := 0
	for i < len(args) {
		arg := args[i]

		// `--` ends xargs flag parsing; the next token is the wrapped command.
		if arg == "--" {
			return s.classifyWrapped(args[i+1:])
		}

		// Long flag: `--name` or `--name=value`. Same dash-prefix rule as matchGNU.
		if strings.HasPrefix(arg, "--") && len(arg) > 2 && arg[2] != '-' {
			name, hasVal := arg[2:], false
			if eq := strings.IndexByte(name, '='); eq >= 0 {
				name = name[:eq]
				hasVal = true
			}
			f, ok := s.findLong(name)
			if !ok {
				return false
			}
			if hasVal {
				if !f.TakesArg && !f.OptionalArg {
					return false
				}
			} else if f.TakesArg {
				if i+1 >= len(args) {
					return false
				}
				i++
			}
			i++
			continue
		}

		// Short flag cluster. Same dash-prefix rule as matchGNU.
		if strings.HasPrefix(arg, "-") && len(arg) > 1 && arg[1] != '-' {
			cluster := arg[1:]
			consumedNext := false
			for j := 0; j < len(cluster); j++ {
				letter := string(cluster[j])
				f, ok := s.findShort(letter)
				if !ok {
					return false
				}
				if f.TakesArg {
					if j+1 < len(cluster) {
						// rest of cluster is the value
					} else {
						if i+1 >= len(args) {
							return false
						}
						consumedNext = true
					}
					break
				}
			}
			i++
			if consumedNext {
				i++
			}
			continue
		}

		// First non-flag token: the wrapped command.
		return s.classifyWrapped(args[i:])
	}

	// No wrapped command (bare `xargs`, or flags only). Bare xargs defaults to
	// running /bin/echo on stdin items; require an explicit command instead.
	return false
}

// classifyWrapped looks up tail[0] in safeCommands and, only if that command is
// ArgvDataSafe (no write path under any argv — see commands.go), recursively
// classifies the fixed initial-arguments tail[1:]. ArgvDataSafe lives on the spec
// itself, so there is no separate list to keep in sync.
func (s *commandSpec) classifyWrapped(tail []string) bool {
	if len(tail) == 0 {
		return false
	}
	sub, ok := safeCommands[tail[0]]
	if !ok {
		return false
	}
	if !sub.ArgvDataSafe {
		return false
	}
	return sub.match(litToks(tail[1:]))
}

// matchAwk parses argv of the shape `[flag…] PROGRAM [files…]`. Pre-program
// short flags from spec.Flags all take arguments (`-F sep`, `-v var=val`).
// The first non-flag positional is the awk program, validated by
// classifyAwkProgram. Long flags (`--name`) and short-without-arg flags
// fall through — gawk extensions and the `-f file` script-load form are
// deliberately out of scope for v1. A substituted token (program or file) is
// rejected: the program must be literal for classifyAwkProgram, and awk is not
// ArgvDataSafe.
func (s *commandSpec) matchAwk(tokens []argToken) bool {
	args, ok := litArgs(tokens)
	if !ok {
		return false
	}
	i := 0
	for i < len(args) {
		arg := args[i]

		// `--` ends flag parsing; first remaining arg is the program.
		if arg == "--" {
			return s.matchAwkProgramAndFiles(args[i+1:])
		}

		// Long flags not supported in v1.
		if strings.HasPrefix(arg, "--") {
			return false
		}

		// Short flag: must be one of the listed flags, must take an arg.
		if strings.HasPrefix(arg, "-") && len(arg) > 1 {
			letter := string(arg[1])
			f, ok := s.findShort(letter)
			if !ok {
				return false
			}
			if !f.TakesArg {
				return false
			}
			if len(arg) > 2 {
				// `-Fsep` form — value attached to the flag token.
				i++
				continue
			}
			// `-F sep` form — value is the next argument.
			if i+1 >= len(args) {
				return false
			}
			i += 2
			continue
		}

		// First non-flag positional: the awk program.
		return s.matchAwkProgramAndFiles(args[i:])
	}
	// No program found.
	return false
}

// matchAwkProgramAndFiles takes the tail starting at the awk program.
// args[0] is the program source; args[1:] are input file paths. Files are
// accepted as-is (litArgs already rejected any substituted operand, and
// wordLiteral rejected other expansions).
func (s *commandSpec) matchAwkProgramAndFiles(args []string) bool {
	if len(args) == 0 {
		return false
	}
	return classifyAwkProgram(args[0])
}

func (s *commandSpec) matchFind(tokens []argToken) bool {
	// find is not ArgvDataSafe (it has -delete/-exec/-fprintf), so a substituted
	// operand is rejected outright.
	args, ok := litArgs(tokens)
	if !ok {
		return false
	}
	i := 0
	for i < len(args) {
		arg := args[i]
		if !strings.HasPrefix(arg, "-") {
			// Positional (a path). Any literal path is fine; substituted operands
			// were already rejected by litArgs above, other expansions by wordLiteral.
			i++
			continue
		}
		// Both `-name` and `--name` accepted (find historically uses single
		// dash, but some long forms also accept `--`).
		name := strings.TrimLeft(arg, "-")
		if name == "" {
			return false
		}
		f, ok := s.findLong(name)
		if !ok {
			return false
		}
		i++
		if f.TakesArg {
			if i >= len(args) {
				return false
			}
			i++ // skip value (any literal is fine)
		}
	}
	return true
}
