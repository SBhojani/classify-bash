# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Committed working preferences and learnings live in @.claude/memory.md.

## What this is

`classify-bash` is a Claude Code **PreToolUse hook for the `Bash` tool**. It reads
one hook event on stdin, parses the embedded shell command, and emits an `allow`
permission decision **only** when the command matches a strict read-only
whitelist; anything else falls through silently to the normal permission prompt
(silent by default — see opt-in logging below). It is an accelerator, never a
gate — see [README.md](README.md) for the contract and [DESIGN.md](DESIGN.md) for
the rationale (allow-only, positive whitelist, tiers A–F, AST handling, the goawk
fork, opt-in logging).

## Architecture

One event flows through a fixed pipeline; reading these in order is the fastest
way to understand the whole thing:

- **`main.go`** — entry point. Resolve logging flags (`parseLogFlags`), decode the
  event, classify the command, and on `decisionAllow` print the fixed allow JSON
  (hand-written, no `encoding/json` on the emit path). Everything else is silent
  exit 0. An unusable event goes through `failOpen` — logged as `undecodable`,
  exit 0 — so a decode problem can never block a tool call. `failLoud` (exit 2)
  survives only for a bad `--log-*` flag and an unknown AST node, and best-effort
  logs a `failloud` record via the package-level `logCfg`/`currentCommand`.
- **`log.go`** — opt-in, best-effort logging of the **non-allowed** cases
  (fall-through + `failOpen` + `schema_drift` + `failLoud`). Off by default; configured by CLI flags
  (`--log`/`--log-to`/`--log-file`) at the registration site, not by env. Two
  failure classes with different strictness: log *writes* are swallowed (never
  block); log *config* (flags) is validated strictly → `failLoud`. Journal sink is
  stdlib `log/syslog` (no new dependency). See DESIGN.md "Logging non-allowed
  commands".
- **`journal_unix.go` / `journal_other.go`** — the `writeJournal` sink, split by
  build tag because `log/syslog` is Unix-only. `_unix` (`!windows && !plan9`) uses
  syslog; `_other` is a stub that errors so Windows/Plan9 still build (the file
  sink works there, `journal` drops, `auto` falls back to file). Keep the binary
  portable — `log.go` itself imports nothing OS-restricted.
- **`event.go`** — tolerant JSON decode of the PreToolUse payload into
  `event`/`toolInput`, plus `unknownFields` for drift reporting. Only `command` is
  read; every other field is enumerated as an ignored `json.RawMessage`, and the
  known-field sets are derived from those struct tags by reflection — so the
  struct is the single source of truth. Name-drift is reported as `schema_drift`
  and ignored; type-drift on ignored fields stays quiet. **Never reintroduce
  `DisallowUnknownFields`**: `PreToolUse` exit 2 blocks the tool, so rejecting a
  harmless new harness field takes the whole Bash tool down (it did, repeatedly —
  see DESIGN.md "Defensive JSON contract").
- **`classify.go`** — the shell-AST walk. `classifyCommand` parses with
  `mvdan.cc/sh/v3/syntax`, then recurses: `&&`/`||`/pipe/`(subshell)` recurse,
  every other compound kind is rejected, an unknown AST node calls `failLoud`.
  `wordLiteral` rejects any word with expansion (`$VAR`, `$(...)`, `<(...)`, …).
  `argTokens` then classifies each operand as a literal or — the one allowed
  expansion — a quoted `"$(...)"` command substitution whose inner command
  classifies read-only (`wordQuotedSubst`/`classifyCmdSubst`); that token reaches a
  spec only as an opaque positional, only for an `ArgvDataSafe` command. The
  command name must stay literal. `safeRedirect` allows reads and writes only to
  `/dev/null`.
- **`spec.go`** — `commandSpec` + the five `flagStyle` matchers (`matchGNU`,
  `matchFind`, `matchWrapper`, `matchXargs`, `matchAwk`). This is the
  flag/subcommand/positional engine; the data it runs on lives in `commands.go`.
  `matchXargs` is the odd one out: no `--` separator (the first non-flag token is
  the wrapped command) and it recurses via `classifyWrapped`, which only accepts a
  command whose spec sets `ArgvDataSafe` — see the privacy/safety note below and
  DESIGN.md's "styleXargs and the stdin-argv hazard". The matchers take
  `[]argToken` (literal-or-substituted), so a `"$(...)"` operand reaches a spec
  only as an opaque positional, gated by the same `ArgvDataSafe` flag.
- **`commands.go`** — the actual whitelist data: `safeCommands` maps each command
  name to a `commandSpec`. This is where you add/extend allowed commands. The
  `ArgvDataSafe` flag on a spec marks a command safe to receive an attacker-
  controlled argv token (from `xargs` stdin or a `$(...)` substitution); it is the
  single source of truth for that — no parallel list — set only on leaf readers
  with no write path under any argv.
- **`awk.go`** — `classifyAwkProgram` walks an awk program's AST (via the goawk
  fork) for `styleAwk`, positively whitelisting nodes/builtins.

The safety argument is structural: the hook only ever *adds* an `allow`. A bug
can at worst fail to accelerate; it can never wave through something the normal
permission flow would have stopped. Preserve that asymmetry.

## Build / test

```bash
nix develop          # dev shell: go, gopls, gotools, delve, go-licenses
go test ./...        # the classifier corpus (TestMustAllow / TestMustNotAllow / TestEventDecode*)
go test -run TestMustNotAllow ./...   # a single test function
nix flake check      # runs 2 checks: the corpus (checks.tests) AND a permissive-
                     # license guard (checks.licenses, go-licenses check) — MUST pass
nix build            # build the binary as a Nix derivation -> ./result/bin/classify-bash
./scripts/gen-third-party-licenses.sh  # regenerate THIRD_PARTY_LICENSES (in nix develop)
```

`checks.licenses` fails if any linked dependency carries a non-permissive
(e.g. copyleft) license. `THIRD_PARTY_LICENSES` reproduces the bundled deps'
notices for binary redistribution; it is generated, not hand-edited — rerun the
script above when dependencies change.

The test corpus is the spec: `TestMustAllow` (forms that must classify allow),
`TestMustNotAllow` (the safety wall — unsafe forms that must fall through),
`TestNotYetAllowed` (forms that are harmless *as written* but fall through only
because a classifier feature isn't built — a regression here is a feature landing,
not an incident), and `TestEventDecode*` (the JSON contract). Each case is a bare
command string in a table — add to the right table, don't write new test
functions. A new fall-through case goes in `TestMustNotAllow` *unless* you can show
it is genuinely harmless, in which case it goes in `TestNotYetAllowed`. See
FUTURE-WORK.md "Two kinds of must not allow".

## Version control: this is a jj repo, not git

The working copy is managed by **jujutsu (`jj`)** — there is a `.jj/` directory and
**no `.git/`**. `git` commands will not work here. Equivalents:

- jj auto-snapshots the working copy on every `jj` command, so a newly-created
  `.go` file is tracked as soon as you run any `jj` command (or `jj status`) — no
  explicit `add` step. This matters because **`nix build`/`nix flake check` use a
  VCS-aware source: an unsnapshotted new file is invisible and the build fails
  `undefined: <symbol>`.** Run a `jj` command (or `jj st`) after creating a file,
  before building.
- The CRLF-repair loop in older notes (`git ls-files | sed …`) becomes
  `jj file list` instead of `git ls-files`.
- The same auto-snapshot catches **build artifacts**: a `nix build` leaves a
  `result` symlink into `/nix/store`, which jj will snapshot and try to commit if
  it isn't ignored. `/result` is in `.gitignore` for exactly this reason — keep it
  there, and check `jj st` before committing so a stray `A result` (or other
  artifact) doesn't ride along.
- To land a change on the remote: `jj commit -m "…"`, then move the bookmark with
  `jj bookmark set master -r @-`, then `jj git push --bookmark master`. (No AI
  attribution in the message; see Conventions.)

(DESIGN.md's "Build gotcha" calls out the jj-vs-git split explicitly; the
published upstream is consumed as a `git+ssh` flake input, but local dev here is
jj.)

## Conventions

- **Strict positive whitelist** in `commands.go`: enumerate every command /
  subcommand / flag; unknown → fall through. Never "allow X except Y". When
  extending, follow the checklist in README "Extending the whitelist" and add
  `mustAllow` cases plus the matching wall (`mustNotAllow`) / deferred-safe
  (`TestNotYetAllowed`) cases.
- **A flag whose value is a program is an exec path** — however read-only the
  command looks. Enumerating flag *names* says nothing about what a *value*
  means, and this is where the whitelist has actually been wrong: `jj --tool`
  and `sort --compress-program` (value is a program), `nix eval --expr/--file`
  (value is evaluated — reads files, reaches the network), `jj --config` (value
  sets `ui.pager`, which the read-only subcommands spawn). All were shipped, not
  hypothetical. When adding any command, walk every `TakesArg` flag and ask what
  the value *is*; when in doubt, point it at a marker script and look. Note
  inertness is not safety (`--config-toml` was harmless only because jj 0.41
  dropped the name), and say in the comment whether an exclusion is a
  demonstrated exec path or merely no logged demand. See DESIGN.md "Flag values
  that are programs" and README "Extending the whitelist" step 2.
- **`ArgvDataSafe` is the one gate for attacker-controlled argv.** A command may
  receive an unseen operand (from `xargs` stdin or a `$(...)` substitution) only if
  its spec sets `ArgvDataSafe` — true only when it has no write/exec/network path
  under *any* argv, flag-shaped values included. It is a field on `commandSpec`, not
  a separate list; do not reintroduce a parallel set.
- **`AllowAnyPositional` is free; `ArgvDataSafe` + a flag-reachable side effect is
  the trap.** Since §8, `matchGNU` validates flags by getopt *permutation* — even
  after a positional — so a reader whose write/exec/network path is a flag
  (`gh repo view --web`, `journalctl --vacuum-size`) can set `AllowAnyPositional`
  safely; the unwhitelisted flag is rejected wherever it lands. The exception is
  `ArgvDataSafe`: such a command keeps the fast path (first positional closes flag
  parsing, rest is opaque data, so `cat file -X` allows `-X` as data), which is only
  sound when it has no flag-reachable side effect at all. So never set `ArgvDataSafe`
  on a spec with such a path. See README "Extending the whitelist" and `matchGNU`.
- **Tolerant JSON decoder** (`event.go`). When the harness starts sending a new
  field on the event or inside `tool_input`, classification proceeds and a
  `schema_drift` record names it. Enumerate it as an ignored `json.RawMessage` on
  the right struct (`event` for top-level, `toolInput` for a `tool_input` field) +
  an accept-test to silence it. Do NOT make this strict again — see DESIGN.md.
- **Fail loud on the unknown, but only where nothing upstream can trigger it**: an
  unrecognized `mvdan/sh` AST node, redirect op, or flag style calls `failLoud`
  (exit 2) rather than guessing — we'd rather block than ship a stale classifier.
  Keep new `switch` defaults loud. Harness-driven input is the opposite case: it
  fails open, because there we cannot afford to block.
- **LF line endings** enforced via `.gitattributes` (`*.go`/`*.nix`/`*.md`). CRLF
  breaks the inline shell in `flake.nix`'s checks.
- No AI attribution in commit messages.

## Privacy invariant

This repo is **PUBLIC** (since 2026-06-09, at
`github.com/shabbir-genetech/classify-bash`); its history was scrubbed before the
flip. It stays clean going forward: do **not** commit genuinely-internal
identifiers (real home paths, internal project codenames, work email/domain). The
`shabbir-genetech` handle is **not** secret — it is the publishing account (and the
public goawk fork's owner), so it is fine in `go.mod`, docs, and the module path.
The pre-publication leak gate (a fresh-clone history scan for real home paths,
emails, and author identity) passed on 2026-06-09; re-run that scan if the history
is ever rewritten.

## How it's deployed

The binary is installed onto `$PATH` and registered by bare name `classify-bash`
in `~/.claude/settings.json`. One known consumer is an external NixOS config that
pulls this repo as a `git+ssh` flake input — so **a change here only reaches that
consumer after a commit + push**, then the consumer re-locks
(`nix flake lock --update-input classify-bash`) and rebuilds. A long-lived
`claude` session picks up the rebuilt hook on its next tool call.
