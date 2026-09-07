# classify-bash

A Claude Code PreToolUse hook for the `Bash` tool. Reads a single hook event
on stdin, parses the embedded shell command with `mvdan.cc/sh/v3/syntax`, and
emits an `allow` permission decision **only** when the command matches a
strict whitelist of read-only forms.

## Design

- **Allow-only.** The hook never emits `deny` or `ask`. Unsafe or
  unclassifiable commands fall through (exit 0 with no stdout) to Claude
  Code's normal permission prompt. We accelerate, we do not gate.
  These non-allowed cases can optionally be logged — see [Logging](#logging-opt-in).
- **Strict whitelist.** Every command, subcommand, and flag is enumerated
  positively in `commands.go`. Unknown command, unknown subcommand, or
  unknown flag on a known command → fall through. We never write
  "allow X except when Y" because a future release may introduce a Z we
  did not anticipate.
- **Defensive contract, but never at the cost of blocking.** The event must
  declare `hook_event_name == "PreToolUse"` and `tool_name == "Bash"` and carry a
  non-empty command; anything else **falls through** (exit 0, empty stdout) and is
  recorded as an `undecodable` log line. **Unknown fields are tolerated** — a
  field the harness adds after this binary was built is recorded as
  `schema_drift` and ignored, never rejected. An unrecognized `mvdan/sh` AST node
  kind is the one remaining loud failure (exit 2): there we would rather block
  than silently ship a stale classifier.

## Failure modes

| Situation                                           | Exit | Stdout      | Stderr                          |
| --------------------------------------------------- | ---- | ----------- | ------------------------------- |
| Command matches the whitelist                       | 0    | allow JSON  | empty                           |
| Command is unsafe, unknown, or has an unknown flag  | 0    | empty       | empty                           |
| Bash parser refuses the input                       | 0    | empty       | empty                           |
| Unknown field in the event                          | 0    | as normal   | empty (logged as `schema_drift`)|
| Undecodable / wrong event / empty command           | 0    | empty       | empty (logged as `undecodable`) |
| Bad `--log-*` flag                                  | 2    | empty       | `classify-bash: bad flag: ...`  |
| Unknown `mvdan/sh` AST node kind                    | 2    | empty       | `classify-bash: unknown ...`    |

## Logging (opt-in)

Off by default — the hook stays silent on fall-through. When enabled with `--log`,
every **non-allowed** command is recorded as one best-effort JSON line, as are the
`undecodable`, `schema_drift` and `failloud` cases. Allowed commands are never
logged. Logging can only fail to record — it never changes the decision and never
blocks a call.

Because unknown fields no longer block, `schema_drift` records are how you learn
the harness changed shape: enumerate the reported field on the struct in
`event.go` to silence it.

| Flag         | Default                              | Meaning                                                                       |
| ------------ | ------------------------------------ | ----------------------------------------------------------------------------- |
| `--log`      | off                                  | enable logging                                                                |
| `--log-to`   | `auto`                               | `auto` (journal if reachable, else file), `journal` (strict), or `file`       |
| `--log-file` | `$XDG_STATE_HOME/classify-bash/log`  | file path for `file`, and the `auto` fallback (then `~/.local/state/...`)      |

Each record is one line:

```json
{"ts":"2026-…Z","kind":"fallthrough","command":"rm -rf /tmp/x"}
{"ts":"2026-…Z","kind":"schema_drift","command":"","reason":"surprise"}
{"ts":"2026-…Z","kind":"undecodable","command":"","reason":"decode stdin: unexpected end of JSON input"}
```

`reason` appears for every kind except `fallthrough`; `orig_len` (original byte length)
appears only when the command was truncated (4 KB cap). On systemd the journal
sink lands in journald via `/dev/log` — query `journalctl -t classify-bash` and
grep the message. The journal sink is **Linux/macOS only** (it uses `log/syslog`);
on Windows/Plan9 it is unavailable, so `auto` uses the file and `journal` drops.

**Strictness is split by failure class:** log *writes* are best-effort (every
error swallowed), but log *config* is validated strictly — a bad flag exits 2 and
blocks the call, the same posture as the JSON decoder. So `--log-to=typo` will
stop every Bash call until fixed; this is intentional (you hear about a
misconfigured logger immediately rather than silently not logging). See DESIGN.md.

**Privacy:** records are the literal commands, verbatim. The default path is under
`$XDG_STATE_HOME`/`$HOME` (resolved at runtime, never hardcoded). On a shared or
recorded host, treat the log as containing whatever Claude tried to run, and scope
its location and retention accordingly.

## Build and test

The sub-flake exposes a Go-aware dev shell and a buildGoModule package.

```bash
# Dev shell with go, gopls, gotools, delve.
nix develop

# Inside the shell:
go mod tidy
go test ./...

# Build the binary as a Nix derivation:
nix build

# Run the test corpus via `nix flake check`:
nix flake check
```

`nix flake check` runs two checks: the test corpus and a `go-licenses` guard that
fails on any non-permissive dependency license. `THIRD_PARTY_LICENSES` — generated
by `scripts/gen-third-party-licenses.sh` — reproduces the bundled dependencies'
notices (goawk/MIT, mvdan/sh/BSD-3-Clause) for **binary** redistribution.

### Without Nix

It is a plain Go module — no Nix required to build or install:

```bash
# Install the latest published version straight onto $PATH:
go install github.com/shabbir-genetech/classify-bash@latest

# Or from a checkout:
go build -o classify-bash .   # or: go install .
go test ./...
```

Put the resulting binary on `$PATH` and register it the same way (see
[Registration](#registration)). Two notes:

- **The goawk dependency is a `replace`-pinned fork** (it re-exports goawk AST
  types `styleAwk` needs). The fork is **public**
  (`github.com/shabbir-genetech/goawk`), so `go build`/`go install` resolves it via
  the module proxy with no extra setup.
- **Platform support: Linux and macOS.** Windows/Plan9 build too, but the
  **journal** sink is unavailable there (it uses `log/syslog`, which those
  platforms lack), so `--log-to=journal` is a no-op and `--log-to=auto` always
  uses the file. The journal proper needs systemd (Linux). For a fully static
  binary, `CGO_ENABLED=0 go build` (the journal sink imports `net`).

## Manual smoke test

```bash
./result/bin/classify-bash <<<'{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls -la"}}'
# -> {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}

./result/bin/classify-bash <<<'{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/x"}}'
# -> (no output, exit 0)

# An unknown field does not disturb classification; it is logged as schema_drift.
./result/bin/classify-bash <<<'{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"},"surprise":true}'
# -> {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}
```

Logging is off by default. Enable it (here to a file) and a non-allowed command is
recorded as one JSON line; allowed commands are not:

```bash
./result/bin/classify-bash --log --log-to=file --log-file=/tmp/cb.log \
  <<<'{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/x"}}'
cat /tmp/cb.log
# -> {"ts":"…Z","kind":"fallthrough","command":"rm -rf /tmp/x"}

# A bad flag is the one strict config path — it exits 2 and blocks the call.
# (Operator error at the registration site; nothing upstream can cause it.)
./result/bin/classify-bash --log --log-to=banana <<<'…'
# -> classify-bash: bad flag: unknown --log-to "banana" (want auto, journal, or file)
# -> (exit 2)
```

With `--log-to=auto` on a systemd host (a live `/dev/log`), records go to the
journal instead of the file — read them with `journalctl -t classify-bash`.

## Registration

Once the binary is on `$PATH`, add this to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "classify-bash"}
        ]
      }
    ]
  }
}
```

To turn on the audit log (see [Logging](#logging-opt-in)), pass the flags in the
command, e.g. `"command": "classify-bash --log --log-to=auto"`.

## Extending the whitelist

1. Audit ALL flags in the manpage for the command you want to add. Pick the
   ones that cannot mutate state.
2. **For every flag that takes a value, ask what the value *is*.** "Read-only
   command" is not enough — a reader can hand its argument to `execve`. Reject
   any flag whose value is:
   - **a program name or path** — `jj --tool`, `sort --compress-program`,
     `rg --pre`, `git -c core.pager=…`, `--exec`/`--editor`/`--pager`/`--filter`
     shapes generally;
   - **text the tool will evaluate** — `nix eval --expr`/`--file`/`--apply`
     (Nix reads files and reaches the network), any `--eval`/`--script` shape;
   - **a config key/file that can set either of the above** — `jj --config`
     sets `ui.pager`, which the read-only subcommands then spawn.

   Each of these was found *shipped* in this whitelist, not hypothesised. The
   rule: **a flag whose value is a program — or a program text the tool will
   evaluate — is an exec path however read-only the subcommand looks.** When in
   doubt, run the command with the flag pointed at a script that touches a
   marker file, and check whether the marker appears.
3. Add a `commandSpec` entry in `commands.go` enumerating those flags
   positively. Document any deliberately-excluded flags in a comment so
   future reviewers see that they were considered — and say *which* kind of
   exclusion it is: a demonstrated exec/write path, or merely no logged demand.
   Conflating the two makes the next reader distrust the whole list.
4. Add `TestMustAllow` cases for the new safe forms and `TestMustNotAllow` cases
   for each known write-mode flag, each exec-path flag from step 2, plus an
   `--unknown-flag` form. If you implement a deferred feature (e.g. a new flag
   style), also move the now-supported cases out of `TestNotYetAllowed` into
   `TestMustAllow`.
5. `nix flake check` must pass before the change can be trusted.

To also let a command receive an **attacker-controlled argv token** — be
**wrappable by `xargs`** *and* accept a `"$(...)"` command-substitution operand —
set `ArgvDataSafe: true` on its spec in `commands.go`. Only do so if it clears a
*stronger* bar than the whitelist itself: it must have **no write/mutate path under
any argv at all** (because xargs appends stdin items, and `$(...)` injects an
operand value, that the classifier never sees). A command whose spec merely
*excludes* a write flag (e.g. `sort`'s `-o`, `date`'s `-s`) does **not** qualify —
the injected token could supply that flag. Add a `mustAllow` `xargs <cmd> …` (and/or
`<cmd> "$(…)"`) case plus the matching `mustNotAllow`. `ArgvDataSafe` is the single
source of truth — no parallel list. See "Flag styles" (`styleXargs`) and DESIGN.md.

**`AllowAnyPositional: true`** lets a command take free positional arguments. Since
§8, `matchGNU` validates flags by GNU getopt *permutation* — a flag-shaped token is
checked against the spec **even after a positional** — so a reader whose
write/exec/network path is a *flag* (`gh repo view --web`, `journalctl
--vacuum-size`) can safely set `AllowAnyPositional`: the unwhitelisted flag is
rejected wherever it lands. The one rule that still bites: such a command must
**not** also be `ArgvDataSafe`, because an `ArgvDataSafe` command keeps the fast
path (its first positional closes flag parsing and the rest is opaque data, so
`cat file -X` allows `-X` as data). That fast path is correct only when the command
has no flag-reachable side effect at all — which is exactly what `ArgvDataSafe`
already asserts. So: `AllowAnyPositional` is free to set; just never pair
`ArgvDataSafe` with a spec that has any flag-reachable write/exec path. See
FUTURE-WORK.md §5/§8 and `matchGNU`.

**`DashValueOK: true`** (on an `OptionalArg` flag) lets that flag consume one
following token that *starts with a dash*, but only when the token is a bare
signed integer (`^[+-][0-9]+$`). It exists for `journalctl -b -1` ("the boot
before last"), where the documented value is a ±offset and so collides with flag
syntax. Note `journalctl -b 0` and `-b all` never needed it — a non-dash value is
already swallowed by `AllowAnyPositional`; only dash-prefixed values were
rejected. The digits-only restriction is what keeps it safe: it can never consume
a real flag, so `journalctl -b --vacuum-size=1G` still falls through. Do not set
it on a `TakesArg` flag (there the value is consumed unconditionally already),
and do not widen it to non-numeric values without re-deriving that argument.

## Flag styles

- **`styleGNU`** (default): standard `-x`/`--name`/`--name=value`/clustered
  shorts. Used by most commands and all `Subcommands` dispatch.
- **`styleFind`**: every flag is `-name` form (single dash, full word), no
  clustering, no `=value`. Used by `find(1)`.
- **`styleWrapper`**: transparent wrapper for `[flag…] [positional…] -- CMD
  [ARG…]`. The literal `--` is REQUIRED — without it, the spec falls through
  (this is what makes `devenv shell` distinct from `devenv shell -- CMD`). The
  tail after `--` is looked up in `safeCommands` and matched recursively, so
  the wrapped command's whitelist rules apply unchanged. Pre-`--` positionals
  are accepted iff `AllowAnyPositional` is true (used for `nix shell PKGS --`).
- **`styleXargs`**: stdin-append wrapper `xargs [flag…] CMD [INITIAL-ARG…]`.
  Unlike `styleWrapper` there is **no `--` separator** — the first non-flag token
  is the wrapped command. The command is accepted only if its spec is
  **`ArgvDataSafe`** (in `commands.go`), not merely in the whitelist, and its
  initial-arguments are matched recursively. The gate matters because xargs
  appends stdin items to the wrapped argv that we never see, so only commands
  with no write path under *any* argv are wrappable (see "Flag styles" rationale
  in DESIGN.md). The replace-mode flags `-I`/`-i`/`--replace` are not
  whitelisted, so `xargs -I{} sh -c …` falls through.
- **`styleAwk`**: awk-shape command line `[flag…] PROGRAM [files…]` where the
  script itself is classified by walking the goawk AST (`awk.go`). Allowed
  pre-program flags are short-only and take values (`-F sep`, `-v var=val`);
  the first non-flag positional is the awk program, parsed via
  `github.com/benhoyt/goawk/parser` and accepted only when every node passes
  the positive whitelist below. Trailing positionals are input files.
  The `-f script.awk` script-load form, the `-e prog` multi-program form, and
  gawk extensions (`-i`, `-l`, `--long-flags`) are deliberately not in v1.
  Inside the awk program:
    - `print`/`printf` with any redirection (`>`, `>>`, `|`) → reject
    - `getline` from a pipe or a file → reject
    - `system(...)` (and other builtins not on the allowlist: `close`,
      `fflush`) → reject
    - User-defined functions (definition or call) → reject
    - Everything else (field/var refs, arithmetic, string ops, control flow,
      `length`/`substr`/`sprintf`/`gsub`/`split`/...) → recurse and accept

### Deferred wrapper shapes

These are useful but each needs its own style/handling — bundling them with v1
would obscure the design.

- **Flag-introduced** (`nix develop -c CMD`, `xargs -I{} CMD …`) — needs a
  `WrapFlag` variant naming which flag introduces the wrapped command. (Plain
  `xargs CMD` is handled by `styleXargs`; only the replace-mode `-I{}` form,
  which inserts the stdin item mid-argv, remains deferred.)
- **Inline** (`env VAR=val CMD`, `nice CMD`, `nice -n 10 CMD`) — first
  non-flag positional starts the wrapped command, no `--` required.
- **AST-level** (`time CMD`) — bash parses `time` as `TimeClause`, currently
  rejected in `classifyCmd`. Would add a recursive case there.
