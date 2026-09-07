// classify-bash classifies a shell command against a strict whitelist of
// read-only commands and flags, so an agent CLI can skip its permission prompt
// for commands that cannot have a side effect.
//
// The classifier is host-agnostic and is reached through `check`. Host wire
// formats live behind subcommands: `hook` speaks Claude Code's PreToolUse
// protocol; pi and oh-my-pi are integrated through extension shims that call
// `check` (see share/classify-bash/*.ts in the installed package).
//
// The invariant the whole design rests on: this program only ever ADDS an
// allow. A bug in it can at worst fail to accelerate, never block. Concretely,
// exit 2 blocks a PreToolUse call, so exit 2 is reserved for the two things
// nothing upstream can trigger — a bad flag at the registration site, and a
// strictness policy the operator explicitly asked to be loud about.
package main

import (
	"fmt"
	"os"
)

func main() {
	args := os.Args[1:]

	if len(args) > 0 {
		switch args[0] {
		case "check":
			os.Exit(runCheck(args[1:]))
		case "hook":
			os.Exit(runHook(args[1:], false))
		case "doctor":
			os.Exit(runDoctor(args[1:]))
		case "-h", "--help", "help":
			usage(os.Stdout)
			os.Exit(0)
		}
	}

	// No recognised subcommand. If this looks like the pre-subcommand hook
	// registration, honour it rather than failing — see looksLikeLegacyHook.
	if looksLikeLegacyHook(args) {
		os.Exit(runHook(args, true))
	}

	usage(os.Stderr)
	os.Exit(1)
}

func usage(w *os.File) {
	fmt.Fprint(w, `classify-bash — classify a shell command as read-only, or not

  classify-bash check '<command>'      classify one command from argv
  classify-bash check --stdin          classify the command read from stdin
      --json                           print {"class","reason"} on stdout
      --on-unknown-ast=fail|fallthrough
    exit 0 = read-only, 1 = not read-only, 2 = this binary is broken or misused

  classify-bash hook --mode=<mode>     run as a Claude Code PreToolUse hook
      --mode=claude-strict|claude-lenient
      --on-unknown-field=fail|log|ignore   (overrides --mode)
      --on-unknown-ast=fail|fallthrough    (overrides --mode)
      --log --log-to=auto|journal|file --log-file=PATH

  classify-bash doctor                 report schema drift and compatibility

Integrating another agent CLI means calling "check" from whatever that host
calls a pre-execution hook. The shipped pi and oh-my-pi shims are examples.
`)
}
