package engine

// safeCommands is the strict whitelist: every command, subcommand, and flag
// that classify-bash will accept. An entry here is a claim that this exact
// invocation cannot mutate disk, network, or process state.
//
// Adding a command:
//  1. Audit ALL its flags in the relevant manpage. Whitelist only those that
//     are read-only.
//  2. Never whitelist a command by saying "allow except when -X is present".
//     A future release may add -Y that is also unsafe. Enumerate positively.
//  3. Add mustAllow and mustNotAllow tests, including an --unknown-flag case
//     and one entry per known write/mutate flag for the command.
//
// Comments above each spec list any deliberately-excluded flags so a future
// reviewer can see "this was considered and rejected" rather than "forgotten".
var safeCommands = map[string]*commandSpec{
	// === Tier A: no-subcommand reads =====================================

	// cat: no write flags exist in GNU coreutils.
	"cat": {
		ArgvDataSafe: true,
		Style:        styleGNU,
		Flags: []flagSpec{
			{Short: "A", Long: "show-all"},
			{Short: "b", Long: "number-nonblank"},
			{Short: "e"},
			{Short: "E", Long: "show-ends"},
			{Short: "n", Long: "number"},
			{Short: "s", Long: "squeeze-blank"},
			{Short: "t"},
			{Short: "T", Long: "show-tabs"},
			{Short: "u"},
			{Short: "v", Long: "show-nonprinting"},
			{Long: "help"},
			{Long: "version"},
		},
		AllowAnyPositional: true,
	},

	// tac: reverse cat. Same shape, no writes.
	"tac": {
		ArgvDataSafe: true,
		Style:        styleGNU,
		Flags: []flagSpec{
			{Short: "b", Long: "before"},
			{Short: "r", Long: "regex"},
			{Short: "s", Long: "separator", TakesArg: true},
			{Long: "help"},
			{Long: "version"},
		},
		AllowAnyPositional: true,
	},

	// nl: number lines.
	"nl": {
		ArgvDataSafe: true,
		Style:        styleGNU,
		Flags: []flagSpec{
			{Short: "b", Long: "body-numbering", TakesArg: true},
			{Short: "d", Long: "section-delimiter", TakesArg: true},
			{Short: "f", Long: "footer-numbering", TakesArg: true},
			{Short: "h", Long: "header-numbering", TakesArg: true},
			{Short: "i", Long: "line-increment", TakesArg: true},
			{Short: "l", Long: "join-blank-lines", TakesArg: true},
			{Short: "n", Long: "number-format", TakesArg: true},
			{Short: "p", Long: "no-renumber"},
			{Short: "s", Long: "number-separator", TakesArg: true},
			{Short: "v", Long: "starting-line-number", TakesArg: true},
			{Short: "w", Long: "number-width", TakesArg: true},
			{Long: "help"},
			{Long: "version"},
		},
		AllowAnyPositional: true,
	},

	// head: -c, -n take numeric values. No write flags.
	// Digits 0-9 added to support the deprecated `head -20 file` form (= -n 20).
	"head": {
		ArgvDataSafe: true,
		Style:        styleGNU,
		Flags: []flagSpec{
			{Short: "c", Long: "bytes", TakesArg: true},
			{Short: "n", Long: "lines", TakesArg: true},
			{Short: "q", Long: "quiet"},
			{Short: "v", Long: "verbose"},
			{Short: "z", Long: "zero-terminated"},
			{Short: "0"}, {Short: "1"}, {Short: "2"}, {Short: "3"}, {Short: "4"},
			{Short: "5"}, {Short: "6"}, {Short: "7"}, {Short: "8"}, {Short: "9"},
			{Long: "help"},
			{Long: "version"},
		},
		AllowAnyPositional: true,
	},

	// tail: -f (follow) is read-only despite holding the file open.
	// Digits 0-9 added to support the deprecated `tail -20 file` form.
	"tail": {
		ArgvDataSafe: true,
		Style:        styleGNU,
		Flags: []flagSpec{
			{Short: "c", Long: "bytes", TakesArg: true},
			{Short: "f", Long: "follow"},
			{Short: "F"},
			{Short: "n", Long: "lines", TakesArg: true},
			{Short: "q", Long: "quiet"},
			{Short: "s", Long: "sleep-interval", TakesArg: true},
			{Short: "v", Long: "verbose"},
			{Short: "z", Long: "zero-terminated"},
			{Short: "0"}, {Short: "1"}, {Short: "2"}, {Short: "3"}, {Short: "4"},
			{Short: "5"}, {Short: "6"}, {Short: "7"}, {Short: "8"}, {Short: "9"},
			{Long: "max-unchanged-stats", TakesArg: true},
			{Long: "pid", TakesArg: true},
			{Long: "retry"},
			{Long: "help"},
			{Long: "version"},
		},
		AllowAnyPositional: true,
	},

	// wc: pure read.
	"wc": {
		ArgvDataSafe: true,
		Style:        styleGNU,
		Flags: []flagSpec{
			{Short: "c", Long: "bytes"},
			{Short: "m", Long: "chars"},
			{Short: "l", Long: "lines"},
			{Short: "L", Long: "max-line-length"},
			{Short: "w", Long: "words"},
			{Long: "files0-from", TakesArg: true},
			{Long: "help"},
			{Long: "version"},
		},
		AllowAnyPositional: true,
	},

	// ls: large flag surface, all read-only. Common letters enumerated; less
	// common letters intentionally omitted so future additions don't slip in.
	"ls": {
		ArgvDataSafe: true,
		Style:        styleGNU,
		Flags: []flagSpec{
			{Short: "a", Long: "all"},
			{Short: "A", Long: "almost-all"},
			{Short: "b", Long: "escape"},
			{Short: "B", Long: "ignore-backups"},
			{Short: "c"},
			{Short: "C"},
			{Short: "d", Long: "directory"},
			{Short: "f"},
			{Short: "F", Long: "classify"},
			{Short: "g"},
			{Short: "G", Long: "no-group"},
			{Short: "h", Long: "human-readable"},
			{Short: "H", Long: "dereference-command-line"},
			{Short: "i", Long: "inode"},
			{Short: "k", Long: "kibibytes"},
			{Short: "l"},
			{Short: "L", Long: "dereference"},
			{Short: "m"},
			{Short: "n", Long: "numeric-uid-gid"},
			{Short: "N", Long: "literal"},
			{Short: "o"},
			{Short: "p"},
			{Short: "q", Long: "hide-control-chars"},
			{Short: "Q", Long: "quote-name"},
			{Short: "r", Long: "reverse"},
			{Short: "R", Long: "recursive"},
			{Short: "s", Long: "size"},
			{Short: "S"},
			{Short: "t"},
			{Short: "T", Long: "tabsize", TakesArg: true},
			{Short: "u"},
			{Short: "U"},
			{Short: "v"},
			{Short: "w", Long: "width", TakesArg: true},
			{Short: "x"},
			{Short: "X"},
			{Short: "Z", Long: "context"},
			{Short: "1"},
			{Long: "block-size", TakesArg: true},
			{Long: "color", OptionalArg: true}, // --color or --color=auto/always/never
			{Long: "hyperlink", OptionalArg: true},
			{Long: "format", TakesArg: true},
			{Long: "full-time"},
			{Long: "group-directories-first"},
			{Long: "hide", TakesArg: true},
			{Long: "indicator-style", TakesArg: true},
			{Long: "ignore", TakesArg: true},
			{Long: "quoting-style", TakesArg: true},
			{Long: "show-control-chars"},
			{Long: "si"},
			{Long: "sort", TakesArg: true},
			{Long: "time", TakesArg: true},
			{Long: "time-style", TakesArg: true},
			{Long: "tabsize", TakesArg: true},
			{Long: "help"},
			{Long: "version"},
		},
		AllowAnyPositional: true,
	},

	// tree: read-only directory walker. No write flags.
	"tree": {
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "a"},
			{Short: "d"},
			{Short: "l"},
			{Short: "f"},
			{Short: "x"},
			{Short: "L", TakesArg: true},
			{Short: "R"},
			{Short: "P", TakesArg: true},
			{Short: "I", TakesArg: true},
			{Short: "C"},
			{Short: "n"},
			{Short: "p"},
			{Short: "s"},
			{Short: "u"},
			{Short: "g"},
			{Short: "D"},
			{Short: "F"},
			{Short: "q"},
			{Short: "N"},
			{Short: "Q"},
			{Short: "i"},
			{Short: "h"},
			{Short: "t"},
			{Short: "r"},
			{Short: "c"},
			{Short: "U"},
			{Long: "noreport"},
			{Long: "charset", TakesArg: true},
			{Long: "filelimit", TakesArg: true},
			{Long: "dirsfirst"},
			{Long: "sort", TakesArg: true},
			{Long: "inodes"},
			{Long: "device"},
			{Long: "du"},
			{Long: "si"},
			{Long: "help"},
			{Long: "version"},
		},
		AllowAnyPositional: true,
	},

	// du: disk usage. Read-only.
	"du": {
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "0", Long: "null"},
			{Short: "a", Long: "all"},
			{Short: "b", Long: "bytes"},
			{Short: "B", Long: "block-size", TakesArg: true},
			{Short: "c", Long: "total"},
			{Short: "d", Long: "max-depth", TakesArg: true},
			{Short: "D", Long: "dereference-args"},
			{Short: "h", Long: "human-readable"},
			{Short: "H"},
			{Short: "k"},
			{Short: "L", Long: "dereference"},
			{Short: "l", Long: "count-links"},
			{Short: "m"},
			{Short: "P", Long: "no-dereference"},
			{Short: "s", Long: "summarize"},
			{Short: "S", Long: "separate-dirs"},
			{Short: "t", Long: "threshold", TakesArg: true},
			{Short: "x", Long: "one-file-system"},
			{Short: "X", Long: "exclude-from", TakesArg: true},
			{Long: "apparent-size"},
			{Long: "exclude", TakesArg: true},
			{Long: "files0-from", TakesArg: true},
			{Long: "inodes"},
			{Long: "si"},
			{Long: "time"},
			{Long: "time-style", TakesArg: true},
			{Long: "help"},
			{Long: "version"},
		},
		AllowAnyPositional: true,
	},

	// df: disk free. Pure read.
	"df": {
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "a", Long: "all"},
			{Short: "B", Long: "block-size", TakesArg: true},
			{Short: "h", Long: "human-readable"},
			{Short: "H", Long: "si"},
			{Short: "i", Long: "inodes"},
			{Short: "k"},
			{Short: "l", Long: "local"},
			{Short: "P", Long: "portability"},
			{Short: "t", Long: "type", TakesArg: true},
			{Short: "T", Long: "print-type"},
			{Short: "x", Long: "exclude-type", TakesArg: true},
			{Long: "no-sync"},
			{Long: "output"},
			{Long: "sync"},
			{Long: "total"},
			{Long: "help"},
			{Long: "version"},
		},
		AllowAnyPositional: true,
	},

	// stat: pure read.
	"stat": {
		ArgvDataSafe: true,
		Style:        styleGNU,
		Flags: []flagSpec{
			{Short: "L", Long: "dereference"},
			{Short: "f", Long: "file-system"},
			{Short: "c", Long: "format", TakesArg: true},
			{Short: "t", Long: "terse"},
			{Long: "cached", TakesArg: true},
			{Long: "printf", TakesArg: true},
			{Long: "help"},
			{Long: "version"},
		},
		AllowAnyPositional: true,
	},

	// file: identify file type. Read-only.
	"file": {
		ArgvDataSafe: true,
		Style:        styleGNU,
		Flags: []flagSpec{
			{Short: "b", Long: "brief"},
			{Short: "h", Long: "no-dereference"},
			{Short: "i", Long: "mime"},
			{Short: "k", Long: "keep-going"},
			{Short: "L", Long: "dereference"},
			{Short: "N", Long: "no-pad"},
			{Short: "n", Long: "no-buffer"},
			{Short: "p", Long: "preserve-date"},
			{Short: "r", Long: "raw"},
			{Short: "s", Long: "special-files"},
			{Short: "z", Long: "uncompress"},
			{Long: "mime-type"},
			{Long: "mime-encoding"},
			{Long: "extension"},
			{Long: "help"},
			{Long: "version"},
		},
		AllowAnyPositional: true,
	},

	// grep / egrep / fgrep: read-only. Same spec for all three.
	"grep":  grepSpec(),
	"egrep": grepSpec(),
	"fgrep": grepSpec(),

	// rg (ripgrep): read-only. -o is "only-matching" (output filter), not a write.
	"rg": {
		ArgvDataSafe: true,
		Style:        styleGNU,
		Flags: []flagSpec{
			{Short: "A", Long: "after-context", TakesArg: true},
			{Short: "B", Long: "before-context", TakesArg: true},
			{Short: "C", Long: "context", TakesArg: true},
			{Short: "c", Long: "count"},
			{Short: "e", Long: "regexp", TakesArg: true},
			{Short: "F", Long: "fixed-strings"},
			{Short: "f", Long: "file", TakesArg: true},
			{Short: "g", Long: "glob", TakesArg: true},
			{Short: "H", Long: "with-filename"},
			{Short: "h", Long: "no-filename"},
			{Short: "i", Long: "ignore-case"},
			{Short: "I"},
			{Short: "L", Long: "follow"},
			{Short: "l", Long: "files-with-matches"},
			{Short: "M", Long: "max-columns", TakesArg: true},
			{Short: "m", Long: "max-count", TakesArg: true},
			{Short: "N", Long: "no-line-number"},
			{Short: "n", Long: "line-number"},
			{Short: "o", Long: "only-matching"},
			{Short: "P", Long: "pcre2"},
			{Short: "p", Long: "pretty"},
			{Short: "q", Long: "quiet"},
			{Short: "r", Long: "replace", TakesArg: true},
			{Short: "S", Long: "smart-case"},
			{Short: "s", Long: "case-sensitive"},
			{Short: "T", Long: "type-not", TakesArg: true},
			{Short: "t", Long: "type", TakesArg: true},
			{Short: "U", Long: "multiline"},
			{Short: "u"},
			{Short: "V", Long: "version"},
			{Short: "v", Long: "invert-match"},
			{Short: "w", Long: "word-regexp"},
			{Short: "x", Long: "line-regexp"},
			{Short: "z", Long: "search-zip"},
			{Long: "color", TakesArg: true},
			{Long: "colors", TakesArg: true},
			{Long: "column"},
			{Long: "context-separator", TakesArg: true},
			{Long: "count-matches"},
			{Long: "encoding", TakesArg: true},
			{Long: "files"},
			{Long: "glob-case-insensitive"},
			{Long: "heading"},
			{Long: "hidden"},
			{Long: "iglob", TakesArg: true},
			{Long: "ignore-file", TakesArg: true},
			{Long: "json"},
			{Long: "line-buffered"},
			{Long: "max-depth", TakesArg: true},
			{Long: "max-filesize", TakesArg: true},
			{Long: "mmap"},
			{Long: "no-config"},
			{Long: "no-heading"},
			{Long: "no-hidden"},
			{Long: "no-ignore"},
			{Long: "no-ignore-vcs"},
			{Long: "no-messages"},
			{Long: "no-mmap"},
			{Long: "no-pcre2-unicode"},
			{Long: "null"},
			{Long: "null-data"},
			{Long: "passthru"},
			{Long: "path-separator", TakesArg: true},
			{Long: "regex-size-limit", TakesArg: true},
			{Long: "sort", TakesArg: true},
			{Long: "sortr", TakesArg: true},
			{Long: "stats"},
			{Long: "threads", TakesArg: true},
			{Long: "trim"},
			{Long: "type-list"},
			{Long: "vimgrep"},
			{Long: "help"},
		},
		AllowAnyPositional: true,
	},

	// sort: `-o FILE` writes; intentionally NOT in whitelist below. Similarly
	// `--output=FILE` is excluded. So `sort -o out.txt in.txt` falls through.
	"sort": {
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "b", Long: "ignore-leading-blanks"},
			{Short: "c", Long: "check"},
			{Short: "C"},
			{Short: "d", Long: "dictionary-order"},
			{Short: "f", Long: "ignore-case"},
			{Short: "g", Long: "general-numeric-sort"},
			{Short: "h", Long: "human-numeric-sort"},
			{Short: "i", Long: "ignore-nonprinting"},
			{Short: "k", Long: "key", TakesArg: true},
			{Short: "M", Long: "month-sort"},
			{Short: "m", Long: "merge"},
			{Short: "n", Long: "numeric-sort"},
			{Short: "R", Long: "random-sort"},
			{Short: "r", Long: "reverse"},
			{Short: "s", Long: "stable"},
			{Short: "S", Long: "buffer-size", TakesArg: true},
			{Short: "t", Long: "field-separator", TakesArg: true},
			{Short: "T", Long: "temporary-directory", TakesArg: true},
			{Short: "u", Long: "unique"},
			{Short: "V", Long: "version-sort"},
			{Short: "z", Long: "zero-terminated"},
			{Long: "batch-size", TakesArg: true},
			{Long: "debug"},
			{Long: "files0-from", TakesArg: true},
			{Long: "parallel", TakesArg: true},
			{Long: "random-source", TakesArg: true},
			{Long: "sort", TakesArg: true},
			{Long: "help"},
			{Long: "version"},
			// NOT whitelisted (write): -o, --output
			// NOT whitelisted (exec): --compress-program NAME names a program and
			// sort runs it for spill files (verified: it executed). Same shape as
			// jj's removed --tool — see jjCommonFlags(). Removed 2026-07-27.
			// --random-source is kept: sort only READS bytes from that file
			// (coreutils randread), it is never executed.
		},
		AllowAnyPositional: true,
	},

	// uniq: `uniq IN OUT` writes the second positional. We allow any positional
	// shape; redirection is caught structurally. The IN/OUT positional form is
	// dual-use; for v1 we accept it because users who want IN OUT can also use
	// `< in > out` which is already caught. (Note: this is the one place we
	// trade strictness for ergonomics; revisit if a real foot-gun emerges.)
	"uniq": {
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "c", Long: "count"},
			{Short: "d", Long: "repeated"},
			{Short: "D"},
			{Short: "f", Long: "skip-fields", TakesArg: true},
			{Short: "i", Long: "ignore-case"},
			{Short: "s", Long: "skip-chars", TakesArg: true},
			{Short: "u", Long: "unique"},
			{Short: "w", Long: "check-chars", TakesArg: true},
			{Short: "z", Long: "zero-terminated"},
			{Long: "all-repeated"},
			{Long: "group"},
			{Long: "help"},
			{Long: "version"},
		},
		AllowAnyPositional: true,
	},

	// cut: stdout only.
	"cut": {
		ArgvDataSafe: true,
		Style:        styleGNU,
		Flags: []flagSpec{
			{Short: "b", Long: "bytes", TakesArg: true},
			{Short: "c", Long: "characters", TakesArg: true},
			{Short: "d", Long: "delimiter", TakesArg: true},
			{Short: "f", Long: "fields", TakesArg: true},
			{Short: "n"},
			{Short: "s", Long: "only-delimited"},
			{Short: "z", Long: "zero-terminated"},
			{Long: "complement"},
			{Long: "output-delimiter", TakesArg: true},
			{Long: "help"},
			{Long: "version"},
		},
		AllowAnyPositional: true,
	},

	// tr: stdin -> stdout. No write flags.
	"tr": {
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "c", Long: "complement"},
			{Short: "C"},
			{Short: "d", Long: "delete"},
			{Short: "s", Long: "squeeze-repeats"},
			{Short: "t", Long: "truncate-set1"},
			{Long: "help"},
			{Long: "version"},
		},
		AllowAnyPositional: true,
	},

	// paste: merge lines from files/stdin side by side. stdin/files -> stdout.
	// No write flags (paste has no output-file option).
	"paste": {
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "d", Long: "delimiters", TakesArg: true},
			{Short: "s", Long: "serial"},
			{Short: "z", Long: "zero-terminated"},
			{Long: "help"},
			{Long: "version"},
		},
		AllowAnyPositional: true,
	},

	// column: format columns. stdout only.
	"column": {
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "c", Long: "output-width", TakesArg: true},
			{Short: "d", Long: "table-noheadings"},
			{Short: "E", Long: "table-noextreme", TakesArg: true},
			{Short: "e", Long: "table-header-repeat"},
			{Short: "H", Long: "table-hide", TakesArg: true},
			{Short: "i", Long: "input-separator", TakesArg: true},
			{Short: "J", Long: "json"},
			{Short: "l", Long: "table-columns-limit", TakesArg: true},
			{Short: "L", Long: "keep-empty-lines"},
			{Short: "N", Long: "table-columns", TakesArg: true},
			{Short: "n", Long: "table-name", TakesArg: true},
			{Short: "O", Long: "table-order", TakesArg: true},
			{Short: "o", Long: "output-separator", TakesArg: true},
			{Short: "p", Long: "keep-trailing-spaces"},
			{Short: "R", Long: "table-right", TakesArg: true},
			{Short: "r", Long: "tree", TakesArg: true},
			{Short: "s", Long: "separator", TakesArg: true},
			{Short: "T", Long: "tree-id", TakesArg: true},
			{Short: "t", Long: "table"},
			{Short: "W", Long: "table-wrap", TakesArg: true},
			{Short: "x", Long: "fillrows"},
			{Long: "tree-parent", TakesArg: true},
			{Long: "help"},
			{Long: "version"},
		},
		AllowAnyPositional: true,
	},

	// fold: stdout only.
	"fold": {
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "b", Long: "bytes"},
			{Short: "s", Long: "spaces"},
			{Short: "w", Long: "width", TakesArg: true},
			{Long: "help"},
			{Long: "version"},
		},
		AllowAnyPositional: true,
	},

	// expand: tabs to spaces. stdout only.
	"expand": {
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "i", Long: "initial"},
			{Short: "t", Long: "tabs", TakesArg: true},
			{Long: "help"},
			{Long: "version"},
		},
		AllowAnyPositional: true,
	},

	// Hash/encode commands: pure read.
	"md5sum":    hashSpec(),
	"sha1sum":   hashSpec(),
	"sha224sum": hashSpec(),
	"sha256sum": hashSpec(),
	"sha384sum": hashSpec(),
	"sha512sum": hashSpec(),
	"b2sum":     hashSpec(),
	"cksum": {
		ArgvDataSafe: true,
		Style:        styleGNU,
		Flags: []flagSpec{
			{Short: "a", TakesArg: true},
			{Long: "help"},
			{Long: "version"},
		},
		AllowAnyPositional: true,
	},
	"base64": {
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "d", Long: "decode"},
			{Short: "i", Long: "ignore-garbage"},
			{Short: "w", Long: "wrap", TakesArg: true},
			{Long: "help"},
			{Long: "version"},
		},
		AllowAnyPositional: true,
	},
	"xxd": {
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "a"},
			{Short: "b"},
			{Short: "c", TakesArg: true},
			{Short: "E"},
			{Short: "e"},
			{Short: "g", TakesArg: true},
			{Short: "h"},
			{Short: "i"},
			{Short: "l", TakesArg: true},
			{Short: "o", TakesArg: true},
			{Short: "p"},
			{Short: "P", TakesArg: true},
			{Short: "r"},
			{Short: "s", TakesArg: true},
			{Short: "u"},
			{Short: "v"},
		},
		AllowAnyPositional: true,
	},
	"od": {
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "A", Long: "address-radix", TakesArg: true},
			{Short: "j", Long: "skip-bytes", TakesArg: true},
			{Short: "N", Long: "read-bytes", TakesArg: true},
			{Short: "S", Long: "strings", TakesArg: true},
			{Short: "t", Long: "format", TakesArg: true},
			{Short: "v"},
			{Short: "w", Long: "width", TakesArg: true},
			{Short: "a"},
			{Short: "b"},
			{Short: "c"},
			{Short: "d"},
			{Short: "f"},
			{Short: "i"},
			{Short: "l"},
			{Short: "o"},
			{Short: "s"},
			{Short: "x"},
			{Long: "endian", TakesArg: true},
			{Long: "traditional"},
			{Long: "help"},
			{Long: "version"},
		},
		AllowAnyPositional: true,
	},
	"hexdump": {
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "b"},
			{Short: "C"},
			{Short: "c"},
			{Short: "d"},
			{Short: "e", TakesArg: true},
			{Short: "f", TakesArg: true},
			{Short: "L"},
			{Short: "n", TakesArg: true},
			{Short: "o"},
			{Short: "s", TakesArg: true},
			{Short: "v"},
			{Short: "x"},
			{Long: "help"},
			{Long: "version"},
		},
		AllowAnyPositional: true,
	},

	// Comparison: read-only.
	"diff": {
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "a", Long: "text"},
			{Short: "b", Long: "ignore-space-change"},
			{Short: "B", Long: "ignore-blank-lines"},
			{Short: "c"},
			{Short: "C", TakesArg: true},
			{Short: "d", Long: "minimal"},
			{Short: "E", Long: "ignore-tab-expansion"},
			{Short: "e", Long: "ed"},
			{Short: "F", TakesArg: true},
			{Short: "H", Long: "speed-large-files"},
			{Short: "i", Long: "ignore-case"},
			{Short: "l", Long: "paginate"},
			{Short: "n", Long: "rcs"},
			{Short: "N", Long: "new-file"},
			{Short: "p", Long: "show-c-function"},
			{Short: "P", Long: "unidirectional-new-file"},
			{Short: "q", Long: "brief"},
			{Short: "r", Long: "recursive"},
			{Short: "s", Long: "report-identical-files"},
			{Short: "S", Long: "starting-file", TakesArg: true},
			{Short: "t", Long: "expand-tabs"},
			{Short: "T", Long: "initial-tab"},
			{Short: "u"},
			{Short: "U", TakesArg: true},
			{Short: "w", Long: "ignore-all-space"},
			{Short: "W", Long: "width", TakesArg: true},
			{Short: "x", Long: "exclude", TakesArg: true},
			{Short: "X", Long: "exclude-from", TakesArg: true},
			{Short: "y", Long: "side-by-side"},
			{Short: "Z", Long: "ignore-trailing-space"},
			{Long: "color"},
			{Long: "color-mode", TakesArg: true},
			{Long: "context"},
			{Long: "from-file", TakesArg: true},
			{Long: "ignore-file-name-case"},
			{Long: "ignore-matching-lines", TakesArg: true},
			{Long: "label", TakesArg: true},
			{Long: "left-column"},
			{Long: "no-dereference"},
			{Long: "no-ignore-file-name-case"},
			{Long: "normal"},
			{Long: "palette", TakesArg: true},
			{Long: "strip-trailing-cr"},
			{Long: "suppress-blank-empty"},
			{Long: "suppress-common-lines"},
			{Long: "tabsize", TakesArg: true},
			{Long: "to-file", TakesArg: true},
			{Long: "unified"},
			{Long: "help"},
			{Long: "version"},
		},
		AllowAnyPositional: true,
	},
	"cmp": {
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "b", Long: "print-bytes"},
			{Short: "i", Long: "ignore-initial", TakesArg: true},
			{Short: "l", Long: "verbose"},
			{Short: "n", Long: "bytes", TakesArg: true},
			{Short: "s", Long: "silent"},
			{Long: "print-chars"},
			{Long: "quiet"},
			{Long: "help"},
			{Long: "version"},
		},
		AllowAnyPositional: true,
	},
	"comm": {
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "1"},
			{Short: "2"},
			{Short: "3"},
			{Long: "check-order"},
			{Long: "nocheck-order"},
			{Long: "output-delimiter", TakesArg: true},
			{Long: "total"},
			{Long: "zero-terminated"},
			{Long: "help"},
			{Long: "version"},
		},
		AllowAnyPositional: true,
	},

	// Path / info commands. Almost no flags, almost all read-only.
	"pwd": {
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "L"},
			{Short: "P"},
			{Long: "help"},
			{Long: "version"},
		},
		AllowAnyPositional: true,
	},
	// cd is a bash builtin whose only effect is chdir(2) on this shell
	// invocation; cwd dies with the process. No flags whitelisted — `cd -P`,
	// `cd -L`, `cd -e`, `cd -@`, `cd -` all fall through. Variable expansion
	// like `cd $HOME` is blocked upstream by wordLiteral.
	"cd": {
		Style:              styleGNU,
		Flags:              nil,
		AllowAnyPositional: true,
	},
	"basename": {
		ArgvDataSafe: true,
		Style:        styleGNU,
		Flags: []flagSpec{
			{Short: "a", Long: "multiple"},
			{Short: "s", Long: "suffix", TakesArg: true},
			{Short: "z", Long: "zero"},
			{Long: "help"},
			{Long: "version"},
		},
		AllowAnyPositional: true,
	},
	"dirname": {
		ArgvDataSafe: true,
		Style:        styleGNU,
		Flags: []flagSpec{
			{Short: "z", Long: "zero"},
			{Long: "help"},
			{Long: "version"},
		},
		AllowAnyPositional: true,
	},
	"realpath": {
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "e", Long: "canonicalize-existing"},
			{Short: "L", Long: "logical"},
			{Short: "m", Long: "canonicalize-missing"},
			{Short: "P", Long: "physical"},
			{Short: "q", Long: "quiet"},
			{Short: "s", Long: "strip"},
			{Short: "z", Long: "zero"},
			{Long: "relative-to", TakesArg: true},
			{Long: "relative-base", TakesArg: true},
			{Long: "no-symlinks"},
			{Long: "help"},
			{Long: "version"},
		},
		AllowAnyPositional: true,
	},
	"readlink": {
		ArgvDataSafe: true,
		Style:        styleGNU,
		Flags: []flagSpec{
			{Short: "e", Long: "canonicalize-existing"},
			{Short: "f", Long: "canonicalize"},
			{Short: "m", Long: "canonicalize-missing"},
			{Short: "n", Long: "no-newline"},
			{Short: "q", Long: "quiet"},
			{Short: "s", Long: "silent"},
			{Short: "v", Long: "verbose"},
			{Short: "z", Long: "zero"},
			{Long: "help"},
			{Long: "version"},
		},
		AllowAnyPositional: true,
	},
	"which": {
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "a"},
			{Short: "s"},
			{Short: "v"},
			{Short: "V"},
		},
		AllowAnyPositional: true,
	},
	"whereis": {
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "b"},
			{Short: "B", TakesArg: true},
			{Short: "f"},
			{Short: "g"},
			{Short: "h"},
			{Short: "l"},
			{Short: "m"},
			{Short: "M", TakesArg: true},
			{Short: "s"},
			{Short: "S", TakesArg: true},
			{Short: "u"},
			{Short: "V"},
		},
		AllowAnyPositional: true,
	},
	"type": {
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "a"},
			{Short: "f"},
			{Short: "p"},
			{Short: "P"},
			{Short: "t"},
		},
		AllowAnyPositional: true,
	},
	"command": {
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "p"},
			{Short: "v"},
			{Short: "V"},
		},
		AllowAnyPositional: true,
	},

	// System info: read-only.
	"date": {
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "d", Long: "date", TakesArg: true},
			{Short: "f", Long: "file", TakesArg: true},
			{Short: "I", TakesArg: false},
			{Short: "R", Long: "rfc-email"},
			{Short: "r", Long: "reference", TakesArg: true},
			{Short: "u", Long: "utc"},
			{Long: "iso-8601"},
			{Long: "rfc-3339", TakesArg: true},
			{Long: "universal"},
			{Long: "debug"},
			{Long: "resolution"},
			{Long: "help"},
			{Long: "version"},
			// NOT whitelisted: -s/--set (sets system clock)
		},
		AllowAnyPositional: true,
	},
	"whoami": {
		Style: styleGNU,
		Flags: []flagSpec{
			{Long: "help"},
			{Long: "version"},
		},
	},
	"id": {
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "a"},
			{Short: "G", Long: "groups"},
			{Short: "g", Long: "group"},
			{Short: "n", Long: "name"},
			{Short: "r", Long: "real"},
			{Short: "u", Long: "user"},
			{Short: "z", Long: "zero"},
			{Short: "Z", Long: "context"},
			{Long: "help"},
			{Long: "version"},
		},
		AllowAnyPositional: true,
	},
	"hostname": {
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "a"},
			{Short: "A"},
			{Short: "b"},
			{Short: "d"},
			{Short: "f"},
			{Short: "i"},
			{Short: "I"},
			{Short: "s"},
			{Short: "v"},
			{Short: "y"},
			// NOT whitelisted: -F/--file (sets hostname), positional arg (sets hostname)
		},
		// Intentionally NOT AllowAnyPositional — `hostname newname` sets the hostname.
	},
	"uname": {
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "a", Long: "all"},
			{Short: "i", Long: "hardware-platform"},
			{Short: "m", Long: "machine"},
			{Short: "n", Long: "nodename"},
			{Short: "o", Long: "operating-system"},
			{Short: "p", Long: "processor"},
			{Short: "r", Long: "kernel-release"},
			{Short: "s", Long: "kernel-name"},
			{Short: "v", Long: "kernel-version"},
			{Long: "help"},
			{Long: "version"},
		},
	},
	"uptime": {
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "p", Long: "pretty"},
			{Short: "s", Long: "since"},
			{Short: "h", Long: "help"},
			{Short: "V", Long: "version"},
		},
	},
	"env": {
		// Bare `env` (no args) or `env -0`/`env --null` is fine. With any positional
		// arg, it runs that command — unsafe in general. Disallow positionals.
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "0", Long: "null"},
			{Long: "help"},
			{Long: "version"},
			// NOT whitelisted: -i/--ignore-environment (still safe, but enables `env -i CMD`),
			//                  -u/--unset, -C/--chdir, --split-string, -S (these enable arbitrary execution patterns)
		},
		// Positional = command to run. Reject.
	},
	"printenv": {
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "0", Long: "null"},
			{Long: "help"},
			{Long: "version"},
		},
		AllowAnyPositional: true,
	},
	"free": {
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "b", Long: "bytes"},
			{Short: "k", Long: "kibi"},
			{Short: "m", Long: "mebi"},
			{Short: "g", Long: "gibi"},
			{Short: "h", Long: "human"},
			{Short: "w", Long: "wide"},
			{Short: "c", Long: "count", TakesArg: true},
			{Short: "l", Long: "lohi"},
			{Short: "s", Long: "seconds", TakesArg: true},
			{Short: "t", Long: "total"},
			{Short: "v", Long: "committed"},
			{Long: "kilo"},
			{Long: "mega"},
			{Long: "giga"},
			{Long: "tera"},
			{Long: "peta"},
			{Long: "kibi"},
			{Long: "mebi"},
			{Long: "gibi"},
			{Long: "tebi"},
			{Long: "pebi"},
			{Long: "si"},
			{Long: "help"},
			{Long: "version"},
		},
	},
	"ps": {
		Style: styleGNU,
		Flags: []flagSpec{
			// BSD-style without dash, GNU-style with dash. Common short flags only.
			{Short: "a"},
			{Short: "A"},
			{Short: "c"},
			{Short: "d"},
			{Short: "e"},
			{Short: "f"},
			{Short: "F"},
			{Short: "g", TakesArg: true},
			{Short: "G", TakesArg: true},
			{Short: "h"},
			{Short: "H"},
			{Short: "j"},
			{Short: "l"},
			{Short: "L"},
			{Short: "M"},
			{Short: "n"},
			{Short: "N"},
			{Short: "o", TakesArg: true},
			{Short: "O", TakesArg: true},
			{Short: "p", TakesArg: true},
			{Short: "P", TakesArg: true},
			{Short: "q", TakesArg: true},
			{Short: "r"},
			{Short: "s", TakesArg: true},
			{Short: "S"},
			{Short: "t", TakesArg: true},
			{Short: "T"},
			{Short: "u", TakesArg: true},
			{Short: "U", TakesArg: true},
			{Short: "v"},
			{Short: "V"},
			{Short: "w"},
			{Short: "x"},
			{Short: "X"},
			{Short: "y"},
			{Long: "deselect"},
			{Long: "forest"},
			{Long: "headers"},
			{Long: "help"},
			{Long: "no-headers"},
			{Long: "lines", TakesArg: true},
			{Long: "ppid", TakesArg: true},
			{Long: "pid", TakesArg: true},
			{Long: "sid", TakesArg: true},
			{Long: "sort", TakesArg: true},
			{Long: "tty", TakesArg: true},
			{Long: "user", TakesArg: true},
			{Long: "version"},
		},
		AllowAnyPositional: true,
	},
	"getent": {
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "s", Long: "service", TakesArg: true},
			{Short: "i", Long: "no-idn"},
			{Short: "?", Long: "help"},
			{Short: "V", Long: "version"},
		},
		AllowAnyPositional: true,
	},

	// Trivial.
	"echo": {
		ArgvDataSafe: true,
		Style:        styleGNU,
		Flags: []flagSpec{
			{Short: "n"},
			{Short: "e"},
			{Short: "E"},
		},
		AllowAnyPositional: true,
	},
	"printf": {
		Style: styleGNU,
		Flags: []flagSpec{
			{Long: "help"},
			{Long: "version"},
		},
		AllowAnyPositional: true,
	},
	"true":  {Style: styleGNU},
	"false": {Style: styleGNU},
	":":     {Style: styleGNU, AllowAnyPositional: true},

	// JSON: jq is mostly safe. NOT whitelisted: --in-place / -i (writes back to file).
	"jq": {
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "a", Long: "ascii-output"},
			{Short: "c", Long: "compact-output"},
			{Short: "C", Long: "color-output"},
			{Short: "e", Long: "exit-status"},
			{Short: "f", Long: "from-file", TakesArg: true},
			{Short: "j", Long: "join-output"},
			{Short: "M", Long: "monochrome-output"},
			{Short: "n", Long: "null-input"},
			{Short: "R", Long: "raw-input"},
			{Short: "r", Long: "raw-output"},
			{Short: "S", Long: "sort-keys"},
			{Short: "s", Long: "slurp"},
			{Long: "arg", TakesArg: true},
			{Long: "argjson", TakesArg: true},
			{Long: "args"},
			{Long: "indent", TakesArg: true},
			{Long: "jsonargs"},
			{Long: "raw-output0"},
			{Long: "rawfile", TakesArg: true},
			{Long: "seq"},
			{Long: "slurpfile", TakesArg: true},
			{Long: "stream"},
			{Long: "tab"},
			{Long: "unbuffered"},
			{Long: "help"},
			{Long: "version"},
		},
		AllowAnyPositional: true,
	},

	// === Tier E: scripting languages with whitelisted constructs ===========
	// awk is allowed only when classifyAwkProgram approves the script body
	// (no system/getline-pipe, no print redirects, no user functions). The
	// `-f script.awk` form is NOT whitelisted — it would require classifying
	// the loaded file's contents.
	"awk": {
		Style: styleAwk,
		Flags: []flagSpec{
			{Short: "F", TakesArg: true},
			{Short: "v", TakesArg: true},
		},
		AllowAnyPositional: true,
	},

	// === Tier B: command-with-subcommand whitelists ======================

	"git":       gitSpec(),
	"jj":        jjSpec(),
	"nix":       nixSpec(),
	"docker":    dockerSpec(),
	"systemctl": systemctlSpec(),
	"gh":        ghSpec(),

	// === Tier C: flag-aware dual-use =====================================

	"find":       findSpec(),
	"journalctl": journalctlSpec(),

	// === Tier D: transparent wrappers (recursive classification) =========
	// These commands exec the argv after a literal `--` separator. The tail
	// is recursively classified against safeCommands, so the wrapper's safety
	// is entirely determined by the wrapped command — it never loosens rules.
	// The `--` is REQUIRED; bare invocations open an interactive shell and
	// fall through. See styleWrapper in spec.go.

	"devenv": devenvSpec(),

	// === Tier F: stdin-append wrapper ====================================
	// xargs runs `CMD [INITIAL-ARGS] <stdin-items>`. There is no `--` separator
	// (the first non-flag token is the command), and stdin items are appended to
	// the wrapped argv where we can't see them. Recursion is therefore gated by the
	// wrapped command's ArgvDataSafe flag, not the full whitelist. See styleXargs /
	// matchXargs in spec.go.

	"xargs": xargsSpec(),
}

// The set of commands xargs may wrap is no longer a separate list: it is exactly
// the commands carrying ArgvDataSafe on their commandSpec (above). Membership rule:
// a command is ArgvDataSafe ONLY if it has NO write/mutate path under ANY argv,
// because both xargs (stdin tokens) and `$(...)` substitution append operands to
// the argv that we cannot see at classify time — those tokens are parsed by the
// program, including as flags. So `sort` (-o writes), `date` (-s sets the clock),
// `uniq` (IN OUT positional), `jq` (-i), `env` (runs a command), and every
// subcommand/exec command (`git`, `jj`, `nix`, `docker`, `systemctl`, `find`,
// `awk`, `devenv`) deliberately do NOT set it even though they are in safeCommands:
// an injected token could be the write. The "minimal core" set today is cat, tac,
// nl, head, tail, wc, grep/egrep/fgrep, rg, stat, file, cut, the *sum hashes,
// cksum, echo, ls, readlink, basename, dirname. Extend deliberately, applying the
// rule above and adding mustAllow tests.

// xargsSpec is the styleXargs spec for xargs. Flags here are the read-safe
// "common subset"; the replace-mode flags -I/-i/--replace are deliberately NOT
// whitelisted (they enable insertion patterns like `xargs -I{} sh -c '… {}'`),
// so they fall through as unknown flags. The wrapped command and its safety come
// entirely from the wrapped command's ArgvDataSafe flag + recursive classification
// in matchXargs.
func xargsSpec() *commandSpec {
	return &commandSpec{
		Style: styleXargs,
		Flags: []flagSpec{
			{Short: "0", Long: "null"},
			{Short: "n", Long: "max-args", TakesArg: true},
			{Short: "P", Long: "max-procs", TakesArg: true},
			{Short: "r", Long: "no-run-if-empty"},
			{Short: "t", Long: "verbose"},
			{Short: "x", Long: "exit"},
			{Long: "help"},
			{Long: "version"},
			// NOT whitelisted (insertion/exec patterns): -I, -i, --replace.
			// Out of scope for v1 (the "broad" set): -a/--arg-file, -d/--delimiter,
			// -s/--max-chars, -L/--max-lines, -E, -p/--interactive.
		},
	}
}

func grepSpec() *commandSpec {
	return &commandSpec{
		ArgvDataSafe: true,
		Style:        styleGNU,
		Flags: []flagSpec{
			{Short: "A", Long: "after-context", TakesArg: true},
			{Short: "a", Long: "text"},
			{Short: "B", Long: "before-context", TakesArg: true},
			{Short: "b", Long: "byte-offset"},
			{Short: "C", Long: "context", TakesArg: true},
			{Short: "c", Long: "count"},
			{Short: "D", Long: "devices", TakesArg: true},
			{Short: "d", Long: "directories", TakesArg: true},
			{Short: "E", Long: "extended-regexp"},
			{Short: "e", Long: "regexp", TakesArg: true},
			{Short: "F", Long: "fixed-strings"},
			{Short: "f", Long: "file", TakesArg: true},
			{Short: "G", Long: "basic-regexp"},
			{Short: "H", Long: "with-filename"},
			{Short: "h", Long: "no-filename"},
			{Short: "I"},
			{Short: "i", Long: "ignore-case"},
			{Short: "L", Long: "files-without-match"},
			{Short: "l", Long: "files-with-matches"},
			{Short: "m", Long: "max-count", TakesArg: true},
			{Short: "n", Long: "line-number"},
			{Short: "o", Long: "only-matching"},
			{Short: "P", Long: "perl-regexp"},
			{Short: "q", Long: "quiet"},
			{Short: "R"},
			{Short: "r", Long: "recursive"},
			{Short: "s", Long: "no-messages"},
			{Short: "U", Long: "binary"},
			{Short: "V", Long: "version"},
			{Short: "v", Long: "invert-match"},
			{Short: "w", Long: "word-regexp"},
			{Short: "x", Long: "line-regexp"},
			{Short: "y"},
			{Short: "Z", Long: "null"},
			{Short: "z", Long: "null-data"},
			{Long: "binary-files", TakesArg: true},
			{Long: "color"},
			{Long: "colour"},
			{Long: "exclude", TakesArg: true},
			{Long: "exclude-dir", TakesArg: true},
			{Long: "exclude-from", TakesArg: true},
			{Long: "group-separator", TakesArg: true},
			{Long: "include", TakesArg: true},
			{Long: "label", TakesArg: true},
			{Long: "line-buffered"},
			{Long: "mmap"},
			{Long: "no-group-separator"},
			{Long: "null"},
			{Long: "null-data"},
			{Long: "help"},
		},
		AllowAnyPositional: true,
	}
}

func hashSpec() *commandSpec {
	return &commandSpec{
		ArgvDataSafe: true,
		Style:        styleGNU,
		Flags: []flagSpec{
			{Short: "b", Long: "binary"},
			{Short: "c", Long: "check"},
			{Short: "l", Long: "length", TakesArg: true},
			{Short: "t", Long: "text"},
			{Short: "z", Long: "zero"},
			{Long: "tag"},
			{Long: "ignore-missing"},
			{Long: "quiet"},
			{Long: "status"},
			{Long: "strict"},
			{Long: "warn"},
			{Long: "help"},
			{Long: "version"},
		},
		AllowAnyPositional: true,
	}
}

func findSpec() *commandSpec {
	// styleFind: no clustering, no =value. Every flag here is single-dash long-form.
	// Deliberately EXCLUDED (any of these makes the invocation unsafe): -delete,
	// -exec, -execdir, -ok, -okdir, -fprint, -fprint0, -fprintf, -fls.
	// Also excluded (operators that need careful pairing): -not, -and, -or,
	// `(`, `)`, `!`.
	return &commandSpec{
		Style: styleFind,
		Flags: []flagSpec{
			{Long: "name", TakesArg: true},
			{Long: "iname", TakesArg: true},
			{Long: "path", TakesArg: true},
			{Long: "ipath", TakesArg: true},
			{Long: "regex", TakesArg: true},
			{Long: "iregex", TakesArg: true},
			{Long: "regextype", TakesArg: true},
			{Long: "type", TakesArg: true},
			{Long: "xtype", TakesArg: true},
			{Long: "maxdepth", TakesArg: true},
			{Long: "mindepth", TakesArg: true},
			{Long: "print"},
			{Long: "print0"},
			{Long: "printf", TakesArg: true},
			{Long: "prune"},
			{Long: "empty"},
			{Long: "newer", TakesArg: true},
			{Long: "anewer", TakesArg: true},
			{Long: "cnewer", TakesArg: true},
			{Long: "mtime", TakesArg: true},
			{Long: "atime", TakesArg: true},
			{Long: "ctime", TakesArg: true},
			{Long: "amin", TakesArg: true},
			{Long: "mmin", TakesArg: true},
			{Long: "cmin", TakesArg: true},
			{Long: "size", TakesArg: true},
			{Long: "perm", TakesArg: true},
			{Long: "user", TakesArg: true},
			{Long: "group", TakesArg: true},
			{Long: "uid", TakesArg: true},
			{Long: "gid", TakesArg: true},
			{Long: "inum", TakesArg: true},
			{Long: "links", TakesArg: true},
			{Long: "samefile", TakesArg: true},
			{Long: "readable"},
			{Long: "writable"},
			{Long: "executable"},
			{Long: "ls"},
			{Long: "nouser"},
			{Long: "nogroup"},
			{Long: "xdev"},
			{Long: "noleaf"},
			{Long: "depth"},
			{Long: "mount"},
			{Long: "follow"},
			{Long: "ignore_readdir_race"},
			{Long: "noignore_readdir_race"},
			{Long: "H"}, // -H, -L, -P appear as -H not --H; styleFind strips all leading dashes.
			{Long: "L"},
			{Long: "P"},
			{Long: "D", TakesArg: true},
			{Long: "O", TakesArg: true},
			{Long: "files0-from", TakesArg: true},
			{Long: "help"},
			{Long: "version"},
		},
	}
}

func gitSpec() *commandSpec {
	// v1 git subcommands: only those that have no write/mutate mode at all.
	// Excluded for v1 (have write modes that share the subcommand binary):
	//   branch, tag, config, remote, worktree, stash, checkout, switch, restore,
	//   add, rm, mv, commit, merge, rebase, pull, push, fetch, clone, init,
	//   reset, clean, gc, prune, repack, notes, submodule, bisect, cherry-pick,
	//   revert, am, format-patch, apply, send-email, archive.
	//
	// Top-level git flags whitelisted here are limited to `-C <path>`. Other
	// top-level flags (--git-dir=, --work-tree=, -c, -P, --no-pager, etc.)
	// still fall through.
	return &commandSpec{
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "C", TakesArg: true},
		},
		Subcommands: map[string]*commandSpec{
			"status":    gitStatusSpec(),
			"log":       gitLogSpec(),
			"show":      gitShowSpec(),
			"diff":      gitDiffSpec(),
			"rev-parse": gitRevParseSpec(),
			"ls-files":  gitLsFilesSpec(),
			"ls-tree":   gitLsTreeSpec(),
			"cat-file":  gitCatFileSpec(),
			"blame":     gitBlameSpec(),
			"describe":  gitDescribeSpec(),
			"shortlog":  gitShortlogSpec(),
			"reflog":    gitReflogSpec(),
			"grep":      gitGrepSpec(),
		},
	}
}

func gitStatusSpec() *commandSpec {
	return &commandSpec{
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "s", Long: "short"},
			{Short: "b", Long: "branch"},
			{Short: "u", Long: "untracked-files", TakesArg: true},
			{Short: "z"},
			{Long: "porcelain"},
			{Long: "long"},
			{Long: "show-stash"},
			{Long: "verbose"},
			{Long: "ignored", TakesArg: true},
			{Long: "column"},
			{Long: "no-column"},
			{Long: "ahead-behind"},
			{Long: "no-ahead-behind"},
			{Long: "renames"},
			{Long: "no-renames"},
			{Long: "find-renames", TakesArg: true},
			{Long: "untracked-files", TakesArg: true},
			{Long: "ignore-submodules", TakesArg: true},
			{Long: "help"},
		},
		AllowAnyPositional: true,
	}
}

func gitLogSpec() *commandSpec {
	return &commandSpec{
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "p"},
			{Short: "u"},
			{Short: "n", TakesArg: true},
			{Short: "L", TakesArg: true},
			{Short: "S", TakesArg: true},
			{Short: "G", TakesArg: true},
			{Short: "i"},
			// -NUM shorthand (e.g. `git log -20`): treat each digit as a no-op flag.
			// Semantically wrong (git reads "-20" as "-n 20") but spec only
			// cares about safety; safe either way.
			{Short: "0"},
			{Short: "1"},
			{Short: "2"},
			{Short: "3"},
			{Short: "4"},
			{Short: "5"},
			{Short: "6"},
			{Short: "7"},
			{Short: "8"},
			{Short: "9"},
			{Long: "oneline"},
			{Long: "graph"},
			{Long: "all"},
			{Long: "decorate"},
			{Long: "no-decorate"},
			{Long: "pretty", TakesArg: true},
			{Long: "format", TakesArg: true},
			{Long: "abbrev"},
			{Long: "abbrev-commit"},
			{Long: "no-abbrev-commit"},
			{Long: "max-count", TakesArg: true},
			{Long: "skip", TakesArg: true},
			{Long: "since", TakesArg: true},
			{Long: "after", TakesArg: true},
			{Long: "until", TakesArg: true},
			{Long: "before", TakesArg: true},
			{Long: "author", TakesArg: true},
			{Long: "committer", TakesArg: true},
			{Long: "grep", TakesArg: true},
			{Long: "all-match"},
			{Long: "invert-grep"},
			{Long: "regexp-ignore-case"},
			{Long: "basic-regexp"},
			{Long: "extended-regexp"},
			{Long: "fixed-strings"},
			{Long: "perl-regexp"},
			{Long: "merges"},
			{Long: "no-merges"},
			{Long: "min-parents", TakesArg: true},
			{Long: "max-parents", TakesArg: true},
			{Long: "first-parent"},
			{Long: "follow"},
			{Long: "name-only"},
			{Long: "name-status"},
			{Long: "stat"},
			{Long: "shortstat"},
			{Long: "numstat"},
			{Long: "patch"},
			{Long: "no-patch"},
			{Long: "raw"},
			{Long: "reverse"},
			{Long: "source"},
			{Long: "show-signature"},
			{Long: "color"},
			{Long: "no-color"},
			{Long: "date", TakesArg: true},
			{Long: "relative-date"},
			{Long: "topo-order"},
			{Long: "date-order"},
			{Long: "author-date-order"},
			{Long: "diff-filter", TakesArg: true},
			{Long: "find-renames"},
			{Long: "find-copies"},
			{Long: "find-copies-harder"},
			{Long: "branches"},
			{Long: "tags"},
			{Long: "remotes"},
			{Long: "exclude", TakesArg: true},
			{Long: "ancestry-path"},
			{Long: "merge"},
			{Long: "boundary"},
			{Long: "simplify-by-decoration"},
			{Long: "no-walk"},
			{Long: "do-walk"},
			{Long: "left-right"},
			{Long: "cherry-mark"},
			{Long: "cherry-pick"},
			{Long: "cherry"},
			{Long: "walk-reflogs"},
			{Long: "help"},
		},
		AllowAnyPositional: true,
	}
}

func gitShowSpec() *commandSpec {
	return &commandSpec{
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "p"},
			{Short: "U", TakesArg: true},
			{Short: "s"},
			{Long: "pretty", TakesArg: true},
			{Long: "format", TakesArg: true},
			{Long: "abbrev"},
			{Long: "abbrev-commit"},
			{Long: "color"},
			{Long: "no-color"},
			{Long: "stat"},
			{Long: "shortstat"},
			{Long: "numstat"},
			{Long: "name-only"},
			{Long: "name-status"},
			{Long: "patch"},
			{Long: "no-patch"},
			{Long: "raw"},
			{Long: "show-signature"},
			{Long: "expand-tabs"},
			{Long: "no-expand-tabs"},
			{Long: "diff-filter", TakesArg: true},
			{Long: "find-renames"},
			{Long: "find-copies"},
			{Long: "unified", TakesArg: true},
			{Long: "no-walk"},
			{Long: "help"},
		},
		AllowAnyPositional: true,
	}
}

func gitDiffSpec() *commandSpec {
	return &commandSpec{
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "p"},
			{Short: "u"},
			{Short: "U", TakesArg: true},
			{Short: "s"},
			{Short: "b"},
			{Short: "w"},
			{Short: "B"},
			{Short: "M"},
			{Short: "C"},
			{Short: "D"},
			{Short: "I", TakesArg: true},
			{Short: "R"},
			{Long: "cached"},
			{Long: "staged"},
			{Long: "stat"},
			{Long: "shortstat"},
			{Long: "numstat"},
			{Long: "name-only"},
			{Long: "name-status"},
			{Long: "patch"},
			{Long: "no-patch"},
			{Long: "raw"},
			{Long: "color"},
			{Long: "no-color"},
			{Long: "color-words"},
			{Long: "word-diff"},
			{Long: "word-diff-regex", TakesArg: true},
			{Long: "ignore-all-space"},
			{Long: "ignore-blank-lines"},
			{Long: "ignore-space-at-eol"},
			{Long: "ignore-space-change"},
			{Long: "ignore-cr-at-eol"},
			{Long: "no-renames"},
			{Long: "find-renames"},
			{Long: "find-copies"},
			{Long: "find-copies-harder"},
			{Long: "diff-filter", TakesArg: true},
			{Long: "exit-code"},
			{Long: "quiet"},
			{Long: "minimal"},
			{Long: "patience"},
			{Long: "histogram"},
			{Long: "indent-heuristic"},
			{Long: "no-indent-heuristic"},
			{Long: "anchored", TakesArg: true},
			{Long: "diff-algorithm", TakesArg: true},
			{Long: "stat-width", TakesArg: true},
			{Long: "stat-name-width", TakesArg: true},
			{Long: "stat-graph-width", TakesArg: true},
			{Long: "stat-count", TakesArg: true},
			{Long: "compact-summary"},
			{Long: "summary"},
			{Long: "check"},
			{Long: "abbrev"},
			{Long: "src-prefix", TakesArg: true},
			{Long: "dst-prefix", TakesArg: true},
			{Long: "no-prefix"},
			{Long: "ignore-submodules"},
			{Long: "submodule"},
			{Long: "merge-base"},
			{Long: "help"},
		},
		AllowAnyPositional: true,
	}
}

func gitRevParseSpec() *commandSpec {
	return &commandSpec{
		Style: styleGNU,
		Flags: []flagSpec{
			{Long: "abbrev-ref"},
			{Long: "all"},
			{Long: "branches"},
			{Long: "default", TakesArg: true},
			{Long: "git-dir"},
			{Long: "git-common-dir"},
			{Long: "git-path", TakesArg: true},
			{Long: "glob", TakesArg: true},
			{Long: "is-bare-repository"},
			{Long: "is-inside-git-dir"},
			{Long: "is-inside-work-tree"},
			{Long: "is-shallow-repository"},
			{Long: "local-env-vars"},
			{Long: "no-flags"},
			{Long: "no-revs"},
			{Long: "not"},
			{Long: "parse-opt"},
			{Long: "prefix", TakesArg: true},
			{Long: "quiet"},
			{Long: "remotes"},
			{Long: "resolve-git-dir", TakesArg: true},
			{Long: "revs-only"},
			{Long: "shared-index-path"},
			{Long: "short"},
			{Long: "show-cdup"},
			{Long: "show-prefix"},
			{Long: "show-toplevel"},
			{Long: "show-superproject-working-tree"},
			{Long: "since", TakesArg: true},
			{Long: "sq"},
			{Long: "sq-quote"},
			{Long: "stop-at-non-option"},
			{Long: "symbolic"},
			{Long: "symbolic-full-name"},
			{Long: "tags"},
			{Long: "until", TakesArg: true},
			{Long: "verify"},
			{Long: "help"},
		},
		AllowAnyPositional: true,
	}
}

func gitLsFilesSpec() *commandSpec {
	return &commandSpec{
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "c", Long: "cached"},
			{Short: "d", Long: "deleted"},
			{Short: "i", Long: "ignored"},
			{Short: "m", Long: "modified"},
			{Short: "o", Long: "others"},
			{Short: "s", Long: "stage"},
			{Short: "t"},
			{Short: "u", Long: "unmerged"},
			{Short: "v"},
			{Short: "x", Long: "exclude", TakesArg: true},
			{Short: "X", Long: "exclude-from", TakesArg: true},
			{Short: "z"},
			{Long: "full-name"},
			{Long: "abbrev"},
			{Long: "directory"},
			{Long: "eol"},
			{Long: "error-unmatch"},
			{Long: "exclude-standard"},
			{Long: "no-empty-directory"},
			{Long: "recurse-submodules"},
			{Long: "with-tree", TakesArg: true},
			{Long: "help"},
		},
		AllowAnyPositional: true,
	}
}

func gitLsTreeSpec() *commandSpec {
	return &commandSpec{
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "d"},
			{Short: "l"},
			{Short: "r"},
			{Short: "t"},
			{Short: "z"},
			{Long: "abbrev"},
			{Long: "full-name"},
			{Long: "full-tree"},
			{Long: "name-only"},
			{Long: "name-status"},
			{Long: "object-only"},
			{Long: "help"},
		},
		AllowAnyPositional: true,
	}
}

func gitCatFileSpec() *commandSpec {
	return &commandSpec{
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "e"},
			{Short: "p"},
			{Short: "s"},
			{Short: "t"},
			{Long: "batch"},
			{Long: "batch-all-objects"},
			{Long: "batch-check"},
			{Long: "buffer"},
			{Long: "follow-symlinks"},
			{Long: "path", TakesArg: true},
			// NOT whitelisted (exec): --textconv and --filters run a program
			// named by gitattributes/git-config (diff.<d>.textconv,
			// filter.<f>.clean). Verified: `git cat-file --textconv` executed
			// the configured filter. Same class as jj --tool. Removed 2026-07-27.
			{Long: "help"},
		},
		AllowAnyPositional: true,
	}
}

func gitBlameSpec() *commandSpec {
	return &commandSpec{
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "b"},
			{Short: "c"},
			{Short: "e", Long: "show-email"},
			{Short: "f", Long: "show-name"},
			{Short: "L", TakesArg: true},
			{Short: "l"},
			{Short: "M"},
			{Short: "n", Long: "show-number"},
			{Short: "p", Long: "porcelain"},
			{Short: "s"},
			{Short: "t"},
			{Short: "w"},
			{Long: "abbrev"},
			{Long: "color-by-age"},
			{Long: "color-lines"},
			{Long: "date", TakesArg: true},
			{Long: "encoding", TakesArg: true},
			{Long: "first-parent"},
			{Long: "ignore-rev", TakesArg: true},
			{Long: "ignore-revs-file", TakesArg: true},
			{Long: "incremental"},
			{Long: "line-porcelain"},
			{Long: "minimal"},
			{Long: "no-progress"},
			{Long: "progress"},
			{Long: "reverse"},
			{Long: "root"},
			{Long: "score-debug"},
			{Long: "show-stats"},
			{Long: "since", TakesArg: true},
			{Long: "help"},
		},
		AllowAnyPositional: true,
	}
}

func gitDescribeSpec() *commandSpec {
	return &commandSpec{
		Style: styleGNU,
		Flags: []flagSpec{
			{Long: "abbrev", TakesArg: true},
			{Long: "all"},
			{Long: "always"},
			{Long: "broken"},
			{Long: "candidates", TakesArg: true},
			{Long: "contains"},
			{Long: "debug"},
			{Long: "dirty"},
			{Long: "exact-match"},
			{Long: "exclude", TakesArg: true},
			{Long: "first-parent"},
			{Long: "long"},
			{Long: "match", TakesArg: true},
			{Long: "tags"},
			{Long: "help"},
		},
		AllowAnyPositional: true,
	}
}

func gitShortlogSpec() *commandSpec {
	return &commandSpec{
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "c"},
			{Short: "e", Long: "email"},
			{Short: "n", Long: "numbered"},
			{Short: "s", Long: "summary"},
			{Short: "w", TakesArg: true},
			{Long: "format", TakesArg: true},
			{Long: "group", TakesArg: true},
			{Long: "help"},
		},
		AllowAnyPositional: true,
	}
}

func gitReflogSpec() *commandSpec {
	// `git reflog` with no subcommand = `git reflog show`. The other subcommands
	// (delete, expire) mutate. For v1, simplest: don't whitelist any reflog
	// subcommand; only allow `git reflog` / `git reflog show ...`.
	return &commandSpec{
		Style: styleGNU,
		Subcommands: map[string]*commandSpec{
			"show": {
				Style:              styleGNU,
				AllowAnyPositional: true,
				Flags: []flagSpec{
					{Long: "all"},
					{Long: "no-merges"},
					{Long: "merges"},
					{Long: "pretty", TakesArg: true},
					{Long: "format", TakesArg: true},
					{Long: "max-count", TakesArg: true},
					{Long: "help"},
				},
			},
		},
	}
}

func gitGrepSpec() *commandSpec {
	return &commandSpec{
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "a", Long: "text"},
			{Short: "c", Long: "count"},
			{Short: "E", Long: "extended-regexp"},
			{Short: "e", TakesArg: true},
			{Short: "F", Long: "fixed-strings"},
			{Short: "f", TakesArg: true},
			{Short: "G", Long: "basic-regexp"},
			{Short: "H"},
			{Short: "h"},
			{Short: "I"},
			{Short: "i", Long: "ignore-case"},
			{Short: "L", Long: "files-without-match"},
			{Short: "l", Long: "files-with-matches"},
			{Short: "n", Long: "line-number"},
			{Short: "O", TakesArg: true},
			{Short: "o", Long: "only-matching"},
			{Short: "P", Long: "perl-regexp"},
			{Short: "p", Long: "show-function"},
			{Short: "q", Long: "quiet"},
			{Short: "r", Long: "recursive"},
			{Short: "v", Long: "invert-match"},
			{Short: "W", Long: "function-context"},
			{Short: "w", Long: "word-regexp"},
			{Short: "z", Long: "null"},
			{Long: "all-match"},
			{Long: "and"},
			{Long: "break"},
			{Long: "cached"},
			{Long: "color"},
			{Long: "column"},
			{Long: "files-with-matches"},
			{Long: "full-name"},
			{Long: "heading"},
			{Long: "max-depth", TakesArg: true},
			{Long: "max-count", TakesArg: true},
			{Long: "no-recursive"},
			{Long: "not"},
			{Long: "or"},
			{Long: "recurse-submodules"},
			{Long: "show-function"},
			{Long: "untracked"},
			{Long: "no-index"},
			{Long: "no-textconv"},
			{Long: "threads", TakesArg: true},
			// NOT whitelisted (exec): --textconv runs the gitattributes-configured
			// textconv program. Verified: `git grep --textconv` executed it.
			// --no-textconv stays (it only DISABLES that path). Removed 2026-07-27.
			{Long: "help"},
		},
		AllowAnyPositional: true,
	}
}

func jjSpec() *commandSpec {
	// jj subcommands chosen for v1: read-only operations only.
	return &commandSpec{
		Style: styleGNU,
		// Global options: jj documents these BEFORE the subcommand (`jj -R <path>
		// log`). matchGNU checks pre-subcommand tokens against this parent flag set
		// and does not inherit into Subcommands, so -R must be declared here as well
		// as in jjCommonFlags(). Mirrors `git -C <path>` in gitSpec().
		//
		// --config/--config-file are excluded as an exec path: ui.pager is spawned by
		// the read-only subcommands below, so `jj --config 'ui.pager=[…]' log` runs an
		// arbitrary program (verified, jj 0.41). The remaining globals
		// (--ignore-immutable, --at-operation, --ignore-working-copy, --debug,
		// --color, --quiet, -V) are out for zero logged demand only, not danger —
		// --ignore-immutable in particular is inert before a read-only subcommand.
		// See DESIGN-jj-global-flags.md.
		Flags: []flagSpec{
			{Short: "R", Long: "repository", TakesArg: true},
			{Long: "no-pager"},
			{Long: "help"},
		},
		Subcommands: map[string]*commandSpec{
			"status":    {Style: styleGNU, AllowAnyPositional: true, Flags: jjCommonFlags()},
			"st":        {Style: styleGNU, AllowAnyPositional: true, Flags: jjCommonFlags()},
			"diff":      {Style: styleGNU, AllowAnyPositional: true, Flags: jjCommonFlags()},
			"log":       {Style: styleGNU, AllowAnyPositional: true, Flags: jjCommonFlags()},
			"show":      {Style: styleGNU, AllowAnyPositional: true, Flags: jjCommonFlags()},
			"op":        jjOpSpec(),
			"operation": jjOpSpec(),
			"bookmark":  jjBookmarkSpec(),
			"git":       jjGitSpec(),
		},
	}
}

// jjBookmarkSpec whitelists ONLY the read-only `jj bookmark list`. The mutating
// siblings — set / move / create / rename / delete / forget / track / untrack —
// all change bookmark state and must fall through to the normal prompt; they are
// simply absent from the Subcommands map below.
func jjBookmarkSpec() *commandSpec {
	listFlags := append(jjCommonFlags(),
		flagSpec{Short: "a", Long: "all"},
		flagSpec{Short: "t", Long: "tracked"},
		flagSpec{Short: "c", Long: "conflicted"},
		flagSpec{Long: "revisions", TakesArg: true},
	)
	return &commandSpec{
		Style: styleGNU,
		Subcommands: map[string]*commandSpec{
			"list": {Style: styleGNU, AllowAnyPositional: true, Flags: listFlags},
		},
	}
}

// jjGitSpec whitelists ONLY the read-only `jj git remote list`. Everything else
// under `jj git` — push / fetch / clone / import / export, and `remote`
// add/remove/set-url — mutates local state or hits the network, so it is omitted
// and falls through.
func jjGitSpec() *commandSpec {
	return &commandSpec{
		Style: styleGNU,
		Subcommands: map[string]*commandSpec{
			"remote": {
				Style: styleGNU,
				Subcommands: map[string]*commandSpec{
					"list": {Style: styleGNU, AllowAnyPositional: true, Flags: jjCommonFlags()},
				},
			},
		},
	}
}

// jjCommonFlags is the post-subcommand flag set shared by the read-only jj
// subcommands (`jj log -R <path>`), as opposed to jjSpec()'s pre-subcommand
// globals.
//
// Two flags were removed here on 2026-07-27 and must not come back: --tool
// (names a merge-tool, i.e. an executable, and jj runs it — `jj diff --tool
// /tmp/evil` classified allow and executed it) and --config-toml (same
// config-injection class as jjSpec()'s excluded --config; inert only because jj
// 0.41 dropped the flag name, which is a version accident, not a safety
// property). See DESIGN.md "Flag values that are programs".
func jjCommonFlags() []flagSpec {
	return []flagSpec{
		{Short: "r", Long: "revision", TakesArg: true},
		// --from/--to take Jujutsu revsets: repository-history queries, not
		// programs or evaluated expressions. Substituted shell values are still
		// rejected by the generic literal-only flag-argument rule.
		{Short: "f", Long: "from", TakesArg: true},
		{Short: "t", Long: "to", TakesArg: true},
		{Short: "p", Long: "patch"},
		{Short: "s", Long: "summary"},
		{Long: "stat"},
		{Long: "name-only"},
		{Long: "git"},
		{Long: "color-words"},
		{Long: "no-pager"},
		{Long: "no-graph"},
		{Long: "reversed"},
		{Long: "limit", TakesArg: true},
		{Long: "template", TakesArg: true},
		{Short: "T", TakesArg: true},
		{Long: "repository", TakesArg: true},
		{Short: "R", TakesArg: true},
		{Long: "help"},
		{Short: "h", Long: "help"},
	}
}

func jjOpSpec() *commandSpec {
	return &commandSpec{
		Style: styleGNU,
		Subcommands: map[string]*commandSpec{
			"log":  {Style: styleGNU, AllowAnyPositional: true, Flags: jjCommonFlags()},
			"show": {Style: styleGNU, AllowAnyPositional: true, Flags: jjCommonFlags()},
			"diff": {Style: styleGNU, AllowAnyPositional: true, Flags: jjCommonFlags()},
		},
	}
}

func nixSpec() *commandSpec {
	// Nix is huge. v1: only the genuinely read-only subcommands. Build/run/etc.
	// are deferred even though they're often used during exploration — they
	// can fetch arbitrary code and write to /nix/store.
	return &commandSpec{
		Style: styleGNU,
		Subcommands: map[string]*commandSpec{
			"eval":            nixGenericSpec(),
			"show-config":     nixGenericSpec(),
			"show-derivation": nixGenericSpec(),
			"path-info":       nixGenericSpec(),
			"why-depends":     nixGenericSpec(),
			"derivation":      nixDerivationSpec(),
			"flake":           nixFlakeSpec(),
			"search":          nixGenericSpec(),
			"hash":            nixHashSpec(),
			"shell":           nixShellSpec(),
		},
	}
}

// nixShellSpec: transparent wrapper. `nix shell PKGS... -- CMD [ARGS]` runs CMD
// in an env with PKGS on PATH. Safety = safety of CMD; deliberately EXCLUDED:
// --command/-c (flag-introduced wrapper variant, deferred to v2),
// --run (shell-eval string — unsafe by design).
func nixShellSpec() *commandSpec {
	return &commandSpec{
		Style: styleWrapper,
		Flags: []flagSpec{
			{Long: "impure"},
			{Long: "offline"},
			{Long: "verbose"}, {Short: "v"},
			{Long: "quiet"},
			{Long: "debug"},
			{Long: "log-format", TakesArg: true},
			{Long: "print-build-logs"}, {Short: "L"},
			{Long: "option", TakesArg: true},
			{Long: "store", TakesArg: true},
			{Long: "extra-experimental-features", TakesArg: true},
			{Long: "extra-substituters", TakesArg: true},
		},
		AllowAnyPositional: true, // package installables (e.g. nixpkgs#hello)
	}
}

// devenvSpec: top-level `devenv` command. Only `shell --` is whitelisted in v1.
// Other subcommands (up, init, test, build, etc.) all mutate state and are
// deliberately out of scope. They fall through to a normal prompt.
func devenvSpec() *commandSpec {
	return &commandSpec{
		Style: styleGNU,
		Subcommands: map[string]*commandSpec{
			"shell": devenvShellSpec(),
		},
	}
}

// devenvShellSpec: `devenv shell [FLAGS] -- CMD [ARGS]`. Without `--`, devenv
// opens an interactive shell — fall through. Deliberately EXCLUDED:
// --config-path (path arg, low value), --pretty-backtrace (cosmetic),
// any subcommand-introducing forms.
func devenvShellSpec() *commandSpec {
	return &commandSpec{
		Style: styleWrapper,
		Flags: []flagSpec{
			{Long: "impure"},
			{Long: "clean"},
			{Long: "offline"},
			{Long: "verbose"}, {Short: "v"},
			{Long: "quiet"}, {Short: "q"},
			{Long: "nix-debugger"},
		},
		// No positionals before `--`: devenv shell takes none.
	}
}

// nixGenericSpec backs `nix eval` and friends. It accepts INSTALLABLES
// (`nix eval .#pkg`) but deliberately not caller-authored Nix source:
// --expr/--file/--apply were removed 2026-07-27 because Nix evaluation is not a
// read-only sandbox (`--impure --expr 'builtins.readFile /etc/hostname'` returns
// the file; builtins.fetchurl makes real outbound requests, and needs no
// --impure).
//
// --arg/--argstr survive only because --file went with them: their values ARE
// Nix expressions, but flakes refuse them and the non-flake form they need is
// -f/--file. If --file is ever restored, reconsider them in the same change.
// See DESIGN.md "Flag values that are programs".
func nixGenericSpec() *commandSpec {
	return &commandSpec{
		Style: styleGNU,
		Flags: []flagSpec{
			{Long: "json"},
			{Long: "raw"},
			{Long: "no-link"},
			{Long: "out-link", TakesArg: true},
			{Long: "include", TakesArg: true},
			{Long: "arg", TakesArg: true},
			{Long: "argstr", TakesArg: true},
			{Long: "impure"},
			{Long: "read-only"},
			{Long: "all"},
			{Long: "recursive"},
			{Long: "derivation"},
			{Long: "closure-size"},
			{Long: "sigs"},
			{Long: "size"},
			{Long: "store", TakesArg: true},
			{Long: "extra-experimental-features", TakesArg: true},
			{Long: "extra-substituters", TakesArg: true},
			{Long: "option", TakesArg: true},
			{Long: "verbose"},
			{Short: "v"},
			{Long: "quiet"},
			{Long: "debug"},
			{Long: "log-format", TakesArg: true},
			{Long: "print-build-logs"},
			{Short: "L"},
			{Long: "help"},
			{Short: "h", Long: "help"},
		},
		AllowAnyPositional: true,
	}
}

func nixDerivationSpec() *commandSpec {
	return &commandSpec{
		Style: styleGNU,
		Subcommands: map[string]*commandSpec{
			"show": nixGenericSpec(),
		},
	}
}

func nixFlakeSpec() *commandSpec {
	return &commandSpec{
		Style: styleGNU,
		Subcommands: map[string]*commandSpec{
			"metadata": nixGenericSpec(),
			"show":     nixGenericSpec(),
			"info":     nixGenericSpec(),
			"check":    nixGenericSpec(),
		},
	}
}

func nixHashSpec() *commandSpec {
	return &commandSpec{
		Style: styleGNU,
		Subcommands: map[string]*commandSpec{
			"file":      nixGenericSpec(),
			"path":      nixGenericSpec(),
			"to-base16": nixGenericSpec(),
			"to-base32": nixGenericSpec(),
			"to-base64": nixGenericSpec(),
			"to-sri":    nixGenericSpec(),
			"convert":   nixGenericSpec(),
		},
	}
}

func dockerSpec() *commandSpec {
	return &commandSpec{
		Style: styleGNU,
		Subcommands: map[string]*commandSpec{
			"ps":      dockerCommonSpec(),
			"images":  dockerCommonSpec(),
			"logs":    dockerCommonSpec(),
			"inspect": dockerCommonSpec(),
			"version": dockerCommonSpec(),
			"info":    dockerCommonSpec(),
		},
	}
}

func dockerCommonSpec() *commandSpec {
	return &commandSpec{
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "a", Long: "all"},
			{Short: "f", Long: "filter", TakesArg: true},
			{Short: "n", Long: "last", TakesArg: true},
			{Short: "l", Long: "latest"},
			{Short: "q", Long: "quiet"},
			{Short: "s", Long: "size"},
			{Long: "format", TakesArg: true},
			{Long: "no-trunc"},
			{Long: "since", TakesArg: true},
			{Long: "until", TakesArg: true},
			{Long: "follow"},
			{Long: "tail", TakesArg: true},
			{Long: "timestamps"},
			{Long: "details"},
			{Long: "type", TakesArg: true},
			{Long: "digests"},
			{Long: "help"},
		},
		AllowAnyPositional: true,
	}
}

func systemctlSpec() *commandSpec {
	return &commandSpec{
		Style: styleGNU,
		Subcommands: map[string]*commandSpec{
			"status":            systemctlReadSpec(),
			"is-active":         systemctlReadSpec(),
			"is-enabled":        systemctlReadSpec(),
			"is-failed":         systemctlReadSpec(),
			"cat":               systemctlReadSpec(),
			"show":              systemctlReadSpec(),
			"list-units":        systemctlReadSpec(),
			"list-unit-files":   systemctlReadSpec(),
			"list-jobs":         systemctlReadSpec(),
			"list-dependencies": systemctlReadSpec(),
			"list-timers":       systemctlReadSpec(),
			"list-sockets":      systemctlReadSpec(),
			"get-default":       systemctlReadSpec(),
		},
	}
}

func systemctlReadSpec() *commandSpec {
	return &commandSpec{
		Style: styleGNU,
		Flags: []flagSpec{
			{Long: "all"},
			{Long: "full"},
			{Long: "no-pager"},
			{Long: "no-legend"},
			{Long: "plain"},
			{Long: "type", TakesArg: true},
			{Short: "t", TakesArg: true},
			{Long: "state", TakesArg: true},
			{Long: "property", TakesArg: true},
			{Short: "p", TakesArg: true},
			{Long: "value"},
			{Long: "lines", TakesArg: true},
			{Short: "n", TakesArg: true},
			{Long: "output", TakesArg: true},
			{Short: "o", TakesArg: true},
			{Long: "show-types"},
			{Long: "user"},
			{Long: "system"},
			{Long: "version"},
			{Long: "help"},
			{Short: "h", Long: "help"},
		},
		AllowAnyPositional: true,
	}
}

// journalctlSpec whitelists journalctl as a read-only journal query tool. It is a
// pure reader EXCEPT for management flags that write or delete journal state; those
// are deliberately left off Flags (so they fall through), never enumerated as a
// deny-list.
//
// AllowAnyPositional is TRUE: positionals are field matches (`_SYSTEMD_UNIT=foo`)
// or executable paths — read filters. This is safe under §8 getopt permutation:
// because journalctl is NOT ArgvDataSafe, matchGNU keeps validating flags even
// after a positional, so an interspersed `journalctl _SYSTEMD_UNIT=x --vacuum-size`
// still rejects the unwhitelisted `--vacuum-size` and falls through. (Before §8,
// matchGNU swallowed post-positional flags as data, so this spec had to set
// AllowAnyPositional=false to stay safe; §8 lifted that restriction.) ArgvDataSafe
// stays FALSE precisely because the destructive path is a flag — same `sort -o`
// reasoning — so journalctl must never receive an opaque, flag-shaped operand.
//
// Deliberately excluded (must keep falling through): --vacuum-size, --vacuum-time,
// --vacuum-files (delete journals), --rotate, --flush, --sync, --relinquish-var,
// --smart-relinquish-var, --setup-keys, --update-catalog, --verify; the streaming
// -f/--follow (never terminates — see TestNotYetAllowed); and the alternate-location
// readers -D/--directory, --file, --root, -M/--machine, --namespace (deferred, D3).
func journalctlSpec() *commandSpec {
	return &commandSpec{
		Style:              styleGNU,
		AllowAnyPositional: true,
		Flags: []flagSpec{
			{Short: "t", Long: "identifier", TakesArg: true},
			{Short: "u", Long: "unit", TakesArg: true},
			{Long: "user-unit", TakesArg: true},
			{Short: "n", Long: "lines", TakesArg: true},
			{Short: "S", Long: "since", TakesArg: true},
			{Short: "U", Long: "until", TakesArg: true},
			{Short: "p", Long: "priority", TakesArg: true},
			{Short: "g", Long: "grep", TakesArg: true},
			{Long: "case-sensitive", OptionalArg: true},
			{Short: "b", Long: "boot", OptionalArg: true, DashValueOK: true},
			// ^ DashValueOK: -b's value is a ±offset ("journalctl -b -1" = the boot
			// before last), so the documented spelling collides with flag syntax.
			// Digits-only, one token — see flagSpec.DashValueOK.
			{Short: "k", Long: "dmesg"},
			{Short: "o", Long: "output", TakesArg: true},
			{Long: "output-fields", TakesArg: true},
			{Short: "r", Long: "reverse"},
			{Short: "e", Long: "pager-end"},
			{Short: "x", Long: "catalog"},
			{Short: "a", Long: "all"},
			{Short: "q", Long: "quiet"},
			{Short: "m", Long: "merge"},
			{Long: "utc"},
			{Long: "no-pager"},
			{Long: "no-tail"},
			{Long: "no-full"},
			{Long: "no-hostname"},
			{Short: "N", Long: "fields"},
			{Short: "F", Long: "field", TakesArg: true},
			{Long: "list-boots"},
			{Long: "header"},
			{Long: "disk-usage"},
			{Long: "version"},
			{Short: "h", Long: "help"},
		},
	}
}

// ghSpec whitelists the GitHub CLI as a read-only tool, modeled on gitSpec(): a
// per-subcommand whitelist where only no-write subcommands appear. gh is heavily
// network-write-capable (repo edit, pr/issue/release create|merge|close, api with
// -X POST), so the Subcommands map is the gate — every mutating subcommand is simply
// absent and falls through. NOT ArgvDataSafe at any level: gh can write over the
// network, so it must never receive an opaque token.
//
// Scope: `gh auth status`, `gh repo view`, and `gh api` (GET-only). The latter two
// require a positional (the OWNER/REPO or the API endpoint); they are safe now that
// §8 getopt permutation validates flags even after a positional — so a trailing
// `gh repo view o/r --web` (browser launch) or `gh api repos/o/r -X POST` (network
// write) hits an unwhitelisted flag and falls through. The write/exec flags are
// simply never listed; permutation does the rest.
func ghSpec() *commandSpec {
	return &commandSpec{
		Style: styleGNU,
		Subcommands: map[string]*commandSpec{
			"auth": ghAuthSpec(),
			"repo": ghRepoSpec(),
			"api":  ghApiSpec(),
		},
	}
}

// ghAuthSpec whitelists ONLY `gh auth status`. The mutating / secret-exposing
// siblings — login, logout, refresh, setup-git, and `token` (prints the auth token)
// — are absent and fall through.
func ghAuthSpec() *commandSpec {
	return &commandSpec{
		Style: styleGNU,
		Subcommands: map[string]*commandSpec{
			"status": ghAuthStatusSpec(),
		},
	}
}

// ghAuthStatusSpec is the read-only `gh auth status`. It takes no positional and has
// no dangerous flag. Deliberately excluded: -t/--show-token (prints the auth
// token — secret disclosure).
func ghAuthStatusSpec() *commandSpec {
	return &commandSpec{
		Style: styleGNU,
		Flags: []flagSpec{
			{Short: "h", Long: "hostname", TakesArg: true},
			{Short: "a", Long: "active"},
			{Long: "help"},
		},
	}
}

// ghRepoSpec whitelists ONLY `gh repo view`. The mutating siblings — create, delete,
// edit, fork, clone, rename, archive, unarchive, sync, set-default — change
// remote/local state and are absent.
func ghRepoSpec() *commandSpec {
	return &commandSpec{
		Style: styleGNU,
		Subcommands: map[string]*commandSpec{
			"view": ghRepoViewSpec(),
		},
	}
}

// ghRepoViewSpec is the read-only `gh repo view [OWNER/REPO]`. The OWNER/REPO is an
// optional positional (AllowAnyPositional); §8 permutation keeps validating flags
// after it, so the excluded -w/--web (launches a browser — exec side effect) is
// rejected wherever it appears. NOT ArgvDataSafe.
func ghRepoViewSpec() *commandSpec {
	return &commandSpec{
		Style:              styleGNU,
		AllowAnyPositional: true,
		Flags: []flagSpec{
			{Long: "json", TakesArg: true},
			{Short: "q", Long: "jq", TakesArg: true},
			{Short: "t", Long: "template", TakesArg: true},
			{Short: "b", Long: "branch", TakesArg: true},
			{Short: "R", Long: "repo", TakesArg: true},
			{Long: "help"},
		},
	}
}

// ghApiSpec is the read-only `gh api ENDPOINT` (GET only). gh api defaults to GET;
// -X/--method, -f/--raw-field, -F/--field, --input turn it into a network write.
// Whitelist-only + §8 permutation close that: only read flags are listed, and the
// method/field/input flags are deliberately absent, so any write form hits an
// unwhitelisted flag — after the endpoint positional too — and falls through. NOT
// ArgvDataSafe. Deliberately excluded: -X/--method, -f/--raw-field, -F/--field,
// --input, -H/--header.
func ghApiSpec() *commandSpec {
	return &commandSpec{
		Style:              styleGNU,
		AllowAnyPositional: true,
		Flags: []flagSpec{
			{Long: "cache", TakesArg: true},
			{Long: "paginate"},
			{Short: "q", Long: "jq", TakesArg: true},
			{Short: "t", Long: "template", TakesArg: true},
			{Long: "hostname", TakesArg: true},
			{Short: "i", Long: "include"},
			{Long: "slurp"},
			{Long: "help"},
		},
	}
}
