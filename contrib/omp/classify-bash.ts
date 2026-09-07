/**
 * classify-bash shim for oh-my-pi (omp).
 *
 * omp already prompts for the bash tool whenever tools.approvalMode is not
 * "yolo", because bash declares the "exec" approval tier. This shim re-registers
 * bash with an approval function that drops read-only commands to tier "read",
 * so they auto-approve in every mode while everything else keeps prompting
 * exactly as before.
 *
 * Polarity: ACCELERATOR. This shim may only ever REMOVE a prompt. If the binary
 * is missing, broken, or slow, every command falls back to the tier bash
 * already had, which is the host's own default. It must never make omp prompt
 * more than it would without this file installed.
 *
 * Install (per-session, for trying it out):
 *   omp -e /path/to/classify-bash.ts
 *
 * Install (always on):
 *   copy or symlink into ~/.omp/agent/extensions/
 *
 * Two constraints, both verified against omp's source rather than assumed:
 *
 *  - `approval` is SYNCHRONOUS. omp calls it as `approval(args)` and normalizes
 *    the result immediately; there is no await anywhere in resolveApproval. So
 *    the classifier is invoked with spawnSync, not an async spawn.
 *  - `approval` is resolved TWICE per tool call — once before the tool_call
 *    event and once after, against the possibly-revised input. Hence the cache.
 */

import { spawnSync } from "node:child_process";

// Replaced at build time with an absolute store path. Left as-is (starting with
// "@") when running from a checkout, in which case we fall back to PATH.
const SUBSTITUTED_BIN = "@classifyBash@";

const BIN =
	process.env.CLASSIFY_BASH_BIN ??
	(SUBSTITUTED_BIN.startsWith("@") ? "classify-bash" : SUBSTITUTED_BIN);

type Verdict = "read_only" | "not_read_only" | "malfunction";

// Bounded so a long session cannot grow it without limit. Commands repeat
// heavily in practice, so even a small cache absorbs the double resolution.
const CACHE_LIMIT = 512;
const cache = new Map<string, Verdict>();

let warnedAboutBinary = false;

function classify(command: string): Verdict {
	const cached = cache.get(command);
	if (cached !== undefined) return cached;

	let verdict: Verdict;
	try {
		const r = spawnSync(BIN, ["check", "--stdin"], {
			input: command,
			encoding: "utf8",
			// A classifier that hangs must not hang the agent. Exceeding this is
			// treated as a malfunction, i.e. as "no opinion".
			timeout: 5000,
		});
		if (r.error || r.status === null) verdict = "malfunction";
		else if (r.status === 0) verdict = "read_only";
		else if (r.status === 1) verdict = "not_read_only";
		else verdict = "malfunction"; // exit 2 = the binary is broken or misused
	} catch {
		verdict = "malfunction";
	}

	if (verdict === "malfunction" && !warnedAboutBinary) {
		warnedAboutBinary = true;
		// Once per session, not per command: a broken install would otherwise
		// bury the session in identical warnings.
		console.error(
			`classify-bash: cannot run "${BIN}" — every bash command will use its ` +
				`normal approval tier. Fix the install or set CLASSIFY_BASH_BIN.`,
		);
	}

	if (cache.size >= CACHE_LIMIT) cache.clear();
	cache.set(command, verdict);
	return verdict;
}

export default function (pi: any) {
	// Re-register bash reusing the LIVE built-in definition rather than a copied
	// schema. omp picks bash's parameter schema at construction time depending on
	// the async.enabled setting, and upstream evolves it, so a hardcoded schema
	// would silently diverge and break tool calls. Spreading the existing tool
	// keeps description, parameters and renderers exactly as they are; only
	// `approval` and `execute` are replaced.
	const install = () => {
		const existing = pi.getAllTools?.()?.find((t: any) => t.name === "bash");
		if (!existing) {
			console.error(
				"classify-bash: no built-in bash tool found to wrap; shim inactive.",
			);
			return;
		}

		pi.registerTool({
			...existing,
			name: "bash",
			approval: (args: any) => {
				const command = typeof args?.command === "string" ? args.command : "";
				if (!command) return "exec";
				// Only ever LOWER the tier. Anything that is not a confident
				// read-only verdict keeps bash's own "exec" tier, which is what
				// omp would have used with this shim absent.
				return classify(command) === "read_only" ? "read" : "exec";
			},
			// Delegate to the native implementation. omp binds ctx.invokeTool to
			// this tool's own name specifically so a re-registration can call
			// through to the built-in it replaced.
			//
			// The fallback matters: this is the one place with nothing to recover
			// to at execute time. If invokeTool is ever absent or renamed, calling
			// the original tool's own execute keeps bash working rather than
			// breaking every command in the session.
			execute: (
				toolCallId: string,
				params: any,
				signal: unknown,
				onUpdate: unknown,
				ctx: any,
			) =>
				typeof ctx?.invokeTool === "function"
					? ctx.invokeTool(params)
					: existing.execute(toolCallId, params, signal, onUpdate, ctx),
		});
	};

	// Built-ins may not be registered yet when the factory runs, so install at
	// session start and tolerate either ordering.
	try {
		install();
	} catch {
		/* fall through to session_start */
	}
	pi.on?.("session_start", () => {
		try {
			install();
		} catch (err) {
			console.error(`classify-bash: could not wrap bash: ${String(err)}`);
		}
	});
}
