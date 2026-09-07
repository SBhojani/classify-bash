/**
 * classify-bash shim for pi.
 *
 * IMPORTANT — read this before installing it globally.
 *
 * pi has no approval system at all: it runs tool calls without asking, and its
 * tool_call hook can only BLOCK. So unlike the omp shim, this one cannot remove
 * a prompt, because there is no prompt to remove. It INSTALLS a baseline: it
 * stays silent for read-only commands and asks about everything else.
 *
 * Polarity: GATE. Installing this makes pi prompt where it previously did not.
 * That is the point, but it is a behaviour change, so it ships uninstalled.
 *
 * Try it for one session:
 *   pi -e /path/to/classify-bash.ts
 *
 * Always on:
 *   copy or symlink into ~/.pi/agent/extensions/
 *
 * Unlike omp's synchronous `approval` callback, pi's tool_call handlers are
 * async, so this spawns asynchronously.
 *
 * The handler must never throw. pi fails CLOSED on a handler error, so an
 * uncaught exception here would block every bash call — the exact outage class
 * classify-bash itself exists to avoid. Every path below is caught, and the
 * fallback is stated explicitly rather than left to an exception.
 */

import { execFile } from "node:child_process";

const SUBSTITUTED_BIN = "@classifyBash@";

const BIN =
	process.env.CLASSIFY_BASH_BIN ??
	(SUBSTITUTED_BIN.startsWith("@") ? "classify-bash" : SUBSTITUTED_BIN);

type Verdict = "read_only" | "not_read_only" | "malfunction";

function classify(command: string): Promise<Verdict> {
	return new Promise((resolve) => {
		try {
			const child = execFile(
				BIN,
				["check", "--stdin"],
				{ timeout: 5000 },
				(err: any) => {
					if (!err) return resolve("read_only"); // exit 0
					if (err.code === 1) return resolve("not_read_only");
					return resolve("malfunction"); // exit 2, spawn failure, timeout
				},
			);
			child.stdin?.end(command);
		} catch {
			resolve("malfunction");
		}
	});
}

export default function (pi: any) {
	pi.on("tool_call", async (event: any, ctx: any) => {
		try {
			if (event?.toolName !== "bash") return undefined;
			const command = String(event?.input?.command ?? "");
			if (!command) return undefined;

			const verdict = await classify(command);
			if (verdict === "read_only") return undefined; // silent — the "allow"

			// The reason is read back by the model as the tool result, so it has to
			// tell it what to do instead, not just that it failed. A terse refusal
			// makes a headless agent retry the same command until it gives up.
			const why =
				verdict === "malfunction"
					? `classify-bash could not run ("${BIN}"), so this command was not ` +
						`confirmed read-only`
					: "this command is not classified read-only";

			if (!ctx?.hasUI) {
				return {
					block: true,
					reason:
						`bash blocked: ${why}, and there is no UI to approve it. ` +
						`Use the write/edit tools for file changes, or re-run interactively.`,
				};
			}

			const ok = await ctx.ui.confirm("Allow command?", `${why}:\n\n  ${command}`);
			return ok ? undefined : { block: true, reason: "denied by user" };
		} catch (err) {
			// Never let this escape: pi fails closed on a handler error, which would
			// block every bash call. Degrade to the documented headless default
			// instead, and say why.
			return {
				block: true,
				reason:
					`bash blocked: the classify-bash pi shim errored (${String(err)}). ` +
					`Remove the extension to restore normal behaviour.`,
			};
		}
	});
}
