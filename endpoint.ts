import { statSync } from "fs";
import { resolve as pathResolve } from "path";

// Endpoint monitor: process poller only (upload focus)
// Detects file upload processes and builds ancestry trees
// Cross-platform: macOS (darwin) and Linux

const DEDICATED_TRANSFER_TOOLS = ["scp", "sftp", "rsync", "ftp"];

const SUSPICIOUS_COMMS = [
	"curl", "wget", "nc", "ncat", "python", "python3",
	"node", "bun", "sh", "bash", "zsh",
	...DEDICATED_TRANSFER_TOOLS,
];

const INTERPRETER_COMMS = new Set(["python", "python3", "node", "bun", "sh", "bash", "zsh"]);

interface UploadMatch {
	matched: boolean;
	pattern: string;
}

export function checkUploadIndicators(comm: string, args: string): UploadMatch {
	const commLower = comm.toLowerCase();
	const argsLower = args.toLowerCase();

	// Dedicated transfer tools: always flag as upload
	if (DEDICATED_TRANSFER_TOOLS.includes(commLower)) {
		return { matched: true, pattern: commLower };
	}

	// curl upload indicators
	if (commLower === "curl") {
		if (/\s-T\s|\s--upload-file\s/i.test(args)) return { matched: true, pattern: "curl -T" };
		if (/\s-F\s|\s--form\s/i.test(args)) return { matched: true, pattern: "curl -F" };
		if (/\s-X\s+PUT\b/i.test(args)) return { matched: true, pattern: "curl -X PUT" };
		if (/\s-d\s+@\S+|\s--data\s+@\S+/i.test(args)) return { matched: true, pattern: "curl -d @file" };
		return { matched: false, pattern: "" };
	}

	// wget upload indicators
	if (commLower === "wget") {
		if (/\s--post-file\s/i.test(args)) return { matched: true, pattern: "wget --post-file" };
		if (/\s--body-file\s/i.test(args)) return { matched: true, pattern: "wget --body-file" };
		if (/\s--method=PUT\b/i.test(args)) return { matched: true, pattern: "wget --method=PUT" };
		return { matched: false, pattern: "" };
	}

	// Interpreters: only flag if explicit upload keywords or script filename
	if (INTERPRETER_COMMS.has(commLower)) {
		if (/\bupload\b|\bexfil\b|\bscp\b|\bsftp\b/i.test(args)) {
			return { matched: true, pattern: `${commLower} upload_keyword` };
		}
		// Check if executing a script with upload/exfil in filename
		const scriptMatch = args.match(/\b\S*(?:upload|exfil)\S*\.\w+/i);
		if (scriptMatch) {
			return { matched: true, pattern: `${commLower} script:${scriptMatch[0]}` };
		}
		return { matched: false, pattern: "" };
	}

	// nc/ncat: flag if args suggest file transfer (e.g., redirect from file)
	if (commLower === "nc" || commLower === "ncat") {
		if (/<\s*\S+/.test(args)) return { matched: true, pattern: `${commLower} stdin_redirect` };
		return { matched: false, pattern: "" };
	}

	return { matched: false, pattern: "" };
}
function extractUploadFilePath(comm: string, args: string): string | null {
	const commLower = comm.toLowerCase();
	const parts = args.split(/\s+/);

	if (commLower === "curl") {
		for (let i = 0; i < parts.length; i++) {
			if ((parts[i] === "-T" || parts[i] === "--upload-file") && i + 1 < parts.length) {
				return parts[i + 1];
			}
		}
	}

	if (commLower === "scp") {
		// scp [options] source... dest — first non-option arg that isn't a flag value is local source
		for (let i = 1; i < parts.length; i++) {
			const p = parts[i];
			if (p.startsWith("-")) continue;
			// If it contains ':', it's a remote spec
			if (p.includes(":")) continue;
			return p;
		}
	}

	if (commLower === "rsync") {
		// rsync [options] source dest — first non-option, non-flag-value arg
		const skipNext = new Set(["-e", "--rsh", "--exclude", "--include", "--filter", "-f", "--files-from"]);
		let skip = false;
		for (let i = 1; i < parts.length; i++) {
			if (skip) { skip = false; continue; }
			const p = parts[i];
			if (skipNext.has(p)) { skip = true; continue; }
			if (p.startsWith("-")) continue;
			return p;
		}
	}

	return null;
}

function getFileSizeBytes(filePath: string): number | null {
	try {
		const st = statSync(filePath);
		return st.size;
	} catch {
		return null;
	}
}

interface EndpointProcessEvent {
	type: "endpoint_process";
	timestamp: string;
	pid: number;
	ppid: number;
	user: string;
	comm: string;
	args: string;
	processTree: string[];
	matchedPattern: string;
	filePath: string | null;
	fileSizeBytes: number | null;
}

export type EndpointEvent = EndpointProcessEvent;

export interface EndpointMonitorHandle {
	stop: () => void;
}

interface ProcInfo {
	pid: number;
	ppid: number;
	user: string;
	comm: string;
	args: string;
}

function buildAncestry(pid: number, procMap: Map<number, ProcInfo>): string[] {
	const chain: string[] = [];
	let current = pid;
	const visited = new Set<number>();
	while (true) {
		if (visited.has(current)) break;
		visited.add(current);
		const info = procMap.get(current);
		if (!info) break;
		chain.unshift(info.comm);
		if (info.ppid <= 1 || !procMap.has(info.ppid)) break;
		current = info.ppid;
	}
	return chain;
}

function getPsCommand(): string[] {
	if (process.platform === "darwin") {
		return ["ps", "-axo", "pid=,ppid=,user=,command="];
	}
	// Linux and other POSIX
	return ["ps", "-eo", "pid=,ppid=,user=,args="];
}

function startProcessPoller(
	onEvent: (e: EndpointEvent) => void,
): EndpointMonitorHandle {
	let running = true;
	const seenPids = new Set<number>();
	const psCmd = getPsCommand();

	console.log(`[endpoint] Using ps command: ${psCmd.join(" ")}`);

	const poll = async () => {
		while (running) {
			try {
				const proc = Bun.spawn(psCmd, {
					stdout: "pipe",
					stderr: null,
					stdin: null,
				});

				const output = await new Response(proc.stdout).text();
				await proc.exited.catch(() => {});

				const lines = output.split("\n");

				// Build full process map for this cycle
				const procMap = new Map<number, ProcInfo>();
				const candidates: ProcInfo[] = [];

				for (let i = 0; i < lines.length; i++) {
					const line = lines[i].trim();
					if (!line) continue;

					const parts = line.split(/\s+/);
					if (parts.length < 4) continue;

					const pid = parseInt(parts[0], 10);
					const ppid = parseInt(parts[1], 10);
					const user = parts[2];
					const args = parts.slice(3).join(" ");
					const comm = args.split(/\s+/)[0].split("/").pop() || "";
					const cleanComm = comm.replace(/^\(+|\)+$/g, "");

					if (Number.isNaN(pid) || Number.isNaN(ppid)) continue;

					const info: ProcInfo = { pid, ppid, user, comm: cleanComm, args };
					procMap.set(pid, info);

					// Check if this is a suspicious comm we care about
					const commLower = cleanComm.toLowerCase();
					const isTrackedComm = SUSPICIOUS_COMMS.some(
						(c) => commLower === c || commLower.endsWith("/" + c),
					);
					if (isTrackedComm && !seenPids.has(pid)) {
						candidates.push(info);
					}
				}

				// Filter candidates to only actual uploads
				for (const info of candidates) {
					const isParenthesized = /^\(.*\)$/.test(info.args);

					let matchedPattern: string | null = null;

					if (isParenthesized) {
						// Kernel threads or zombies — only flag dedicated transfer tools
						const commLower = info.comm.toLowerCase();
						if (DEDICATED_TRANSFER_TOOLS.includes(commLower)) {
							matchedPattern = commLower;
						}
					} else {
						const result = checkUploadIndicators(info.comm, info.args);
						if (result.matched) {
							matchedPattern = result.pattern;
						}
					}

					if (!matchedPattern) continue;

					seenPids.add(info.pid);
					const processTree = buildAncestry(info.pid, procMap);

 const rawPath = extractUploadFilePath(info.comm, info.args);
 const filePath = rawPath ? pathResolve(rawPath) : null;
 const fileSizeBytes = filePath ? getFileSizeBytes(filePath) : null;

 console.log("[endpoint] Upload detected:", { pid: info.pid, user: info.user, comm: info.comm, pattern: matchedPattern, tree: processTree, filePath, fileSizeBytes });

					onEvent({
						type: "endpoint_process",
						timestamp: new Date().toISOString(),
						pid: info.pid,
						ppid: info.ppid,
						user: info.user,
						comm: info.comm,
						args: isParenthesized ? info.comm : info.args,
						processTree,
						matchedPattern,
						filePath,
						fileSizeBytes,
					});
				}
			} catch (err: unknown) {
				if (running) {
					const msg = err instanceof Error ? err.message : String(err);
					console.error(`[endpoint] Process poll error: ${msg}`);
				}
			}

			const { promise, resolve } = Promise.withResolvers<void>();
			setTimeout(resolve, 500);
			await promise;
		}
	};

	poll();

	return {
		stop() {
			running = false;
		},
	};
}

export function startEndpointMonitor(
	onEvent: (e: EndpointEvent) => void,
): EndpointMonitorHandle {
	const processPoller = startProcessPoller(onEvent);

	return {
		stop() {
			processPoller.stop();
		},
	};
}