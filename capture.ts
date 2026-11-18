// Network capture module using tcpdump
// Parses TCP traffic on common HTTP ports and emits structured events
// Cross-platform: macOS (darwin) and Linux

import type { Subprocess } from "bun";
import { readFileSync, readdirSync } from "fs";
import { execSync } from "child_process";

const MIN_BYTES_DEFAULT = 64;

function getDefaultInterface(): string {
	if (process.platform === "darwin") {
		return "en0";
	}

	// Linux: try to find the active default route interface
	try {
		const output = execSync("ip route show default", { encoding: "utf-8", timeout: 2000 }).trim();
		// Format: "default via 192.168.1.1 dev wlan0 proto dhcp ..."
		const match = output.match(/\bdev\s+(\S+)/);
		if (match && match[1]) {
			console.log(`[capture] Detected default interface via ip route: ${match[1]}`);
			return match[1];
		}
	} catch {
		// ip command not available or failed
	}

	// Fallback: scan /sys/class/net/ for a non-loopback, operational interface
	try {
		const netDir = "/sys/class/net/";
		const ifaces = readdirSync(netDir).filter((name) => name !== "lo");
		for (const iface of ifaces) {
			try {
				const operstate = readFileSync(`${netDir}${iface}/operstate`, "utf-8").trim();
				if (operstate === "up") {
					console.log(`[capture] Detected active interface via sysfs: ${iface}`);
					return iface;
				}
			} catch {
				// skip unreadable interfaces
			}
		}
		// If none are "up", return first non-lo interface
		if (ifaces.length > 0) {
			console.log(`[capture] No active interface found, falling back to first: ${ifaces[0]}`);
			return ifaces[0];
		}
	} catch {
		// /sys/class/net not accessible
	}

	console.log("[capture] Could not detect interface, defaulting to wlan0");
	return "wlan0";
}

interface NetworkEvent {
	type: "network";
	timestamp: string;
	srcIp: string;
	dstIp: string;
	dstPort: number;
	bytes: number;
	rawLine: string;
}

interface StatusEvent {
	type: "status";
	message: string;
}

export type CaptureEvent = NetworkEvent | StatusEvent;

export interface CaptureHandle {
	stop: () => void;
	status: () => string;
}

interface CaptureOptions {
	iface?: string;
	minBytes?: number;
}

type TcpdumpProcess = Subprocess<"pipe", "pipe", null>;

function extractErrorMessage(err: unknown): string {
	return err instanceof Error ? err.message : String(err);
}

export function startNetworkCapture(
	onEvent: (e: CaptureEvent) => void,
	opts?: CaptureOptions,
): CaptureHandle {
	const iface = opts?.iface ?? process.env.BUT_INTERFACE ?? getDefaultInterface();
	const minBytes = opts?.minBytes ?? MIN_BYTES_DEFAULT;
	let state: "running" | "stopped" = "running";
	let proc: TcpdumpProcess | null = null;

	console.log(`[capture] Starting tcpdump on interface: ${iface}`);

	const filter = `tcp and (port 80 or port 443 or port 8080 or port 8443)`;

	try {
		proc = Bun.spawn(
			["sudo", "tcpdump", "-i", iface, "-l", "-n", "-q", "-tttt", "-s", "0", filter],
			{ stdout: "pipe", stderr: "pipe", stdin: null },
		);
	} catch (err: unknown) {
		state = "stopped";
		onEvent({ type: "status", message: `capture_stopped: spawn_failed: ${extractErrorMessage(err)}` });
		return {
			stop() {},
			status: () => state,
		};
	}

	// Line pattern: <timestamp> IP <src>.<port> > <dst>.<port>: tcp <length>
	// Example: 2026-11-18 10:23:45.123456 IP 192.168.1.5.54321 > 93.184.216.34.443: tcp 1500
	const lineRegex =
		/^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+IP\s+(\d+\.\d+\.\d+\.\d+)\.(\d+)\s+>\s+(\d+\.\d+\.\d+\.\d+)\.(\d+):\s+tcp\s+(\d+)/;

	let buffer = "";

	// Read stdout line by line
	(async () => {
		const reader = proc!.stdout.getReader();
		const decoder = new TextDecoder();
		try {
			while (true) {
				const chunk = await reader.read();
				if (chunk.done) break;
				buffer += decoder.decode(chunk.value, { stream: true });
				let newlineIdx: number;
				while ((newlineIdx = buffer.indexOf("\n")) !== -1) {
					const line = buffer.slice(0, newlineIdx).trim();
					buffer = buffer.slice(newlineIdx + 1);
					if (!line) continue;
					const m = line.match(lineRegex);
					if (!m) continue;
					const payloadLength = parseInt(m[6], 10);
					if (payloadLength < minBytes) continue;
					onEvent({
						type: "network",
						timestamp: m[1],
						srcIp: m[2],
						dstIp: m[4],
						dstPort: parseInt(m[5], 10),
						bytes: payloadLength,
						rawLine: line,
					});
				}
			}
		} catch (err: unknown) {
			if (state === "running") {
				console.error(`[capture] stdout read error: ${extractErrorMessage(err)}`);
			}
		} finally {
			reader.releaseLock();
		}
	})();

	// Drain stderr
	(async () => {
		const reader = proc!.stderr.getReader();
		const decoder = new TextDecoder();
		try {
			while (true) {
				const chunk = await reader.read();
				if (chunk.done) break;
				const text = decoder.decode(chunk.value, { stream: true }).trim();
				if (text) console.error(`[tcpdump] ${text}`);
			}
		} catch {
			// ignore
		} finally {
			reader.releaseLock();
		}
	})();

	// Handle process exit
	proc.exited
		.then((code) => {
			if (state === "running") {
				state = "stopped";
				onEvent({ type: "status", message: `capture_stopped: exited_with_code_${code}` });
			}
		})
		.catch((err: unknown) => {
			if (state === "running") {
				state = "stopped";
				onEvent({ type: "status", message: `capture_stopped: error: ${extractErrorMessage(err)}` });
			}
		});

	return {
		stop() {
			if (state === "stopped") return;
			state = "stopped";
			try {
				proc?.kill("SIGTERM");
			} catch {
				// already dead
			}
			onEvent({ type: "status", message: "capture_stopped: user_requested" });
		},
		status: () => state,
	};
}