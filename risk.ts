// Backend Risk Engine: classifies events before SSE emission
// Evaluates NetworkEvent and EndpointProcessEvent, appends risk fields

export type RiskLevel = "low" | "medium" | "high" | "critical";
export type Classification = "known_safe" | "unknown" | "suspicious";

export interface RiskAssessment {
	riskLevel: RiskLevel;
	riskScore: number; // 0-100
	classification: Classification;
	riskFactors: string[];
}

const SAFE_SYSTEM_DIRS = [
	"/usr/bin/",
	"/bin/",
	"/usr/sbin/",
	"/sbin/",
	"/System/",
	"/Applications/",
	"/opt/homebrew/bin/",
];

const SUSPICIOUS_DIRS = ["/tmp/", "/var/tmp/"];
const DOWNLOADS_PATTERNS = ["~/Downloads/", "/Downloads/"];
const INTERPRETER_COMMS = new Set([
	"python",
	"python3",
	"node",
	"bun",
	"sh",
	"bash",
	"zsh",
	"perl",
	"ruby",
	"php",
]);
const STANDARD_PORTS = new Set([80, 443, 22]);

function isPrivateIp(ip: string): boolean {
	if (!ip) return false;
	if (ip === "127.0.0.1" || ip === "::1" || ip === "localhost") return true;
	if (ip.startsWith("10.")) return true;
	if (ip.startsWith("192.168.")) return true;
	if (ip.startsWith("172.")) {
		const parts = ip.split(".");
		if (parts.length >= 2) {
			const second = parseInt(parts[1], 10);
			if (second >= 16 && second <= 31) return true;
		}
	}
	return false;
}

function isInSafeSystemDir(path: string): boolean {
	for (const dir of SAFE_SYSTEM_DIRS) {
		if (path.startsWith(dir)) return true;
	}
	return false;
}

function isInSuspiciousDir(path: string): boolean {
	for (const dir of SUSPICIOUS_DIRS) {
		if (path.startsWith(dir)) return true;
	}
	for (const pat of DOWNLOADS_PATTERNS) {
		if (path.includes(pat)) return true;
	}
	return false;
}

function hasObfuscation(args: string): boolean {
	const lower = args.toLowerCase();
	if (lower.includes("base64")) return true;
	if (lower.includes("eval(")) return true;
	if (lower.includes("exec(")) return true;
	// Check for long hex/base64-like strings (>40 chars of alnum+/=)
	const suspiciousPattern = /[A-Za-z0-9+/=]{40,}/;
	if (suspiciousPattern.test(args)) return true;
	return false;
}

function scoreToLevel(score: number): RiskLevel {
	if (score >= 80) return "critical";
	if (score >= 60) return "high";
	if (score >= 30) return "medium";
	return "low";
}

interface ProcessEventData {
	type: "endpoint_process";
	args: string;
	comm: string;
	processTree: string[];
	fileSizeBytes: number | null;
	[key: string]: unknown;
}

interface NetworkEventData {
	type: "network";
	dstIp: string;
	dstPort: number;
	bytes: number;
	[key: string]: unknown;
}

type EventData = ProcessEventData | NetworkEventData;

export function assessRisk(event: EventData): RiskAssessment {
	if (event.type === "endpoint_process") {
		return assessProcessRisk(event);
	}
	if (event.type === "network") {
		return assessNetworkRisk(event);
	}
	// Status events or unknown: default safe
	return {
		riskLevel: "low",
		riskScore: 0,
		classification: "known_safe",
		riskFactors: [],
	};
}

function assessProcessRisk(event: ProcessEventData): RiskAssessment {
	const factors: string[] = [];
	let score = 0;
	let classification: Classification = "unknown";

	const binaryPath = event.args.split(/\s+/)[0] || event.comm;
	const processTree = event.processTree || [];
	const fullCmdLine = event.args;

	// Check suspicious directories in binary path
	const binaryInTmp = isInSuspiciousDir(binaryPath);
	const binaryInDownloads =
		binaryPath.includes("/Downloads/") || binaryPath.includes("~/Downloads/");

	// Check ancestry for suspicious paths
	let suspiciousAncestry = false;
	for (const ancestor of processTree) {
		if (isInSuspiciousDir(ancestor)) {
			suspiciousAncestry = true;
			break;
		}
	}

	// Check for obfuscation
	const obfuscated = hasObfuscation(fullCmdLine);

	// Determine if binary is in safe system directory
	const inSafeDir = isInSafeSystemDir(binaryPath);

	// Check if executed via interpreter
	const commLower = event.comm.toLowerCase();
	const isInterpreter = INTERPRETER_COMMS.has(commLower);

	// --- Classification Logic ---

	// Suspicious conditions (highest priority)
	if (binaryInTmp || suspiciousAncestry) {
		classification = "suspicious";
		score = 85;
		if (binaryInTmp) factors.push("TMP_EXECUTION");
		if (suspiciousAncestry) factors.push("SUSPICIOUS_ANCESTRY");
	} else if (binaryInDownloads) {
		classification = "suspicious";
		score = 80;
		factors.push("DOWNLOADS_FOLDER_EXECUTION");
	} else if (obfuscated) {
		classification = "suspicious";
		score = 85;
		factors.push("OBFUSCATED_ARGS");
	} else if (inSafeDir && !suspiciousAncestry) {
		// Known safe
		classification = "known_safe";
		score = 5;
	} else if (isInterpreter) {
		// Interpreter execution without clear safe script
		classification = "unknown";
		score = 55;
		factors.push("INTERPRETER_EXECUTION");
		// Check if the script path itself is in a user directory
		const scriptArg = event.args.split(/\s+/)[1];
		if (scriptArg && (scriptArg.startsWith("~/") || scriptArg.startsWith("/Users/"))) {
			factors.push("USER_SPACE_BINARY");
			score = 60;
		} else if (scriptArg && isInSuspiciousDir(scriptArg)) {
			classification = "suspicious";
			factors.push("TMP_EXECUTION");
			score = 85;
		} else {
			factors.push("UNKNOWN_SCRIPT");
		}
	} else if (binaryPath.startsWith("~/") || binaryPath.startsWith("/Users/")) {
		classification = "unknown";
		score = 50;
		factors.push("USER_SPACE_BINARY");
	} else {
		// Default unknown for anything not clearly safe
		classification = "unknown";
		score = 45;
	}

	// Upload-specific modifiers
	if (event.fileSizeBytes != null && event.fileSizeBytes > 10 * 1024 * 1024) {
		factors.push("MASSIVE_UPLOAD");
		score = Math.min(score + 15, 100);
	}

	return {
		riskLevel: scoreToLevel(score),
		riskScore: Math.min(score, 100),
		classification,
		riskFactors: factors,
	};
}

function assessNetworkRisk(event: NetworkEventData): RiskAssessment {
	const factors: string[] = [];
	let score = 0;
	let classification: Classification = "unknown";

	const dstIp = event.dstIp || "";
	const dstPort = event.dstPort || 0;
	const bytes = event.bytes || 0;

	const isPrivate = isPrivateIp(dstIp);
	const isStandardPort = STANDARD_PORTS.has(dstPort);

	if (isPrivate) {
		classification = "known_safe";
		score = 5;
		factors.push("LOCAL_NETWORK");
	} else if (!isStandardPort && dstPort > 1024) {
		classification = "suspicious";
		score = 75;
		factors.push("NON_STANDARD_PORT");
	} else if (isStandardPort) {
		classification = "unknown";
		score = 40;
		factors.push("PUBLIC_INTERNET");
	} else {
		classification = "unknown";
		score = 45;
		factors.push("PUBLIC_INTERNET");
	}

	// Large raw payload without TLS context
	if (bytes > 10240 && !isPrivate) {
		factors.push("LARGE_RAW_PAYLOAD");
		score = Math.min(score + 15, 100);
	}

	return {
		riskLevel: scoreToLevel(score),
		riskScore: Math.min(score, 100),
		classification,
		riskFactors: factors,
	};
}