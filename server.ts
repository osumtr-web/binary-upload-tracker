// HTTP server with SSE event streaming and ring buffer event store
// Serves dashboard, streams events, provides stats API

import { readFileSync } from "fs";
import { join } from "path";
import { startNetworkCapture, type CaptureEvent } from "./capture";
import { assessRisk, type RiskAssessment } from "./risk";
import { startEndpointMonitor, type EndpointEvent } from "./endpoint";
const PORT = 3777;
const HOST = "127.0.0.1";
const MAX_EVENTS = 500;
const MIN_BYTES = parseInt(process.env.MIN_BYTES ?? "64", 10) || 64;

// --- Ring Buffer ---
class RingBuffer<T> {
	private buffer: (T | undefined)[];
	private head = 0;
	private count = 0;
	private capacity: number;

	constructor(capacity: number) {
		this.capacity = capacity;
		this.buffer = new Array(capacity);
	}

	push(item: T): void {
		this.buffer[this.head] = item;
		this.head = (this.head + 1) % this.capacity;
		if (this.count < this.capacity) this.count++;
	}

	getAll(): T[] {
		const result: T[] = [];
		if (this.count === 0) return result;
		const start = this.count < this.capacity ? 0 : this.head;
		for (let i = 0; i < this.count; i++) {
			const idx = (start + i) % this.capacity;
			result.push(this.buffer[idx]!);
		}
		return result;
	}

	get length(): number {
		return this.count;
	}
}

// --- Event Store & Stats ---
type TrackerEvent = CaptureEvent | EndpointEvent;

interface TrackedEvent extends RiskAssessment {
	type: string;
	timestamp?: string;
	dstIp?: string;
	comm?: string;
	[key: string]: unknown;
}

interface DstIpEntry {
	ip: string;
	count: number;
}

interface ProcessEntry {
	comm: string;
	count: number;
}

interface StatsResponse {
	totalEvents: number;
	networkCount: number;
	endpointFileCount: number;
	endpointProcessCount: number;
	topDstIps: DstIpEntry[];
	topProcesses: ProcessEntry[];
	lastEventTimestamp: string | null;
	knownSafeCount: number;
	unknownCount: number;
	suspiciousCount: number;
}

const eventStore = new RingBuffer<TrackedEvent>(MAX_EVENTS);
let networkCount = 0;
let endpointFileCount = 0;
let endpointProcessCount = 0;
let knownSafeCount = 0;
let unknownCount = 0;
let suspiciousCount = 0;
let lastEventTimestamp: string | null = null;
const dstIpCounts = new Map<string, number>();
const processCommCounts = new Map<string, number>();

function recordEvent(e: TrackerEvent): void {
	const risk = assessRisk(e as Parameters<typeof assessRisk>[0]);
	const tracked: TrackedEvent = {
		...e,
		riskLevel: risk.riskLevel,
		riskScore: risk.riskScore,
		classification: risk.classification,
		riskFactors: risk.riskFactors,
	};
	eventStore.push(tracked);
	lastEventTimestamp = tracked.timestamp ?? new Date().toISOString();

	switch (tracked.classification) {
		case "known_safe":
			knownSafeCount++;
			break;
		case "unknown":
			unknownCount++;
			break;
		case "suspicious":
			suspiciousCount++;
			break;
	}

	switch (tracked.type) {
		case "network":
			networkCount++;
			if (tracked.dstIp) {
				dstIpCounts.set(tracked.dstIp, (dstIpCounts.get(tracked.dstIp) ?? 0) + 1);
			}
			break;
		case "endpoint_file":
			endpointFileCount++;
			break;
		case "endpoint_process":
			endpointProcessCount++;
			if (tracked.comm) {
				processCommCounts.set(tracked.comm, (processCommCounts.get(tracked.comm) ?? 0) + 1);
			}
			break;
	}
}

function getStats(): StatsResponse {
	const topDstIps: DstIpEntry[] = [...dstIpCounts.entries()]
		.sort((a, b) => b[1] - a[1])
		.slice(0, 10)
		.map(([ip, count]) => ({ ip, count }));

	const topProcesses: ProcessEntry[] = [...processCommCounts.entries()]
		.sort((a, b) => b[1] - a[1])
		.slice(0, 10)
		.map(([comm, count]) => ({ comm, count }));

	return {
		totalEvents: eventStore.length,
		networkCount,
		endpointFileCount,
		endpointProcessCount,
		topDstIps,
		topProcesses,
		lastEventTimestamp,
		knownSafeCount,
		unknownCount,
		suspiciousCount,
	};
}

// --- SSE Client Management ---
interface SSEClient {
	writer: WritableStreamDefaultWriter<Uint8Array>;
	queue: Promise<void>;
}

const sseClients = new Set<SSEClient>();
const encoder = new TextEncoder();

function formatSSE(data: string): Uint8Array {
	return encoder.encode(`data: ${data}\n\n`);
}

function addSSEClient(writer: WritableStreamDefaultWriter<Uint8Array>): SSEClient {
	const client: SSEClient = {
		writer,
		queue: Promise.resolve(),
	};
	sseClients.add(client);
	return client;
}

function removeSSEClient(client: SSEClient): void {
	sseClients.delete(client);
	try {
		client.writer.releaseLock();
	} catch {
		// ignore
	}
}

function broadcastEvent(e: TrackerEvent): void {
	const data = formatSSE(JSON.stringify(e));
	for (const client of sseClients) {
		client.queue = client.queue.then(async () => {
			try {
				await client.writer.write(data);
			} catch {
				removeSSEClient(client);
			}
		});
	}
}

// --- Dashboard HTML ---
const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Binary Upload Tracker</title>
<style>
  :root { --bg: #0f1923; --surface: #1a2733; --border: #2d3e4d; --text: #e0e6ed; --accent: #e8913a; --green: #4caf84; --red: #d94f4f; --muted: #7a8fa0; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { background: var(--bg); color: var(--text); font-family: 'SF Mono', 'Menlo', monospace; font-size: 13px; padding: 20px; }
  h1 { color: var(--accent); margin-bottom: 16px; font-size: 18px; }
  #stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 20px; }
  .stat { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 12px; }
  .stat-label { color: var(--muted); font-size: 11px; text-transform: uppercase; }
  .stat-value { font-size: 22px; font-weight: bold; margin-top: 4px; color: var(--accent); }
  #events { max-height: 70vh; overflow-y: auto; }
  .event { background: var(--surface); border: 1px solid var(--border); border-radius: 4px; padding: 10px 12px; margin-bottom: 6px; font-size: 12px; word-break: break-all; }
  .event.network { border-left: 3px solid var(--accent); }
  .event.endpoint_file { border-left: 3px solid var(--green); }
  .event.endpoint_process { border-left: 3px solid var(--red); }
  .event.status { border-left: 3px solid var(--muted); }
  .event-type { font-weight: bold; text-transform: uppercase; font-size: 10px; margin-bottom: 4px; }
  .event.network .event-type { color: var(--accent); }
  .event.endpoint_file .event-type { color: var(--green); }
  .event.endpoint_process .event-type { color: var(--red); }
  .event.status .event-type { color: var(--muted); }
  .event-detail { color: var(--muted); }
</style>
</head>
<body>
<h1>Binary Upload Tracker</h1>
<div id="stats"></div>
<div id="events"></div>
<script>
var eventsEl = document.getElementById('events');
var statsEl = document.getElementById('stats');
var MAX_DISPLAY = 200;

function renderStats(s) {
  statsEl.innerHTML = [
    ['Total Events', s.totalEvents],
    ['Network', s.networkCount],
    ['Files', s.endpointFileCount],
    ['Processes', s.endpointProcessCount],
    ['Last Event', s.lastEventTimestamp ? new Date(s.lastEventTimestamp).toLocaleTimeString() : '-']
  ].map(function(pair) {
    return '<div class="stat"><div class="stat-label">' + pair[0] + '</div><div class="stat-value">' + pair[1] + '</div></div>';
  }).join('');
}

function addEvent(e) {
  var div = document.createElement('div');
  div.className = 'event ' + (e.type || '').replace(/[^a-z_]/g, '');
  var detail = '';
  if (e.type === 'network') detail = e.srcIp + ' -> ' + e.dstIp + ':' + e.dstPort + ' (' + e.bytes + 'B)';
  else if (e.type === 'endpoint_file') detail = e.path + ' (' + e.size + 'B, H=' + e.entropy + ')';
  else if (e.type === 'endpoint_process') detail = '[' + e.pid + '] ' + e.comm + ' ' + e.args;
  else if (e.type === 'status') detail = e.message;
  div.innerHTML = '<div class="event-type">' + e.type + '</div><div class="event-detail">' + (e.timestamp || '') + ' ' + detail + '</div>';
  eventsEl.prepend(div);
  while (eventsEl.children.length > MAX_DISPLAY) eventsEl.lastChild.remove();
}

function connectSSE() {
  var es = new EventSource('/events');
  es.onmessage = function(msg) {
    try { addEvent(JSON.parse(msg.data)); } catch(ex) {}
  };
  es.onerror = function() { es.close(); setTimeout(connectSSE, 2000); };
}

function fetchStats() {
  fetch('/api/stats').then(function(r) { return r.json(); }).then(function(s) {
    renderStats(s);
  }).catch(function() {});
}

connectSSE();
fetchStats();
setInterval(fetchStats, 3000);
</script>
</body>
</html>`;

function loadDashboard(): string {
	try {
		const htmlPath = join(import.meta.dir, "dashboard.html");
		return readFileSync(htmlPath, "utf-8");
	} catch {
		return DASHBOARD_HTML;
	}
}

// --- Parse CLI args for interface ---
function parseInterface(): string {
	const args = process.argv.slice(2);
	const idx = args.indexOf("--interface");
	if (idx !== -1 && args[idx + 1]) {
		return args[idx + 1];
	}
	return "en0";
}

// --- Server ---
const dashboardHtml = loadDashboard();
const iface = parseInterface();

const capture = startNetworkCapture(
	(e) => {
		recordEvent(e);
		broadcastEvent(e);
	},
	{ iface, minBytes: MIN_BYTES },
);

const endpoint = startEndpointMonitor(
	(e) => {
		recordEvent(e);
		broadcastEvent(e);
	},
	{ minBytes: MIN_BYTES },
);

const server = Bun.serve({
	hostname: HOST,
	port: PORT,
	reusePort: false,

	fetch(req) {
		const url = new URL(req.url);

		if (url.pathname === "/" && req.method === "GET") {
			return new Response(dashboardHtml, {
				headers: { "Content-Type": "text/html; charset=utf-8" },
			});
		}

		if (url.pathname === "/events" && req.method === "GET") {
			const stream = new TransformStream();
			const writer = stream.writable.getWriter();
			const client = addSSEClient(writer);

			const buffered = eventStore.getAll();
			let initQueue = Promise.resolve();
			for (const evt of buffered) {
				initQueue = initQueue.then(() =>
					writer.write(formatSSE(JSON.stringify(evt))),
				);
			}
			initQueue.catch(() => removeSSEClient(client));

			req.signal.addEventListener("abort", () => {
				removeSSEClient(client);
			});

			return new Response(stream.readable, {
				headers: {
					"Content-Type": "text/event-stream",
					"Cache-Control": "no-cache",
					Connection: "keep-alive",
				},
			});
		}

		if (url.pathname === "/api/stats" && req.method === "GET") {
			return Response.json(getStats());
		}

		return new Response("Not Found", { status: 404 });
	},
});

console.log(`Binary Upload Tracker running at http://${HOST}:${PORT}`);

// --- Graceful Shutdown ---
function shutdown() {
	capture.stop();
	endpoint.stop();
	for (const client of sseClients) {
		removeSSEClient(client);
	}
	server.stop(true);
	process.exit(0);
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);