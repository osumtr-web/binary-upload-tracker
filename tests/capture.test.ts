import { describe, expect, test } from "bun:test";

// Replicate the exact regex from capture.ts line 119-120 for unit testing
const lineRegex =
	/^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+IP\s+(\d+\.\d+\.\d+\.\d+)\.(\d+)\s+>\s+(\d+\.\d+\.\d+\.\d+)\.(\d+):\s+tcp\s+(\d+)/;

interface ParsedLine {
	timestamp: string;
	srcIp: string;
	srcPort: number;
	dstIp: string;
	dstPort: number;
	bytes: number;
}

function parseTcpdumpLine(line: string): ParsedLine | null {
	const m = line.match(lineRegex);
	if (!m) return null;
	return {
		timestamp: m[1],
		srcIp: m[2],
		srcPort: parseInt(m[3], 10),
		dstIp: m[4],
		dstPort: parseInt(m[5], 10),
		bytes: parseInt(m[6], 10),
	};
}

describe("tcpdump line regex parsing", () => {
	test("parses standard tcpdump line correctly", () => {
		const line = "2026-11-18 10:23:45.123456 IP 192.168.1.5.54321 > 93.184.216.34.443: tcp 1500";
		const result = parseTcpdumpLine(line);
		expect(result).not.toBeNull();
		expect(result!.timestamp).toBe("2026-11-18 10:23:45.123456");
		expect(result!.srcIp).toBe("192.168.1.5");
		expect(result!.srcPort).toBe(54321);
		expect(result!.dstIp).toBe("93.184.216.34");
		expect(result!.dstPort).toBe(443);
		expect(result!.bytes).toBe(1500);
	});

	test("parses HTTP port 80 traffic", () => {
		const line = "2026-11-18 14:00:00.000001 IP 10.0.0.1.12345 > 203.0.113.50.80: tcp 256";
		const result = parseTcpdumpLine(line);
		expect(result).not.toBeNull();
		expect(result!.dstPort).toBe(80);
		expect(result!.bytes).toBe(256);
	});

	test("parses high port traffic", () => {
		const line = "2026-11-18 09:15:30.999999 IP 172.16.0.100.60000 > 10.10.10.10.8080: tcp 65535";
		const result = parseTcpdumpLine(line);
		expect(result).not.toBeNull();
		expect(result!.srcPort).toBe(60000);
		expect(result!.dstPort).toBe(8080);
		expect(result!.bytes).toBe(65535);
	});

	test("returns null for non-matching lines", () => {
		expect(parseTcpdumpLine("listening on en0, link-type EN10MB")).toBeNull();
		expect(parseTcpdumpLine("tcpdump: verbose output suppressed")).toBeNull();
		expect(parseTcpdumpLine("")).toBeNull();
		expect(parseTcpdumpLine("2026-11-18 10:23:45.123456 ARP ...")).toBeNull();
	});

	test("handles microsecond precision timestamps", () => {
		const line = "2026-01-01 00:00:00.000000 IP 1.2.3.4.1 > 5.6.7.8.443: tcp 64";
		const result = parseTcpdumpLine(line);
		expect(result).not.toBeNull();
		expect(result!.timestamp).toBe("2026-01-01 00:00:00.000000");
	});

	test("extracts correct source and destination IPs independently", () => {
		const line = "2026-11-18 12:00:00.500000 IP 10.255.255.1.9999 > 192.168.0.1.8443: tcp 1024";
		const result = parseTcpdumpLine(line);
		expect(result).not.toBeNull();
		expect(result!.srcIp).toBe("10.255.255.1");
		expect(result!.dstIp).toBe("192.168.0.1");
		expect(result!.srcPort).toBe(9999);
		expect(result!.dstPort).toBe(8443);
	});
});