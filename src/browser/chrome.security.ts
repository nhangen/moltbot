import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

export const MIN_CHROMIUM_SECURITY_VERSION = "156.0.8078.73";
export const PINNED_CFT_VERSION = "156.0.8078.80";
export const PINNED_CFT_REVISION = "1706539";

export const CHROMIUM_SECURITY_CVES = [
  "CVE-2026-118306",
  "CVE-2026-118331",
  "CVE-2026-118348",
  "CVE-2026-118344",
] as const;

export const CHROMIUM_SECURITY_ADVISORY =
  "https://chromereleases.googleblog.com/2026/10/stable-channel-update-for-desktop_0562499947.html";

export function parseChromiumVersion(raw: string): [number, number, number, number] | null {
  if (!raw || typeof raw !== "string") return null;
  const match = raw.match(/(\d+)\.(\d+)\.(\d+)\.(\d+)/);
  if (!match) return null;
  return [
    Number.parseInt(match[1], 10),
    Number.parseInt(match[2], 10),
    Number.parseInt(match[3], 10),
    Number.parseInt(match[4], 10),
  ];
}

export function compareChromiumVersions(a: string, b: string): number {
  const partsA = parseChromiumVersion(a);
  const partsB = parseChromiumVersion(b);
  if (!partsA || !partsB) {
    throw new Error(`Cannot compare invalid Chromium versions: "${a}" and "${b}"`);
  }
  for (let i = 0; i < 4; i += 1) {
    if (partsA[i] > partsB[i]) return 1;
    if (partsA[i] < partsB[i]) return -1;
  }
  return 0;
}

export function isChromiumVersionAtLeast(
  version: string,
  minimum = MIN_CHROMIUM_SECURITY_VERSION,
): boolean {
  try {
    return compareChromiumVersions(version, minimum) >= 0;
  } catch {
    return false;
  }
}

export function assertBrowserSecurityBaseline(
  version: string,
  context?: string,
  minimum = MIN_CHROMIUM_SECURITY_VERSION,
): void {
  if (!isChromiumVersionAtLeast(version, minimum)) {
    const ctxMsg = context ? ` for ${context}` : "";
    throw new Error(
      `Refusing browser (version ${version})${ctxMsg}: version is below minimum security baseline ${minimum}. ` +
        `Prior releases are vulnerable to ${CHROMIUM_SECURITY_CVES.join(", ")}. ` +
        `See advisory: ${CHROMIUM_SECURITY_ADVISORY}. Update browser to ${minimum} or newer.`,
    );
  }
}

export function getBrowserExecutableVersion(exePath: string, timeoutMs = 1500): string | null {
  try {
    if (!fs.existsSync(exePath)) return null;
  } catch {
    return null;
  }

  // 1. Try running `--version`
  try {
    const output = execFileSync(exePath, ["--version"], {
      timeout: timeoutMs,
      encoding: "utf8",
      maxBuffer: 256 * 1024,
      stdio: ["pipe", "pipe", "ignore"],
    });
    const parsed = parseChromiumVersion(String(output ?? ""));
    if (parsed) return parsed.join(".");
  } catch {
    // ignore
  }

  // 2. On macOS, try reading Info.plist if inside an .app bundle
  if (process.platform === "darwin" && exePath.includes(".app")) {
    try {
      const appDir = exePath.slice(0, exePath.indexOf(".app") + 4);
      const plistInfo = path.join(appDir, "Contents", "Info");
      const output = execFileSync(
        "/usr/bin/defaults",
        ["read", plistInfo, "CFBundleShortVersionString"],
        {
          timeout: timeoutMs,
          encoding: "utf8",
          stdio: ["pipe", "pipe", "ignore"],
        },
      );
      const parsed = parseChromiumVersion(String(output ?? ""));
      if (parsed) return parsed.join(".");
    } catch {
      // ignore
    }
  }

  return null;
}

export function validateBrowserExecutableSecurity(
  exePath: string,
  minVersion = MIN_CHROMIUM_SECURITY_VERSION,
  versionResolver = getBrowserExecutableVersion,
): { valid: true; version: string } | { valid: false; error: string; version: string | null } {
  const version = versionResolver(exePath);
  if (!version) {
    return {
      valid: false,
      error: `Could not verify browser executable version at "${exePath}". Version proof is required for security baseline.`,
      version: null,
    };
  }
  if (!isChromiumVersionAtLeast(version, minVersion)) {
    return {
      valid: false,
      error:
        `Browser executable at "${exePath}" has version "${version}", which is below minimum security baseline ${minVersion}. ` +
        `Vulnerable to ${CHROMIUM_SECURITY_CVES.join(", ")}. Update to ${minVersion} or newer.`,
      version,
    };
  }
  return { valid: true, version };
}

/**
 * Asserts that a Chromium process command line conforms to OS sandboxing invariants.
 * Throws if the process command line contains forbidden flags (e.g. `--no-sandbox`)
 * or lacks required OS-level sandbox confinement mechanisms (e.g. macOS Seatbelt client for renderers).
 */
export function assertProcessSandboxed(commandLine: string, platform = process.platform): void {
  if (commandLine.includes("--no-sandbox")) {
    throw new Error(
      `Process violates security baseline: forbidden flag "--no-sandbox" detected in command line: ${commandLine}`,
    );
  }
  if (platform === "darwin" && commandLine.includes("--type=renderer")) {
    if (!commandLine.includes("--seatbelt-client=")) {
      throw new Error(
        `Process violates macOS security baseline: renderer process lacks "--seatbelt-client=" OS sandbox confinement: ${commandLine}`,
      );
    }
  }
}

/**
 * Queries macOS Seatbelt sandbox state for an active process PID using system libsandbox.1.dylib.
 * Returns true if the process is sandboxed (sandbox_check returns 1), false if unsandboxed (0).
 * Throws explicitly if the PID is invalid, dead/disappearing, or if the platform query fails.
 */
export function queryDarwinProcessSeatbeltState(pid: number): boolean {
  if (process.platform !== "darwin") {
    throw new Error(
      `queryDarwinProcessSeatbeltState is only supported on macOS (darwin), got ${process.platform}`,
    );
  }
  if (!Number.isInteger(pid) || pid <= 0) {
    throw new Error(`Invalid PID for Seatbelt state query: ${pid}`);
  }

  // Fails explicitly if the process does not exist or has disappeared
  process.kill(pid, 0);

  const pyScript =
    "import ctypes, sys\n" +
    "try:\n" +
    '    lib = ctypes.CDLL("/usr/lib/libsandbox.1.dylib")\n' +
    `    res = lib.sandbox_check(${pid}, None, 0)\n` +
    "    sys.stdout.write(str(res))\n" +
    "except Exception as e:\n" +
    "    sys.stderr.write(str(e))\n" +
    "    sys.exit(2)\n";

  const output = execFileSync("python3", ["-c", pyScript], {
    encoding: "utf8",
    timeout: 3000,
    stdio: ["pipe", "pipe", "pipe"],
  }).trim();

  if (output === "1") return true;
  if (output === "0") return false;
  throw new Error(`Unexpected output from Seatbelt sandbox_check for PID ${pid}: "${output}"`);
}
