import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import { appendCdpPath, getHeadersWithAuth } from "./cdp.helpers.js";
import {
  CHROMIUM_SECURITY_CNA_RECORDS,
  MIN_CHROMIUM_SECURITY_VERSION,
  compareChromiumVersions,
  isChromiumVersionAtLeast,
  parseChromiumProductVersion,
  parseChromiumVersion,
} from "./chromium-version.js";

export {
  CHROMIUM_SECURITY_CNA_RECORDS,
  MIN_CHROMIUM_SECURITY_VERSION,
  compareChromiumVersions,
  isChromiumVersionAtLeast,
  parseChromiumProductVersion,
  parseChromiumVersion,
};

export const PINNED_CFT_VERSION = "156.0.8078.80";
export const PINNED_CFT_REVISION = "1706539";

const CNA_RECORDS_LABEL = `Chrome CNA records ${CHROMIUM_SECURITY_CNA_RECORDS.join("/")}`;

/** A browser or endpoint was positively refused by the security baseline. Never retry. */
export class BrowserSecurityRefusalError extends Error {
  override name = "BrowserSecurityRefusalError";
}

/** Version proof could not be obtained. Fails closed; transport-level retries are allowed. */
export class BrowserSecurityProofUnavailableError extends Error {
  override name = "BrowserSecurityProofUnavailableError";
}

export function isBrowserSecurityError(err: unknown): boolean {
  return (
    err instanceof BrowserSecurityRefusalError ||
    err instanceof BrowserSecurityProofUnavailableError
  );
}

/** Strips userinfo, query and fragment so tokens never reach error text or logs. */
export function redactCdpUrl(raw: string): string {
  try {
    const url = new URL(raw);
    const hadSecret = Boolean(url.username || url.password || url.search || url.hash);
    url.username = "";
    url.password = "";
    url.search = "";
    url.hash = "";
    const base = url.toString().replace(/\/$/, "");
    return hadSecret ? `${base} [redacted]` : base;
  } catch {
    return "[unparseable CDP URL]";
  }
}

export const CHROMIUM_SECURITY_ADVISORY =
  "https://chromereleases.googleblog.com/2026/10/stable-channel-update-for-desktop_0562499947.html";

export function assertBrowserSecurityBaseline(
  version: string,
  context?: string,
  minimum = MIN_CHROMIUM_SECURITY_VERSION,
): void {
  if (!isChromiumVersionAtLeast(version, minimum)) {
    const ctxMsg = context ? ` for ${context}` : "";
    throw new BrowserSecurityRefusalError(
      `Refusing browser (version ${version})${ctxMsg}: version is below minimum security baseline ${minimum}. ` +
        `Releases before ${minimum} are covered by ${CNA_RECORDS_LABEL}. ` +
        `See advisory: ${CHROMIUM_SECURITY_ADVISORY}. Update browser to ${minimum} or newer.`,
    );
  }
}

export function assertBrowserSandboxEnabled(noSandbox: boolean): void {
  if (!noSandbox) return;
  throw new BrowserSecurityRefusalError(
    "Refusing browser: browser.noSandbox turns off the Chromium sandbox, which the security baseline requires. " +
      "Remove browser.noSandbox from your config, and start any browser you attach to with its sandbox on.",
  );
}

export type BrowserExecutableVersionOptions = {
  /**
   * Trust whole-quad bundle metadata (macOS Info.plist, Windows FileVersion). Only safe for
   * Google Chrome/Chromium builds: derivatives (Brave, Edge) publish their own release numbers there.
   */
  allowBundleVersion?: boolean;
};

function resolveWindowsSystem32Path(env: NodeJS.ProcessEnv, ...segments: string[]): string {
  const systemRoot = env.SystemRoot?.trim() || env.windir?.trim() || "C:\\Windows";
  return path.win32.join(systemRoot, "System32", ...segments);
}

export function resolveWindowsPowerShellPath(env: NodeJS.ProcessEnv = process.env): string {
  return resolveWindowsSystem32Path(env, "WindowsPowerShell", "v1.0", "powershell.exe");
}

export function resolveWindowsRegPath(env: NodeJS.ProcessEnv = process.env): string {
  return resolveWindowsSystem32Path(env, "reg.exe");
}

export function getBrowserExecutableVersion(
  exePath: string,
  timeoutMs = 1500,
  options: BrowserExecutableVersionOptions = {},
): string | null {
  const allowBundleVersion = options.allowBundleVersion ?? false;
  try {
    if (!fs.existsSync(exePath)) return null;
  } catch {
    return null;
  }

  // 1. `--version` (skipped on Windows, where chrome.exe launches or forwards to a GUI instance).
  if (process.platform !== "win32")
    try {
      const output = execFileSync(exePath, ["--version"], {
        timeout: timeoutMs,
        encoding: "utf8",
        maxBuffer: 256 * 1024,
        stdio: ["pipe", "pipe", "ignore"],
      });
      const parsed = parseChromiumProductVersion(String(output ?? ""));
      if (parsed) return parsed.join(".");
    } catch {
      // ignore
    }

  if (!allowBundleVersion) return null;

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

  // 3. On Windows (win32), read file version metadata
  if (process.platform === "win32") {
    try {
      const escaped = exePath.replace(/'/g, "''");
      const psCmd = `(Get-Item -LiteralPath '${escaped}').VersionInfo.FileVersion`;
      const output = execFileSync(
        resolveWindowsPowerShellPath(),
        ["-NoProfile", "-NonInteractive", "-Command", psCmd],
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
        `Releases before ${minVersion} are covered by ${CNA_RECORDS_LABEL}. Update to ${minVersion} or newer.`,
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

  const pythonBin = "/usr/bin/python3";
  if (!fs.existsSync(pythonBin)) {
    throw new Error(`Trusted system python3 not found at ${pythonBin} for Seatbelt query`);
  }

  const pyScript =
    "import ctypes, sys\n" +
    "try:\n" +
    '    lib = ctypes.CDLL("/usr/lib/libsandbox.1.dylib")\n' +
    `    res = lib.sandbox_check(${pid}, None, 0)\n` +
    "    sys.stdout.write(str(res))\n" +
    "except Exception as e:\n" +
    "    sys.stderr.write(str(e))\n" +
    "    sys.exit(2)\n";

  const output = execFileSync(pythonBin, ["-c", pyScript], {
    encoding: "utf8",
    timeout: 3000,
    stdio: ["pipe", "pipe", "pipe"],
  }).trim();

  if (output === "1") return true;
  if (output === "0") return false;
  throw new Error(`Unexpected output from Seatbelt sandbox_check for PID ${pid}: "${output}"`);
}

const cdpSecurityCache = new Map<string, { version: string; checkedAt: number }>();

export function clearCdpSecurityCache(): void {
  cdpSecurityCache.clear();
}

/**
 * Checks a `/json/version` `Browser` value and returns the verified version.
 * `endpointLabel` must already be redacted.
 */
export function assertCdpBrowserProof(
  browser: unknown,
  label: string,
  endpointLabel: string,
): string {
  if (typeof browser !== "string" || !browser) {
    throw new BrowserSecurityProofUnavailableError(
      `Refusing CDP connection for ${label}: failed to obtain /json/version proof from ${endpointLabel}. Version proof is required for security baseline.`,
    );
  }

  if (/extension-relay/i.test(browser)) {
    throw new BrowserSecurityRefusalError(
      `Refusing CDP connection for ${label}: the extension relay does not yet support verifiable underlying browser version proof, so it cannot satisfy security baseline ${MIN_CHROMIUM_SECURITY_VERSION}.`,
    );
  }

  const parsed = parseChromiumVersion(browser);
  if (!parsed) {
    throw new BrowserSecurityRefusalError(
      `Refusing CDP connection for ${label}: unparseable Browser string from ${endpointLabel}. Version proof is required for security baseline.`,
    );
  }

  const versionStr = parsed.join(".");
  assertBrowserSecurityBaseline(versionStr, label);
  return versionStr;
}

function buildCdpVersionRequest(cdpUrl: string): { url: string; headers: Record<string, string> } {
  const headers = getHeadersWithAuth(cdpUrl);
  const url = new URL(appendCdpPath(cdpUrl, "/json/version"));
  // fetch() rejects URLs with embedded credentials; they travel as the Authorization header instead.
  url.username = "";
  url.password = "";
  return { url: url.toString(), headers };
}

/**
 * Validates the security baseline of a CDP endpoint before connection.
 * Fails closed if the endpoint cannot be contacted, returns missing/unparseable version,
 * is an extension relay (which cannot prove its underlying browser version),
 * or if the reported version is below MIN_CHROMIUM_SECURITY_VERSION.
 */
export async function assertCdpEndpointSecurity(
  cdpUrl: string,
  context?: string,
  timeoutMs = 2500,
): Promise<{ version: string }> {
  const cached = cdpSecurityCache.get(cdpUrl);
  if (cached && Date.now() - cached.checkedAt < 10_000) {
    return { version: cached.version };
  }

  const label = context ?? `CDP endpoint at ${redactCdpUrl(cdpUrl)}`;
  const safeEndpoint = redactCdpUrl(
    (() => {
      try {
        return appendCdpPath(cdpUrl, "/json/version");
      } catch {
        return cdpUrl;
      }
    })(),
  );

  let browser: string | undefined;
  try {
    const req = buildCdpVersionRequest(cdpUrl);
    const res = await fetch(req.url, {
      headers: req.headers,
      redirect: "error",
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (res.ok) {
      const body = (await res.json()) as { Browser?: unknown };
      if (typeof body?.Browser === "string") browser = body.Browser;
    }
  } catch {
    browser = undefined;
  }

  const versionStr = assertCdpBrowserProof(browser, label, safeEndpoint);

  cdpSecurityCache.set(cdpUrl, { version: versionStr, checkedAt: Date.now() });
  return { version: versionStr };
}
