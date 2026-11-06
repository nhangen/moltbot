import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import type { ResolvedBrowserConfig } from "./config.js";
import {
  MIN_CHROMIUM_SECURITY_VERSION,
  assertBrowserSecurityBaseline,
  getBrowserExecutableVersion,
  isChromiumVersionAtLeast,
} from "./chrome.security.js";

export type BrowserExecutable = {
  kind: "brave" | "canary" | "chromium" | "chrome" | "custom" | "edge" | "fork";
  path: string;
  version?: string;
};

const CHROMIUM_BUNDLE_IDS = new Set([
  "com.google.Chrome",
  "com.google.Chrome.beta",
  "com.google.Chrome.canary",
  "com.google.Chrome.dev",
  "com.brave.Browser",
  "com.brave.Browser.beta",
  "com.brave.Browser.nightly",
  "com.microsoft.Edge",
  "com.microsoft.EdgeBeta",
  "com.microsoft.EdgeDev",
  "com.microsoft.EdgeCanary",
  "org.chromium.Chromium",
  "com.vivaldi.Vivaldi",
  "com.operasoftware.Opera",
  "com.operasoftware.OperaGX",
  "com.yandex.desktop.yandex-browser",
  "company.thebrowser.Browser", // Arc
]);

const CHROMIUM_DESKTOP_IDS = new Set([
  "google-chrome.desktop",
  "google-chrome-beta.desktop",
  "google-chrome-unstable.desktop",
  "brave-browser.desktop",
  "microsoft-edge.desktop",
  "microsoft-edge-beta.desktop",
  "microsoft-edge-dev.desktop",
  "microsoft-edge-canary.desktop",
  "chromium.desktop",
  "chromium-browser.desktop",
  "vivaldi.desktop",
  "vivaldi-stable.desktop",
  "opera.desktop",
  "opera-gx.desktop",
  "yandex-browser.desktop",
  "org.chromium.Chromium.desktop",
]);

const CHROMIUM_EXE_NAMES = new Set([
  "chrome.exe",
  "msedge.exe",
  "brave.exe",
  "brave-browser.exe",
  "chromium.exe",
  "vivaldi.exe",
  "opera.exe",
  "launcher.exe",
  "yandex.exe",
  "yandexbrowser.exe",
  // mac/linux names
  "google chrome",
  "google chrome canary",
  "brave browser",
  "microsoft edge",
  "chromium",
  "chrome",
  "brave",
  "msedge",
  "brave-browser",
  "google-chrome",
  "google-chrome-stable",
  "google-chrome-beta",
  "google-chrome-unstable",
  "microsoft-edge",
  "microsoft-edge-beta",
  "microsoft-edge-dev",
  "microsoft-edge-canary",
  "chromium-browser",
  "vivaldi",
  "vivaldi-stable",
  "opera",
  "opera-stable",
  "opera-gx",
  "yandex-browser",
]);

function exists(filePath: string) {
  try {
    return fs.existsSync(filePath);
  } catch {
    return false;
  }
}

function execText(
  command: string,
  args: string[],
  timeoutMs = 1200,
  maxBuffer = 1024 * 1024,
): string | null {
  try {
    const output = execFileSync(command, args, {
      timeout: timeoutMs,
      encoding: "utf8",
      maxBuffer,
    });
    return String(output ?? "").trim() || null;
  } catch {
    return null;
  }
}

const BUNDLE_ID_KINDS: Readonly<Record<string, BrowserExecutable["kind"]>> = {
  "com.google.Chrome": "chrome",
  "com.google.Chrome.beta": "chrome",
  "com.google.Chrome.dev": "chrome",
  "com.google.Chrome.canary": "canary",
  "com.brave.Browser": "brave",
  "com.brave.Browser.beta": "brave",
  "com.brave.Browser.nightly": "brave",
  "com.microsoft.Edge": "edge",
  "com.microsoft.EdgeBeta": "edge",
  "com.microsoft.EdgeDev": "edge",
  "com.microsoft.EdgeCanary": "edge",
  "org.chromium.Chromium": "chromium",
};

// Anything not listed (Opera's launcher.exe, Vivaldi, Yandex, Arc, unknown
// names) is a fork: its vendor version number is never Chromium proof.
const EXECUTABLE_NAME_KINDS: Readonly<Record<string, BrowserExecutable["kind"]>> = {
  "chrome.exe": "chrome",
  "msedge.exe": "edge",
  "brave.exe": "brave",
  "brave-browser.exe": "brave",
  "chromium.exe": "chromium",
  "google chrome": "chrome",
  "google chrome canary": "canary",
  "brave browser": "brave",
  "microsoft edge": "edge",
  chromium: "chromium",
  chrome: "chrome",
  brave: "brave",
  msedge: "edge",
  "brave-browser": "brave",
  "google-chrome": "chrome",
  "google-chrome-stable": "chrome",
  "google-chrome-beta": "chrome",
  "google-chrome-unstable": "chrome",
  "microsoft-edge": "edge",
  "microsoft-edge-beta": "edge",
  "microsoft-edge-dev": "edge",
  "microsoft-edge-canary": "edge",
  "chromium-browser": "chromium",
};

function inferKindFromIdentifier(identifier: string): BrowserExecutable["kind"] {
  return BUNDLE_ID_KINDS[identifier] ?? "fork";
}

function inferKindFromExecutableName(name: string): BrowserExecutable["kind"] {
  return EXECUTABLE_NAME_KINDS[name.toLowerCase()] ?? "fork";
}

function detectDefaultChromiumExecutable(platform: NodeJS.Platform): BrowserExecutable | null {
  if (platform === "darwin") return detectDefaultChromiumExecutableMac();
  if (platform === "linux") return detectDefaultChromiumExecutableLinux();
  if (platform === "win32") return detectDefaultChromiumExecutableWindows();
  return null;
}

function detectDefaultChromiumExecutableMac(): BrowserExecutable | null {
  const bundleId = detectDefaultBrowserBundleIdMac();
  if (!bundleId || !CHROMIUM_BUNDLE_IDS.has(bundleId)) return null;

  const appPathRaw = execText("/usr/bin/osascript", [
    "-e",
    `POSIX path of (path to application id "${bundleId}")`,
  ]);
  if (!appPathRaw) return null;
  const appPath = appPathRaw.trim().replace(/\/$/, "");
  const exeName = execText("/usr/bin/defaults", [
    "read",
    path.join(appPath, "Contents", "Info"),
    "CFBundleExecutable",
  ]);
  if (!exeName) return null;
  const exePath = path.join(appPath, "Contents", "MacOS", exeName.trim());
  if (!exists(exePath)) return null;
  return { kind: inferKindFromIdentifier(bundleId), path: exePath };
}

function detectDefaultBrowserBundleIdMac(): string | null {
  const plistPath = path.join(
    os.homedir(),
    "Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist",
  );
  if (!exists(plistPath)) return null;
  const handlersRaw = execText(
    "/usr/bin/plutil",
    ["-extract", "LSHandlers", "json", "-o", "-", "--", plistPath],
    2000,
    5 * 1024 * 1024,
  );
  if (!handlersRaw) return null;
  let handlers: unknown;
  try {
    handlers = JSON.parse(handlersRaw);
  } catch {
    return null;
  }
  if (!Array.isArray(handlers)) return null;

  const resolveScheme = (scheme: string) => {
    let candidate: string | null = null;
    for (const entry of handlers) {
      if (!entry || typeof entry !== "object") continue;
      const record = entry as Record<string, unknown>;
      if (record.LSHandlerURLScheme !== scheme) continue;
      const role =
        (typeof record.LSHandlerRoleAll === "string" && record.LSHandlerRoleAll) ||
        (typeof record.LSHandlerRoleViewer === "string" && record.LSHandlerRoleViewer) ||
        null;
      if (role) candidate = role;
    }
    return candidate;
  };

  return resolveScheme("http") ?? resolveScheme("https");
}

function detectDefaultChromiumExecutableLinux(): BrowserExecutable | null {
  const desktopId =
    execText("xdg-settings", ["get", "default-web-browser"]) ||
    execText("xdg-mime", ["query", "default", "x-scheme-handler/http"]);
  if (!desktopId) return null;
  const trimmed = desktopId.trim();
  if (!CHROMIUM_DESKTOP_IDS.has(trimmed)) return null;
  const desktopPath = findDesktopFilePath(trimmed);
  if (!desktopPath) return null;
  const execLine = readDesktopExecLine(desktopPath);
  if (!execLine) return null;
  const command = extractExecutableFromExecLine(execLine);
  if (!command) return null;
  const resolved = resolveLinuxExecutablePath(command);
  if (!resolved) return null;
  const exeName = path.posix.basename(resolved).toLowerCase();
  if (!CHROMIUM_EXE_NAMES.has(exeName)) return null;
  return { kind: inferKindFromExecutableName(exeName), path: resolved };
}

function detectDefaultChromiumExecutableWindows(): BrowserExecutable | null {
  const progId = readWindowsProgId();
  const command =
    (progId ? readWindowsCommandForProgId(progId) : null) || readWindowsCommandForProgId("http");
  if (!command) return null;
  const expanded = expandWindowsEnvVars(command);
  const exePath = extractWindowsExecutablePath(expanded);
  if (!exePath) return null;
  if (!exists(exePath)) return null;
  const exeName = path.win32.basename(exePath).toLowerCase();
  if (!CHROMIUM_EXE_NAMES.has(exeName)) return null;
  return { kind: inferKindFromExecutableName(exeName), path: exePath };
}

function findDesktopFilePath(desktopId: string): string | null {
  const candidates = [
    path.join(os.homedir(), ".local", "share", "applications", desktopId),
    path.join("/usr/local/share/applications", desktopId),
    path.join("/usr/share/applications", desktopId),
    path.join("/var/lib/snapd/desktop/applications", desktopId),
  ];
  for (const candidate of candidates) {
    if (exists(candidate)) return candidate;
  }
  return null;
}

function readDesktopExecLine(desktopPath: string): string | null {
  try {
    const raw = fs.readFileSync(desktopPath, "utf8");
    const lines = raw.split(/\r?\n/);
    for (const line of lines) {
      if (line.startsWith("Exec=")) {
        return line.slice("Exec=".length).trim();
      }
    }
  } catch {
    // ignore
  }
  return null;
}

function extractExecutableFromExecLine(execLine: string): string | null {
  const tokens = splitExecLine(execLine);
  for (const token of tokens) {
    if (!token) continue;
    if (token === "env") continue;
    if (token.includes("=") && !token.startsWith("/") && !token.includes("\\")) continue;
    return token.replace(/^["']|["']$/g, "");
  }
  return null;
}

function splitExecLine(line: string): string[] {
  const tokens: string[] = [];
  let current = "";
  let inQuotes = false;
  let quoteChar = "";
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if ((ch === '"' || ch === "'") && (!inQuotes || ch === quoteChar)) {
      if (inQuotes) {
        inQuotes = false;
        quoteChar = "";
      } else {
        inQuotes = true;
        quoteChar = ch;
      }
      continue;
    }
    if (!inQuotes && /\s/.test(ch)) {
      if (current) {
        tokens.push(current);
        current = "";
      }
      continue;
    }
    current += ch;
  }
  if (current) tokens.push(current);
  return tokens;
}

function resolveLinuxExecutablePath(command: string): string | null {
  const cleaned = command.trim().replace(/%[a-zA-Z]/g, "");
  if (!cleaned) return null;
  if (cleaned.startsWith("/")) return cleaned;
  const resolved = execText("which", [cleaned], 800);
  return resolved ? resolved.trim() : null;
}

function readWindowsProgId(): string | null {
  const output = execText("reg", [
    "query",
    "HKCU\\Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\http\\UserChoice",
    "/v",
    "ProgId",
  ]);
  if (!output) return null;
  const match = output.match(/ProgId\s+REG_\w+\s+(.+)$/im);
  return match?.[1]?.trim() || null;
}

function readWindowsCommandForProgId(progId: string): string | null {
  const key =
    progId === "http"
      ? "HKCR\\http\\shell\\open\\command"
      : `HKCR\\${progId}\\shell\\open\\command`;
  const output = execText("reg", ["query", key, "/ve"]);
  if (!output) return null;
  const match = output.match(/REG_\w+\s+(.+)$/im);
  return match?.[1]?.trim() || null;
}

function expandWindowsEnvVars(value: string): string {
  return value.replace(/%([^%]+)%/g, (_match, name) => {
    const key = String(name ?? "").trim();
    return key ? (process.env[key] ?? `%${key}%`) : _match;
  });
}

function extractWindowsExecutablePath(command: string): string | null {
  const quoted = command.match(/"([^"]+\\.exe)"/i);
  if (quoted?.[1]) return quoted[1];
  const unquoted = command.match(/([^\\s]+\\.exe)/i);
  if (unquoted?.[1]) return unquoted[1];
  return null;
}

export type FindExecutableOptions = {
  minVersion?: string;
  versionResolver?: (path: string) => string | null;
  enforceSecurity?: boolean;
  allowInsecureTestOnly?: boolean;
};

type StatIdentity = { dev: number; ino: number; size: number; mtimeMs: number; ctimeMs: number };

function statIdentity(target: string): StatIdentity | null {
  try {
    const st = fs.statSync(target);
    return { dev: st.dev, ino: st.ino, size: st.size, mtimeMs: st.mtimeMs, ctimeMs: st.ctimeMs };
  } catch {
    return null;
  }
}

function sameIdentity(a: StatIdentity | null, b: StatIdentity | null): boolean {
  if (!a || !b) return a === b;
  return (
    a.dev === b.dev &&
    a.ino === b.ino &&
    a.size === b.size &&
    a.mtimeMs === b.mtimeMs &&
    a.ctimeMs === b.ctimeMs
  );
}

function bundleInfoPlistPath(exePath: string): string | null {
  const idx = exePath.indexOf(".app/");
  if (idx < 0) return null;
  return path.join(exePath.slice(0, idx + 4), "Contents", "Info.plist");
}

const BUNDLE_VERSION_KINDS: ReadonlySet<BrowserExecutable["kind"]> = new Set([
  "chrome",
  "chromium",
  "canary",
]);

export function allowsBundleVersionProof(kind: BrowserExecutable["kind"]): boolean {
  return BUNDLE_VERSION_KINDS.has(kind);
}

const executableVersionCache = new Map<
  string,
  { exe: StatIdentity; plist: StatIdentity | null; version: string | null }
>();

export function clearExecutableVersionCache(): void {
  executableVersionCache.clear();
}

/**
 * Caches version proof per resolved executable. Any change to the binary's or (macOS) the bundle
 * Info.plist's dev/ino/size/mtime/ctime invalidates the entry; ctime cannot be restored by utimes.
 */
export function getCachedBrowserExecutableVersion(
  exePath: string,
  resolver: (path: string) => string | null = getBrowserExecutableVersion,
  cacheScope = "default",
): string | null {
  let real: string;
  try {
    real = fs.realpathSync(exePath);
  } catch {
    return resolver(exePath);
  }
  // A link whose target has another name is a multiplexing launcher such as snap: its identity
  // says nothing about which app or revision runs, so it is never cached.
  if (path.basename(real) !== path.basename(exePath)) return resolver(exePath);
  const plistPath = process.platform === "darwin" ? bundleInfoPlistPath(real) : null;
  const exe = statIdentity(real);
  if (!exe) return resolver(exePath);
  const plist = plistPath ? statIdentity(plistPath) : null;
  const key = `${cacheScope}\u0000${real}`;
  const cached = executableVersionCache.get(key);
  if (cached && sameIdentity(cached.exe, exe) && sameIdentity(cached.plist, plist)) {
    return cached.version;
  }
  const version = resolver(exePath);
  executableVersionCache.set(key, { exe, plist, version });
  return version;
}

function resolveCandidateVersion(
  candidate: BrowserExecutable,
  options?: FindExecutableOptions,
): string | null {
  if (options?.versionResolver) return options.versionResolver(candidate.path);
  const allowBundleVersion = allowsBundleVersionProof(candidate.kind);
  return getCachedBrowserExecutableVersion(
    candidate.path,
    (p) => getBrowserExecutableVersion(p, undefined, { allowBundleVersion }),
    allowBundleVersion ? "bundle" : "cli",
  );
}

function findFirstExecutable(
  candidates: Array<BrowserExecutable>,
  options?: FindExecutableOptions,
): BrowserExecutable | null {
  const minVersion = options?.minVersion ?? MIN_CHROMIUM_SECURITY_VERSION;
  const enforce = options?.enforceSecurity ?? true;

  for (const candidate of candidates) {
    if (!exists(candidate.path)) continue;
    const version = resolveCandidateVersion(candidate, options);
    if (version) {
      if (enforce && !isChromiumVersionAtLeast(version, minVersion)) {
        continue;
      }
      return { ...candidate, version };
    }
    if (!enforce || options?.allowInsecureTestOnly) {
      return candidate;
    }
  }

  return null;
}

export function findChromeExecutableMac(options?: FindExecutableOptions): BrowserExecutable | null {
  const candidates: Array<BrowserExecutable> = [
    {
      kind: "chrome",
      path: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    },
    {
      kind: "chrome",
      path: path.join(os.homedir(), "Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
    },
    {
      kind: "brave",
      path: "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
    },
    {
      kind: "brave",
      path: path.join(os.homedir(), "Applications/Brave Browser.app/Contents/MacOS/Brave Browser"),
    },
    {
      kind: "edge",
      path: "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    },
    {
      kind: "edge",
      path: path.join(
        os.homedir(),
        "Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
      ),
    },
    {
      kind: "chromium",
      path: "/Applications/Chromium.app/Contents/MacOS/Chromium",
    },
    {
      kind: "chromium",
      path: path.join(os.homedir(), "Applications/Chromium.app/Contents/MacOS/Chromium"),
    },
    {
      kind: "canary",
      path: "/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
    },
    {
      kind: "canary",
      path: path.join(
        os.homedir(),
        "Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
      ),
    },
  ];

  const opts: FindExecutableOptions = {
    ...options,
    enforceSecurity:
      options?.enforceSecurity ?? (options?.versionResolver ? true : process.platform === "darwin"),
  };
  return findFirstExecutable(candidates, opts);
}

export function findChromeExecutableLinux(
  options?: FindExecutableOptions,
): BrowserExecutable | null {
  const candidates: Array<BrowserExecutable> = [
    { kind: "chrome", path: "/usr/bin/google-chrome" },
    { kind: "chrome", path: "/usr/bin/google-chrome-stable" },
    { kind: "chrome", path: "/usr/bin/chrome" },
    { kind: "brave", path: "/usr/bin/brave-browser" },
    { kind: "brave", path: "/usr/bin/brave-browser-stable" },
    { kind: "brave", path: "/usr/bin/brave" },
    { kind: "brave", path: "/snap/bin/brave" },
    { kind: "edge", path: "/usr/bin/microsoft-edge" },
    { kind: "edge", path: "/usr/bin/microsoft-edge-stable" },
    { kind: "chromium", path: "/usr/bin/chromium" },
    { kind: "chromium", path: "/usr/bin/chromium-browser" },
    { kind: "chromium", path: "/snap/bin/chromium" },
  ];

  const opts: FindExecutableOptions = {
    ...options,
    enforceSecurity:
      options?.enforceSecurity ?? (options?.versionResolver ? true : process.platform === "linux"),
  };
  return findFirstExecutable(candidates, opts);
}

export function findChromeExecutableWindows(
  options?: FindExecutableOptions,
): BrowserExecutable | null {
  const localAppData = process.env.LOCALAPPDATA ?? "";
  const programFiles = process.env.ProgramFiles ?? "C:\\Program Files";
  // Must use bracket notation: variable name contains parentheses
  const programFilesX86 = process.env["ProgramFiles(x86)"] ?? "C:\\Program Files (x86)";

  const joinWin = path.win32.join;
  const candidates: Array<BrowserExecutable> = [];

  if (localAppData) {
    // Chrome (user install)
    candidates.push({
      kind: "chrome",
      path: joinWin(localAppData, "Google", "Chrome", "Application", "chrome.exe"),
    });
    // Brave (user install)
    candidates.push({
      kind: "brave",
      path: joinWin(localAppData, "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
    });
    // Edge (user install)
    candidates.push({
      kind: "edge",
      path: joinWin(localAppData, "Microsoft", "Edge", "Application", "msedge.exe"),
    });
    // Chromium (user install)
    candidates.push({
      kind: "chromium",
      path: joinWin(localAppData, "Chromium", "Application", "chrome.exe"),
    });
    // Chrome Canary (user install)
    candidates.push({
      kind: "canary",
      path: joinWin(localAppData, "Google", "Chrome SxS", "Application", "chrome.exe"),
    });
  }

  // Chrome (system install, 64-bit)
  candidates.push({
    kind: "chrome",
    path: joinWin(programFiles, "Google", "Chrome", "Application", "chrome.exe"),
  });
  // Chrome (system install, 32-bit on 64-bit Windows)
  candidates.push({
    kind: "chrome",
    path: joinWin(programFilesX86, "Google", "Chrome", "Application", "chrome.exe"),
  });
  // Brave (system install, 64-bit)
  candidates.push({
    kind: "brave",
    path: joinWin(programFiles, "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
  });
  // Brave (system install, 32-bit on 64-bit Windows)
  candidates.push({
    kind: "brave",
    path: joinWin(programFilesX86, "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
  });
  // Edge (system install, 64-bit)
  candidates.push({
    kind: "edge",
    path: joinWin(programFiles, "Microsoft", "Edge", "Application", "msedge.exe"),
  });
  // Edge (system install, 32-bit on 64-bit Windows)
  candidates.push({
    kind: "edge",
    path: joinWin(programFilesX86, "Microsoft", "Edge", "Application", "msedge.exe"),
  });

  const opts: FindExecutableOptions = {
    ...options,
    enforceSecurity:
      options?.enforceSecurity ?? (options?.versionResolver ? true : process.platform === "win32"),
  };
  return findFirstExecutable(candidates, opts);
}

export function resolveBrowserExecutableForPlatform(
  resolved: ResolvedBrowserConfig,
  platform: NodeJS.Platform = process.platform,
  options?: FindExecutableOptions,
): BrowserExecutable | null {
  const minVersion = options?.minVersion ?? MIN_CHROMIUM_SECURITY_VERSION;
  const isHost = platform === process.platform;

  if (resolved.executablePath) {
    if (!exists(resolved.executablePath)) {
      throw new Error(`browser.executablePath not found: ${resolved.executablePath}`);
    }
    const version = resolveCandidateVersion(
      { kind: "custom", path: resolved.executablePath },
      options,
    );
    if (version) {
      assertBrowserSecurityBaseline(
        version,
        `executable at ${resolved.executablePath}`,
        minVersion,
      );
      return { kind: "custom", path: resolved.executablePath, version };
    }
    if (isHost && !options?.allowInsecureTestOnly) {
      throw new Error(
        `Unable to verify version of browser executable at "${resolved.executablePath}". Version proof is required for security baseline ${minVersion}.`,
      );
    }
    if (options?.allowInsecureTestOnly) {
      return { kind: "custom", path: resolved.executablePath };
    }
    throw new Error(
      `Unable to verify version of browser executable at "${resolved.executablePath}". Version proof is required for security baseline ${minVersion}.`,
    );
  }

  const detected = detectDefaultChromiumExecutable(platform);
  if (detected) {
    const version = resolveCandidateVersion(detected, options);
    if (version) {
      if (isChromiumVersionAtLeast(version, minVersion)) {
        return { ...detected, version };
      }
      // Detected default browser is below baseline, fail closed for default
    } else if (options?.allowInsecureTestOnly) {
      return detected;
    }
  }

  const opts: FindExecutableOptions = {
    ...options,
    enforceSecurity: options?.enforceSecurity ?? (isHost ? true : false),
  };

  if (platform === "darwin") return findChromeExecutableMac(opts);
  if (platform === "linux") return findChromeExecutableLinux(opts);
  if (platform === "win32") return findChromeExecutableWindows(opts);
  return null;
}
