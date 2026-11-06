import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const execFileSyncMock = vi.hoisted(() => vi.fn());

vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return { ...actual, execFileSync: execFileSyncMock };
});

import {
  clearExecutableVersionCache,
  getCachedBrowserExecutableVersion,
  resolveBrowserExecutableForPlatform,
} from "./chrome.executables.js";
import { getBrowserExecutableVersion, resolveWindowsPowerShellPath } from "./chrome.security.js";
import type { ResolvedBrowserConfig } from "./config.js";

const realPlatform = process.platform;
function setPlatform(platform: NodeJS.Platform) {
  Object.defineProperty(process, "platform", { value: platform, configurable: true });
}

function makeConfig(executablePath?: string): ResolvedBrowserConfig {
  return {
    enabled: true,
    evaluateEnabled: true,
    controlPort: 0,
    cdpProtocol: "http",
    cdpHost: "127.0.0.1",
    cdpIsLoopback: true,
    remoteCdpTimeoutMs: 1000,
    remoteCdpHandshakeTimeoutMs: 2000,
    color: "#000",
    executablePath,
    headless: true,
    noSandbox: false,
    attachOnly: false,
    defaultProfile: "clawd",
    profiles: {},
  } as ResolvedBrowserConfig;
}

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "moltbot-version-proof-"));
  execFileSyncMock.mockReset();
  clearExecutableVersionCache();
});

afterEach(() => {
  setPlatform(realPlatform);
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

function makeFakeApp(name: string): string {
  const exe = path.join(tmpDir, `${name}.app`, "Contents", "MacOS", name);
  fs.mkdirSync(path.dirname(exe), { recursive: true });
  fs.writeFileSync(exe, "#!/bin/sh\n");
  fs.writeFileSync(path.join(tmpDir, `${name}.app`, "Contents", "Info.plist"), "<plist/>");
  return exe;
}

describe("bundle-version proof is limited to Google Chrome and Chromium builds", () => {
  it("never trusts Info.plist for a custom executable whose --version is unparseable", () => {
    setPlatform("darwin");
    const exe = makeFakeApp("Brave Browser");
    execFileSyncMock.mockImplementation((cmd: string) => {
      if (cmd === exe) return "Brave Browser 1.80.1";
      if (cmd === "/usr/bin/defaults") return "156.1.80.1";
      throw new Error(`unexpected ${cmd}`);
    });

    expect(() => resolveBrowserExecutableForPlatform(makeConfig(exe), "darwin")).toThrowError(
      /Unable to verify version/,
    );
    expect(execFileSyncMock.mock.calls.some(([cmd]) => cmd === "/usr/bin/defaults")).toBe(false);
  });

  it("uses Info.plist only when the caller allows bundle proof", () => {
    setPlatform("darwin");
    const exe = makeFakeApp("Google Chrome");
    execFileSyncMock.mockImplementation((cmd: string) => {
      if (cmd === exe) throw new Error("launch blocked");
      if (cmd === "/usr/bin/defaults") return "156.0.8078.80\n";
      throw new Error(`unexpected ${cmd}`);
    });

    expect(getBrowserExecutableVersion(exe)).toBeNull();
    expect(getBrowserExecutableVersion(exe, 1500, { allowBundleVersion: true })).toBe(
      "156.0.8078.80",
    );
  });
});

describe("Windows version probe", () => {
  it("skips --version and runs PowerShell from an absolute System32 path", () => {
    setPlatform("win32");
    const exe = path.join(tmpDir, "chrome.exe");
    fs.writeFileSync(exe, "MZ");
    vi.stubEnv("SystemRoot", "D:\\WinRoot");
    execFileSyncMock.mockImplementation(() => "156.0.8078.80\r\n");

    expect(getBrowserExecutableVersion(exe, 1500, { allowBundleVersion: true })).toBe(
      "156.0.8078.80",
    );
    expect(execFileSyncMock).toHaveBeenCalledTimes(1);
    const [cmd, args] = execFileSyncMock.mock.calls[0];
    expect(cmd).toBe("D:\\WinRoot\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
    expect(args).not.toContain("--version");
    vi.unstubAllEnvs();
  });

  it("falls back to the default Windows directory when SystemRoot is unset", () => {
    expect(resolveWindowsPowerShellPath({})).toBe(
      "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    );
  });

  it("refuses an Edge/Brave executable on win32 because FileVersion is vendor-numbered", () => {
    setPlatform("win32");
    const exe = path.join(tmpDir, "msedge.exe");
    fs.writeFileSync(exe, "MZ");
    execFileSyncMock.mockImplementation(() => "156.0.3065.92\r\n");

    expect(getBrowserExecutableVersion(exe)).toBeNull();
    expect(execFileSyncMock).not.toHaveBeenCalled();
  });
});

describe("Windows explicit executablePath", () => {
  it("is refused because a custom path gets no FileVersion proof on win32", () => {
    setPlatform("win32");
    const exe = path.join(tmpDir, "chrome.exe");
    fs.writeFileSync(exe, "");
    execFileSyncMock.mockImplementation((cmd: string) => {
      if (cmd.toLowerCase().endsWith("powershell.exe")) return "156.0.8078.80";
      throw new Error(`unexpected ${cmd}`);
    });

    expect(() => resolveBrowserExecutableForPlatform(makeConfig(exe), "win32")).toThrowError(
      /Unable to verify version/,
    );
    expect(execFileSyncMock).not.toHaveBeenCalled();
  });
});

describe("Windows default-browser detection", () => {
  const LOCAL = "C:\\Users\\t\\AppData\\Local";
  const CHROME_USER = `${LOCAL}\\Google\\Chrome\\Application\\chrome.exe`;
  const CANARY_USER = `${LOCAL}\\Google\\Chrome SxS\\Application\\chrome.exe`;
  const CHROME_SYSTEM = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
  const FORGED_VERSION = "156.0.8078.80\r\n";

  function stubDefaultBrowser(command: string, installed: string[]) {
    setPlatform("win32");
    vi.stubEnv("LOCALAPPDATA", LOCAL);
    vi.stubEnv("ProgramFiles", "C:\\Program Files");
    vi.stubEnv("ProgramFiles(x86)", "C:\\Program Files (x86)");
    vi.stubEnv("SystemRoot", "C:\\Windows");
    vi.spyOn(fs, "existsSync").mockImplementation((p) => installed.includes(String(p)));
    execFileSyncMock.mockImplementation((cmd: string, args: string[]) => {
      if (cmd.toLowerCase().endsWith("powershell.exe")) return FORGED_VERSION;
      if (cmd !== "C:\\Windows\\System32\\reg.exe") throw new Error(`unexpected ${cmd}`);
      if (args[1].endsWith("\\UserChoice")) {
        return `\r\n${args[1]}\r\n    ProgId    REG_SZ    ChromeHTML\r\n\r\n`;
      }
      if (args[1] === "HKCR\\ChromeHTML\\shell\\open\\command") {
        return `\r\n${args[1]}\r\n    (Default)    REG_SZ    ${command}\r\n\r\n`;
      }
      throw new Error(`unexpected key ${args[1]}`);
    });
  }

  function powershellProbes() {
    return execFileSyncMock.mock.calls.filter(([cmd]) =>
      String(cmd).toLowerCase().endsWith("powershell.exe"),
    );
  }

  it.each([
    ["quoted", `"${CANARY_USER}" --single-argument %1`],
    ["unquoted with spaces", `${CANARY_USER} --single-argument %1`],
    ["bare", CANARY_USER],
    ["env-var", `"%LOCALAPPDATA%\\Google\\Chrome SxS\\Application\\chrome.exe" -- "%1"`],
  ])("selects the default browser from a %s registry command", (_label, command) => {
    stubDefaultBrowser(command, [CHROME_USER, CANARY_USER]);

    expect(resolveBrowserExecutableForPlatform(makeConfig(), "win32")).toEqual({
      kind: "canary",
      path: CANARY_USER,
      version: "156.0.8078.80",
    });
  });

  it("matches install locations case-insensitively", () => {
    const spelled = CANARY_USER.toUpperCase();
    stubDefaultBrowser(`"${spelled}" -- "%1"`, [CHROME_USER, spelled]);

    expect(resolveBrowserExecutableForPlatform(makeConfig(), "win32")?.kind).toBe("canary");
  });

  it.each([
    ["an unknown location", `"C:\\Temp\\chrome.exe" -- "%1"`, "C:\\Temp\\chrome.exe"],
    ["an unquoted unknown location", "C:\\Temp\\chrome.exe -- %1", "C:\\Temp\\chrome.exe"],
    [
      "a traversal out of the install location",
      `"C:\\Program Files\\Google\\Chrome\\Application\\..\\..\\..\\..\\Temp\\chrome.exe"`,
      "C:\\Program Files\\Google\\Chrome\\Application\\..\\..\\..\\..\\Temp\\chrome.exe",
    ],
    ["a relative path", `"chrome.exe" -- "%1"`, "chrome.exe"],
    ["a UNC path", `"\\\\host\\share\\chrome.exe"`, "\\\\host\\share\\chrome.exe"],
    ["a wrapper argument", `C:\\Temp\\run.cmd "${CHROME_SYSTEM}"`, "C:\\Temp\\run.cmd"],
    ["an interpreter argument", `C:\\Temp\\cmd.exe /c "${CHROME_SYSTEM}"`, "C:\\Temp\\cmd.exe"],
    ["Opera's launcher", `"${LOCAL}\\Programs\\Opera\\launcher.exe"`, "launcher.exe"],
  ])("gives no FileVersion trust to %s", (_label, command, onDisk) => {
    stubDefaultBrowser(command, [onDisk, `${LOCAL}\\Programs\\Opera\\launcher.exe`]);

    expect(resolveBrowserExecutableForPlatform(makeConfig(), "win32")).toBeNull();
    expect(powershellProbes()).toEqual([]);
  });

  it("gives no FileVersion trust to Edge at its install location", () => {
    const edge = "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe";
    stubDefaultBrowser(`"${edge}" --single-argument %1`, [edge]);

    expect(resolveBrowserExecutableForPlatform(makeConfig(), "win32")).toBeNull();
    expect(powershellProbes()).toEqual([]);
  });

  it("falls back to an installed Chrome when the default browser is untrusted", () => {
    stubDefaultBrowser(`"C:\\Temp\\chrome.exe"`, ["C:\\Temp\\chrome.exe", CHROME_SYSTEM]);

    expect(resolveBrowserExecutableForPlatform(makeConfig(), "win32")).toEqual({
      kind: "chrome",
      path: CHROME_SYSTEM,
      version: "156.0.8078.80",
    });
    expect(powershellProbes()).toHaveLength(1);
  });
});

describe("--version output must name a Chromium product", () => {
  it.each([
    ["a bare vendor number", "156.0.8078.80", false],
    ["a Chromium banner", "Chromium 156.0.8078.80", true],
    ["a Google Chrome banner", "Google Chrome 156.0.8078.80", true],
  ])("treats %s accordingly for a custom executable", (_label, output, accepted) => {
    setPlatform("darwin");
    const exe = path.join(tmpDir, "browser-bin");
    fs.writeFileSync(exe, "#!/bin/sh\n");
    execFileSyncMock.mockImplementation((cmd: string) => {
      if (cmd === exe) return `${output}\n`;
      throw new Error(`unexpected ${cmd}`);
    });

    const resolve = () => resolveBrowserExecutableForPlatform(makeConfig(exe), "darwin");
    if (accepted) {
      expect(resolve()?.version).toBe("156.0.8078.80");
    } else {
      expect(resolve).toThrowError(/Unable to verify version/);
    }
  });
});

describe("executable version cache identity", () => {
  it("invalidates on a same-size content swap with restored mtime (ctime changes)", () => {
    setPlatform("linux");
    const exe = path.join(tmpDir, "chromium");
    fs.writeFileSync(exe, "binary-v156-alpha");
    const fixed = new Date(1700000000000);
    fs.utimesSync(exe, fixed, fixed);
    const resolver = vi.fn((p: string) =>
      fs.readFileSync(p, "utf8").includes("156") ? "156.0.8078.80" : "133.0.6943.53",
    );

    expect(getCachedBrowserExecutableVersion(exe, resolver)).toBe("156.0.8078.80");
    expect(getCachedBrowserExecutableVersion(exe, resolver)).toBe("156.0.8078.80");
    expect(resolver).toHaveBeenCalledTimes(1);

    fs.writeFileSync(exe, "binary-v133-omega");
    fs.utimesSync(exe, fixed, fixed);
    expect(getCachedBrowserExecutableVersion(exe, resolver)).toBe("133.0.6943.53");
    expect(resolver).toHaveBeenCalledTimes(2);
  });

  it("keys on the resolved target so a repointed symlink is re-probed", () => {
    setPlatform("linux");
    const a = path.join(tmpDir, "chrome-a");
    const b = path.join(tmpDir, "chrome-b");
    fs.writeFileSync(a, "a");
    fs.writeFileSync(b, "b");
    const link = path.join(tmpDir, "chrome");
    fs.symlinkSync(a, link);
    const resolver = vi.fn((p: string) =>
      fs.realpathSync(p) === fs.realpathSync(a) ? "156.0.8078.80" : "133.0.6943.53",
    );

    expect(getCachedBrowserExecutableVersion(link, resolver)).toBe("156.0.8078.80");
    fs.unlinkSync(link);
    fs.symlinkSync(b, link);
    expect(getCachedBrowserExecutableVersion(link, resolver)).toBe("133.0.6943.53");
  });

  it("never reuses proof through a multiplexing launcher such as snap", () => {
    setPlatform("linux");
    const launcher = path.join(tmpDir, "snap");
    fs.writeFileSync(launcher, "snap-launcher");
    const chromium = path.join(tmpDir, "chromium");
    const brave = path.join(tmpDir, "brave");
    fs.symlinkSync(launcher, chromium);
    fs.symlinkSync(launcher, brave);
    let chromiumRevision = "156.0.8078.80";
    const resolver = vi.fn((p: string) =>
      path.basename(p) === "chromium" ? chromiumRevision : null,
    );

    expect(getCachedBrowserExecutableVersion(chromium, resolver)).toBe("156.0.8078.80");
    expect(getCachedBrowserExecutableVersion(brave, resolver)).toBeNull();
    chromiumRevision = "133.0.6943.53";
    expect(getCachedBrowserExecutableVersion(chromium, resolver)).toBe("133.0.6943.53");
  });

  it("invalidates a macOS bundle entry when Info.plist changes", () => {
    setPlatform("darwin");
    const exe = makeFakeApp("Google Chrome");
    const plist = path.join(tmpDir, "Google Chrome.app", "Contents", "Info.plist");
    const resolver = vi.fn((_p: string) =>
      fs.readFileSync(plist, "utf8").includes("156") ? "156.0.8078.80" : "133.0.6943.53",
    );
    fs.writeFileSync(plist, "<plist>156</plist>");

    expect(getCachedBrowserExecutableVersion(exe, resolver)).toBe("156.0.8078.80");
    fs.writeFileSync(plist, "<plist>133</plist>");
    expect(getCachedBrowserExecutableVersion(exe, resolver)).toBe("133.0.6943.53");
    expect(resolver).toHaveBeenCalledTimes(2);
  });
});

describe("Chromium-fork default browsers", () => {
  it.each([
    ["com.vivaldi.Vivaldi", "Vivaldi"],
    ["com.operasoftware.Opera", "Opera"],
    ["company.thebrowser.Browser", "Arc"],
  ])("never accepts Info.plist version proof for %s", (bundleId, appName) => {
    setPlatform("darwin");
    const home = path.join(tmpDir, "home");
    const plist = path.join(
      home,
      "Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist",
    );
    fs.mkdirSync(path.dirname(plist), { recursive: true });
    fs.writeFileSync(plist, "<plist/>");
    vi.stubEnv("HOME", home);
    const exe = makeFakeApp(appName);
    const appPath = path.dirname(path.dirname(path.dirname(exe)));
    const realExists = fs.existsSync;
    vi.spyOn(fs, "existsSync").mockImplementation((p) =>
      String(p).startsWith(tmpDir) ? realExists(p) : false,
    );
    execFileSyncMock.mockImplementation((cmd: string, args: string[]) => {
      if (cmd === "/usr/bin/plutil") {
        return JSON.stringify([{ LSHandlerURLScheme: "http", LSHandlerRoleAll: bundleId }]);
      }
      if (cmd === "/usr/bin/osascript") return `${appPath}/\n`;
      if (cmd === "/usr/bin/defaults" && args.includes("CFBundleExecutable")) return appName;
      if (cmd === "/usr/bin/defaults") return "156.0.8078.80\n";
      if (cmd === exe) return `${appName} 7.0.3495.6`;
      throw new Error(`unexpected ${cmd}`);
    });

    try {
      expect(resolveBrowserExecutableForPlatform(makeConfig(), "darwin")).toBeNull();
      expect(
        execFileSyncMock.mock.calls.some(
          ([cmd, args]) =>
            cmd === "/usr/bin/defaults" &&
            (args as string[]).includes("CFBundleShortVersionString"),
        ),
      ).toBe(false);
    } finally {
      vi.unstubAllEnvs();
    }
  });
});
