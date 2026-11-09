import { describe, expect, it, vi, beforeEach } from "vitest";

vi.mock("node:child_process", () => ({
  execFileSync: vi.fn(),
}));
vi.mock("node:fs", () => {
  const existsSync = vi.fn();
  const readFileSync = vi.fn();
  return {
    existsSync,
    readFileSync,
    default: { existsSync, readFileSync },
  };
});
import { execFileSync } from "node:child_process";
import * as fs from "node:fs";

describe("browser default executable detection", () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
  });

  it("prefers default Chromium browser on macOS", async () => {
    vi.mocked(execFileSync).mockImplementation((cmd, args) => {
      const argsStr = Array.isArray(args) ? args.join(" ") : "";
      if (cmd === "/usr/bin/plutil" && argsStr.includes("LSHandlers")) {
        return JSON.stringify([
          { LSHandlerURLScheme: "http", LSHandlerRoleAll: "com.google.Chrome" },
        ]);
      }
      if (cmd === "/usr/bin/osascript" && argsStr.includes("path to application id")) {
        return "/Applications/Google Chrome.app";
      }
      if (cmd === "/usr/bin/defaults") {
        if (argsStr.includes("CFBundleShortVersionString")) {
          return "156.0.8078.80";
        }
        return "Google Chrome";
      }
      if (argsStr.includes("--version")) {
        return "Google Chrome 156.0.8078.80";
      }
      return "";
    });
    vi.mocked(fs.existsSync).mockImplementation((p) => {
      const value = String(p);
      if (value.includes("com.apple.launchservices.secure.plist")) return true;
      return value.includes("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
    });

    const { resolveBrowserExecutableForPlatform } = await import("./chrome.executables.js");
    const exe = resolveBrowserExecutableForPlatform(
      {} as Parameters<typeof resolveBrowserExecutableForPlatform>[0],
      "darwin",
    );

    expect(exe?.path).toContain("Google Chrome.app/Contents/MacOS/Google Chrome");
    expect(exe?.kind).toBe("chrome");
  });

  it("falls back when default browser is non-Chromium on macOS", async () => {
    vi.mocked(execFileSync).mockImplementation((cmd, args) => {
      const argsStr = Array.isArray(args) ? args.join(" ") : "";
      if (cmd === "/usr/bin/plutil" && argsStr.includes("LSHandlers")) {
        return JSON.stringify([
          { LSHandlerURLScheme: "http", LSHandlerRoleAll: "com.apple.Safari" },
        ]);
      }
      if (cmd === "/usr/bin/defaults" && argsStr.includes("CFBundleShortVersionString")) {
        return "156.0.8078.80";
      }
      if (argsStr.includes("--version")) {
        return "Google Chrome 156.0.8078.80";
      }
      return "";
    });
    vi.mocked(fs.existsSync).mockImplementation((p) => {
      const value = String(p);
      if (value.includes("com.apple.launchservices.secure.plist")) return true;
      return value.includes("Google Chrome.app/Contents/MacOS/Google Chrome");
    });

    const { resolveBrowserExecutableForPlatform } = await import("./chrome.executables.js");
    const exe = resolveBrowserExecutableForPlatform(
      {} as Parameters<typeof resolveBrowserExecutableForPlatform>[0],
      "darwin",
    );

    expect(exe?.path).toContain("Google Chrome.app/Contents/MacOS/Google Chrome");
  });
});
