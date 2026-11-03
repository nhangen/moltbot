import fs from "node:fs";
import { afterEach, describe, expect, it, vi } from "vitest";

import { resolveBrowserExecutableForPlatform } from "./chrome.executables.js";
import {
  CHROMIUM_SECURITY_ADVISORY,
  CHROMIUM_SECURITY_CVES,
  MIN_CHROMIUM_SECURITY_VERSION,
  PINNED_CFT_VERSION,
  assertBrowserSecurityBaseline,
  compareChromiumVersions,
  isChromiumVersionAtLeast,
  parseChromiumVersion,
  validateBrowserExecutableSecurity,
} from "./chrome.security.js";
import type { ResolvedBrowserConfig } from "./config.js";

describe("Chromium security baseline and version verification", () => {
  describe("version parsing and comparison", () => {
    it("parses valid Chromium versions from various banner formats", () => {
      expect(parseChromiumVersion("Google Chrome 156.0.8078.80")).toEqual([156, 0, 8078, 80]);
      expect(parseChromiumVersion("Chromium 156.0.8078.73")).toEqual([156, 0, 8078, 73]);
      expect(parseChromiumVersion("Brave Browser 156.0.8078.74")).toEqual([156, 0, 8078, 74]);
      expect(parseChromiumVersion("Chrome/156.0.8078.80")).toEqual([156, 0, 8078, 80]);
      expect(parseChromiumVersion("156.0.8078.4")).toEqual([156, 0, 8078, 4]);
      expect(parseChromiumVersion("145.0.7632.6")).toEqual([145, 0, 7632, 6]);
      expect(parseChromiumVersion("invalid-version")).toBeNull();
      expect(parseChromiumVersion("")).toBeNull();
    });

    it("correctly compares version components", () => {
      // Pinned official patched candidate vs baseline
      expect(compareChromiumVersions("156.0.8078.80", MIN_CHROMIUM_SECURITY_VERSION)).toBe(1);
      // Fixed platform release (.74) vs baseline (.73)
      expect(compareChromiumVersions("156.0.8078.74", MIN_CHROMIUM_SECURITY_VERSION)).toBe(1);
      // Exact baseline
      expect(compareChromiumVersions("156.0.8078.73", MIN_CHROMIUM_SECURITY_VERSION)).toBe(0);
      // One build patch below baseline (.72)
      expect(compareChromiumVersions("156.0.8078.72", MIN_CHROMIUM_SECURITY_VERSION)).toBe(-1);
      // Playwright 1.64.1 mapped Chromium (156.0.8078.4 / rev 1248) - MUST be refused
      expect(compareChromiumVersions("156.0.8078.4", MIN_CHROMIUM_SECURITY_VERSION)).toBe(-1);
      // Playwright 1.58.0 bundled Chromium (145.0.7632.6 / rev 1208) - MUST be refused
      expect(compareChromiumVersions("145.0.7632.6", MIN_CHROMIUM_SECURITY_VERSION)).toBe(-1);
      // Older unpinned releases
      expect(compareChromiumVersions("130.0.6723.69", MIN_CHROMIUM_SECURITY_VERSION)).toBe(-1);
    });

    it("isChromiumVersionAtLeast matches expected security boundary", () => {
      expect(isChromiumVersionAtLeast("156.0.8078.80")).toBe(true);
      expect(isChromiumVersionAtLeast("156.0.8078.74")).toBe(true);
      expect(isChromiumVersionAtLeast("156.0.8078.73")).toBe(true);
      expect(isChromiumVersionAtLeast("156.0.8078.4")).toBe(false);
      expect(isChromiumVersionAtLeast("145.0.7632.6")).toBe(false);
      expect(isChromiumVersionAtLeast("130.0.0.0")).toBe(false);
    });

    it("assertBrowserSecurityBaseline succeeds for secure versions and throws with CVE details for insecure versions", () => {
      expect(() => assertBrowserSecurityBaseline("156.0.8078.80")).not.toThrow();
      expect(() => assertBrowserSecurityBaseline("156.0.8078.73")).not.toThrow();

      expect(() =>
        assertBrowserSecurityBaseline("156.0.8078.4", "Playwright test runner"),
      ).toThrowError(
        /Refusing browser \(version 156\.0\.8078\.4\) for Playwright test runner: version is below minimum security baseline 156\.0\.8078\.73/,
      );

      try {
        assertBrowserSecurityBaseline("145.0.7632.6", "bundled fallback");
      } catch (err: unknown) {
        const msg = String(err);
        for (const cve of CHROMIUM_SECURITY_CVES) {
          expect(msg).toContain(cve);
        }
        expect(msg).toContain(CHROMIUM_SECURITY_ADVISORY);
      }
    });
  });

  describe("production-path resolution with injected launchers", () => {
    afterEach(() => {
      vi.unstubAllEnvs();
      vi.unstubAllGlobals();
      vi.restoreAllMocks();
    });

    it("refuses missing executable path with descriptive error", () => {
      const config: ResolvedBrowserConfig = {
        enabled: true,
        evaluateEnabled: true,
        controlPort: 0,
        cdpProtocol: "http",
        cdpHost: "127.0.0.1",
        cdpIsLoopback: true,
        remoteCdpTimeoutMs: 1000,
        remoteCdpHandshakeTimeoutMs: 2000,
        color: "#000",
        executablePath: "/nonexistent/browser/path/chrome",
        headless: true,
        noSandbox: false,
        attachOnly: false,
        defaultProfile: "clawd",
        profiles: {},
      };

      expect(() => resolveBrowserExecutableForPlatform(config, process.platform)).toThrowError(
        /browser\.executablePath not found: \/nonexistent\/browser\/path\/chrome/,
      );
    });

    it("refuses an explicit executable whose version is below security baseline", () => {
      vi.spyOn(fs, "existsSync").mockReturnValue(true);

      const mockResolver = vi.fn((_p: string) => "156.0.8078.4"); // Playwright 1.64.1 rev, below fix

      const config: ResolvedBrowserConfig = {
        enabled: true,
        evaluateEnabled: true,
        controlPort: 0,
        cdpProtocol: "http",
        cdpHost: "127.0.0.1",
        cdpIsLoopback: true,
        remoteCdpTimeoutMs: 1000,
        remoteCdpHandshakeTimeoutMs: 2000,
        color: "#000",
        executablePath: "/custom/bin/chrome-old",
        headless: true,
        noSandbox: false,
        attachOnly: false,
        defaultProfile: "clawd",
        profiles: {},
      };

      expect(() =>
        resolveBrowserExecutableForPlatform(config, process.platform, {
          versionResolver: mockResolver,
        }),
      ).toThrowError(/below minimum security baseline 156\.0\.8078\.73/);
    });

    it("refuses an explicit executable when version proof fails on host platform", () => {
      vi.spyOn(fs, "existsSync").mockReturnValue(true);
      const mockResolver = vi.fn((_p: string) => null);

      const config: ResolvedBrowserConfig = {
        enabled: true,
        evaluateEnabled: true,
        controlPort: 0,
        cdpProtocol: "http",
        cdpHost: "127.0.0.1",
        cdpIsLoopback: true,
        remoteCdpTimeoutMs: 1000,
        remoteCdpHandshakeTimeoutMs: 2000,
        color: "#000",
        executablePath: "/custom/bin/unverifiable-chrome",
        headless: true,
        noSandbox: false,
        attachOnly: false,
        defaultProfile: "clawd",
        profiles: {},
      };

      expect(() =>
        resolveBrowserExecutableForPlatform(config, process.platform, {
          versionResolver: mockResolver,
        }),
      ).toThrowError(/Unable to verify version of browser executable/);
    });

    it("succeeds when an explicit patched executable is selected and verified", () => {
      vi.spyOn(fs, "existsSync").mockReturnValue(true);
      const mockResolver = vi.fn((_p: string) => PINNED_CFT_VERSION);

      const config: ResolvedBrowserConfig = {
        enabled: true,
        evaluateEnabled: true,
        controlPort: 0,
        cdpProtocol: "http",
        cdpHost: "127.0.0.1",
        cdpIsLoopback: true,
        remoteCdpTimeoutMs: 1000,
        remoteCdpHandshakeTimeoutMs: 2000,
        color: "#000",
        executablePath: "/custom/bin/chrome-patched",
        headless: true,
        noSandbox: false,
        attachOnly: false,
        defaultProfile: "clawd",
        profiles: {},
      };

      const resolved = resolveBrowserExecutableForPlatform(config, process.platform, {
        versionResolver: mockResolver,
      });

      expect(resolved).toEqual({
        kind: "custom",
        path: "/custom/bin/chrome-patched",
        version: "156.0.8078.80",
      });
    });

    it("fails closed without silent fallback when installed candidates are below baseline", () => {
      vi.spyOn(fs, "existsSync").mockReturnValue(true);
      // All discovered candidates report unpatched version
      const mockResolver = vi.fn((_p: string) => "145.0.7632.6");

      const config: ResolvedBrowserConfig = {
        enabled: true,
        evaluateEnabled: true,
        controlPort: 0,
        cdpProtocol: "http",
        cdpHost: "127.0.0.1",
        cdpIsLoopback: true,
        remoteCdpTimeoutMs: 1000,
        remoteCdpHandshakeTimeoutMs: 2000,
        color: "#000",
        executablePath: undefined,
        headless: true,
        noSandbox: false,
        attachOnly: false,
        defaultProfile: "clawd",
        profiles: {},
      };

      const resolved = resolveBrowserExecutableForPlatform(config, process.platform, {
        versionResolver: mockResolver,
      });

      // Must fail closed (null), never returning an unpatched executable
      expect(resolved).toBeNull();
    });

    it("selects patched candidate when older candidates precede it", () => {
      vi.spyOn(fs, "existsSync").mockReturnValue(true);
      const mockResolver = vi.fn((p: string) => {
        // First candidate is old, second is patched
        if (p.includes("Google Chrome.app")) return "156.0.8078.4"; // old
        if (p.includes("Brave Browser.app")) return "156.0.8078.80"; // patched
        return null;
      });

      const config: ResolvedBrowserConfig = {
        enabled: true,
        evaluateEnabled: true,
        controlPort: 0,
        cdpProtocol: "http",
        cdpHost: "127.0.0.1",
        cdpIsLoopback: true,
        remoteCdpTimeoutMs: 1000,
        remoteCdpHandshakeTimeoutMs: 2000,
        color: "#000",
        executablePath: undefined,
        headless: true,
        noSandbox: false,
        attachOnly: false,
        defaultProfile: "clawd",
        profiles: {},
      };

      const resolved = resolveBrowserExecutableForPlatform(config, "darwin", {
        versionResolver: mockResolver,
      });

      expect(resolved?.kind).toBe("brave");
      expect(resolved?.version).toBe("156.0.8078.80");
    });
  });

  describe("sandboxing and security invariant verification", () => {
    it("refuses CDP connection when /json/version reports vulnerable browser", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn().mockImplementation((url: string) => {
          if (String(url).includes("/json/version")) {
            return Promise.resolve({
              ok: true,
              json: async () => ({
                Browser: "Chrome/145.0.7632.6",
                webSocketDebuggerUrl: "ws://127.0.0.1:9222/devtools/browser/1",
              }),
            });
          }
          return Promise.resolve({ ok: false });
        }),
      );

      const { getPageForTargetId } = await import("./pw-session.js");
      await expect(getPageForTargetId({ cdpUrl: "http://127.0.0.1:9222" })).rejects.toThrowError(
        /below minimum security baseline 156\.0\.8078\.73/,
      );
    });

    it("accepts CDP connection when /json/version reports patched browser", () => {
      const cdpVersion = { Browser: "Chrome/156.0.8078.80" };
      const parsed = parseChromiumVersion(cdpVersion.Browser);
      expect(parsed).toEqual([156, 0, 8078, 80]);
      expect(() => assertBrowserSecurityBaseline(parsed!.join("."), "CDP endpoint")).not.toThrow();
    });

    it("preserves sandboxing by defaulting noSandbox to false in browser config", async () => {
      const { resolveBrowserConfig } = await import("./config.js");
      const resolved = resolveBrowserConfig({});
      expect(resolved.noSandbox).toBe(false);
    });

    it("validates validateBrowserExecutableSecurity helper output", () => {
      // Insecure binary
      const mockResolverInsecure = () => "156.0.8078.4";
      const resInsecure = validateBrowserExecutableSecurity(
        "/mock/chrome",
        MIN_CHROMIUM_SECURITY_VERSION,
        mockResolverInsecure,
      );
      expect(resInsecure.valid).toBe(false);
      if (!resInsecure.valid) {
        expect(resInsecure.version).toBe("156.0.8078.4");
        expect(resInsecure.error).toContain("below minimum security baseline");
      }

      // Patched binary
      const mockResolverSecure = () => "156.0.8078.80";
      const resSecure = validateBrowserExecutableSecurity(
        "/mock/chrome",
        MIN_CHROMIUM_SECURITY_VERSION,
        mockResolverSecure,
      );
      expect(resSecure.valid).toBe(true);
      if (resSecure.valid) {
        expect(resSecure.version).toBe("156.0.8078.80");
      }
    });
  });
});
