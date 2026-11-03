import { execFileSync } from "node:child_process";
import fs from "node:fs";
import { chromium } from "playwright-core";
import { afterEach, describe, expect, it, vi } from "vitest";

import { resolveBrowserExecutableForPlatform } from "./chrome.executables.js";
import {
  CHROMIUM_SECURITY_ADVISORY,
  CHROMIUM_SECURITY_CVES,
  MIN_CHROMIUM_SECURITY_VERSION,
  PINNED_CFT_VERSION,
  assertBrowserSecurityBaseline,
  assertProcessSandboxed,
  compareChromiumVersions,
  isChromiumVersionAtLeast,
  parseChromiumVersion,
  queryDarwinProcessSeatbeltState,
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
      // Future major versions (> 156) must be permitted
      expect(compareChromiumVersions("200.0.0.0", MIN_CHROMIUM_SECURITY_VERSION)).toBe(1);
      expect(compareChromiumVersions("157.0.0.0", MIN_CHROMIUM_SECURITY_VERSION)).toBe(1);
      expect(compareChromiumVersions("156.1.0.0", MIN_CHROMIUM_SECURITY_VERSION)).toBe(1);
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

    it("isChromiumVersionAtLeast matches expected security boundary and permits newer major versions", () => {
      // Future major versions must succeed without hardcoded major 156 lock-in
      expect(isChromiumVersionAtLeast("200.0.0.0")).toBe(true);
      expect(isChromiumVersionAtLeast("160.0.8100.1")).toBe(true);
      expect(isChromiumVersionAtLeast("157.0.0.0")).toBe(true);
      expect(isChromiumVersionAtLeast("156.1.0.0")).toBe(true);
      // Supported patched candidates
      expect(isChromiumVersionAtLeast("156.0.8078.80")).toBe(true);
      expect(isChromiumVersionAtLeast("156.0.8078.74")).toBe(true);
      expect(isChromiumVersionAtLeast("156.0.8078.73")).toBe(true);
      // Insecure releases below baseline
      expect(isChromiumVersionAtLeast("156.0.8078.72")).toBe(false);
      expect(isChromiumVersionAtLeast("156.0.8078.4")).toBe(false);
      expect(isChromiumVersionAtLeast("145.0.7632.6")).toBe(false);
      expect(isChromiumVersionAtLeast("130.0.0.0")).toBe(false);
    });

    it("assertBrowserSecurityBaseline succeeds for secure versions and throws with CVE details for insecure versions", () => {
      // Future and patched versions succeed
      expect(() => assertBrowserSecurityBaseline("200.0.0.0")).not.toThrow();
      expect(() => assertBrowserSecurityBaseline("157.0.0.0")).not.toThrow();
      expect(() => assertBrowserSecurityBaseline("156.0.8078.80")).not.toThrow();
      expect(() => assertBrowserSecurityBaseline("156.0.8078.73")).not.toThrow();

      // Refusal on version below baseline throws outside any process-read catch
      expect(() =>
        assertBrowserSecurityBaseline("156.0.8078.4", "Playwright test runner"),
      ).toThrowError(
        /Refusing browser \(version 156\.0\.8078\.4\) for Playwright test runner: version is below minimum security baseline 156\.0\.8078\.73/,
      );

      // Verify exact error message includes CVE IDs and official advisory link
      expect(() => assertBrowserSecurityBaseline("145.0.7632.6", "bundled fallback")).toThrowError(
        new RegExp(CHROMIUM_SECURITY_CVES[0]),
      );
      expect(() => assertBrowserSecurityBaseline("145.0.7632.6", "bundled fallback")).toThrowError(
        new RegExp(CHROMIUM_SECURITY_ADVISORY.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")),
      );
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

    it("assertProcessSandboxed verifies command lines and rejects forbidden --no-sandbox", () => {
      // Sandboxed renderer on darwin with seatbelt
      const sandboxedDarwinCmd =
        "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Helpers/Google Chrome Helper (Renderer).app/Contents/MacOS/Google Chrome Helper (Renderer) --type=renderer --seatbelt-client=23 --headless=new";
      expect(() => assertProcessSandboxed(sandboxedDarwinCmd, "darwin")).not.toThrow();

      // Mutant renderer with --no-sandbox
      const mutantNoSandboxCmd =
        "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Helpers/Google Chrome Helper (Renderer).app/Contents/MacOS/Google Chrome Helper (Renderer) --type=renderer --no-sandbox --headless=new";
      expect(() => assertProcessSandboxed(mutantNoSandboxCmd, "darwin")).toThrowError(
        /forbidden flag "--no-sandbox" detected/,
      );

      // Mutant renderer lacking seatbelt on darwin
      const mutantNoSeatbeltCmd =
        "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Helpers/Google Chrome Helper (Renderer).app/Contents/MacOS/Google Chrome Helper (Renderer) --type=renderer --headless=new";
      expect(() => assertProcessSandboxed(mutantNoSeatbeltCmd, "darwin")).toThrowError(
        /renderer process lacks "--seatbelt-client=" OS sandbox confinement/,
      );
    });

    it.runIf(process.platform === "darwin")(
      "queryDarwinProcessSeatbeltState verifies Seatbelt sandbox_check directly",
      () => {
        // Harness process self is not sandboxed (verifies checking self is NOT browser proof)
        expect(queryDarwinProcessSeatbeltState(process.pid)).toBe(false);

        // Rejects invalid PIDs
        expect(() => queryDarwinProcessSeatbeltState(0)).toThrowError(/Invalid PID/);
        expect(() => queryDarwinProcessSeatbeltState(-123)).toThrowError(/Invalid PID/);

        // Fails explicitly on non-existent / disappearing target without accepting false-positive
        expect(() => queryDarwinProcessSeatbeltState(9999999)).toThrow();
      },
    );

    const localChromePath = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
    const hasLocalChrome = fs.existsSync(localChromePath);

    it.runIf(hasLocalChrome)(
      "verifies causal real OS sandbox confinement and proves forbidden --no-sandbox mutant fails",
      async () => {
        // 1. Positive verification: sandboxed execution
        const browser = await chromium.launch({
          executablePath: localChromePath,
          args: ["--headless=new"],
          chromiumSandbox: true,
        });

        try {
          const page = await browser.newPage();
          await page.goto("about:blank");

          const session = await browser.newBrowserCDPSession();
          const info = (await session.send("SystemInfo.getProcessInfo")) as {
            processInfo: Array<{ id: number; type: string }>;
          };

          // Observed process counts must be non-vacuous
          const allProcesses = info.processInfo;
          expect(allProcesses.length).toBeGreaterThanOrEqual(2);

          const renderers = allProcesses.filter((p) => p.type === "renderer");
          expect(renderers.length).toBeGreaterThan(0);

          if (process.platform === "darwin") {
            const browserProc = allProcesses.find((p) => p.type === "browser");
            if (browserProc) {
              // The broker/parent process is unsandboxed; checking broker/harness is NOT renderer proof
              expect(queryDarwinProcessSeatbeltState(browserProc.id)).toBe(false);
            }
          }

          // Assertions outside process-read catches: inspect each real OS process command line
          for (const renderer of renderers) {
            const cmd = execFileSync("ps", ["-p", String(renderer.id), "-o", "command="], {
              encoding: "utf8",
            });
            // OS confinement proof: macOS Seatbelt sandbox is active and --no-sandbox is absent
            expect(cmd).toContain("--seatbelt-client=");
            expect(cmd).not.toContain("--no-sandbox");
            expect(() => assertProcessSandboxed(cmd, "darwin")).not.toThrow();

            // Direct Seatbelt libsandbox sandbox_check proof for actual owned launched renderer PID
            if (process.platform === "darwin") {
              expect(queryDarwinProcessSeatbeltState(renderer.id)).toBe(true);
            }
          }
        } finally {
          await browser.close();
        }

        // 2. Negative mutant verification: launch with forbidden --no-sandbox / chromiumSandbox: false
        const mutantBrowser = await chromium.launch({
          executablePath: localChromePath,
          args: ["--headless=new", "--no-sandbox"],
          chromiumSandbox: false,
        });

        try {
          const mutantPage = await mutantBrowser.newPage();
          await mutantPage.goto("about:blank");

          const mutantSession = await mutantBrowser.newBrowserCDPSession();
          const mutantInfo = (await mutantSession.send("SystemInfo.getProcessInfo")) as {
            processInfo: Array<{ id: number; type: string }>;
          };

          // Non-vacuous check on mutant renderers
          const mutantRenderers = mutantInfo.processInfo.filter((p) => p.type === "renderer");
          expect(mutantRenderers.length).toBeGreaterThan(0);

          // Assert each mutant renderer is unconfined and violates sandbox invariants
          for (const mutantRenderer of mutantRenderers) {
            const mutantCmd = execFileSync(
              "ps",
              ["-p", String(mutantRenderer.id), "-o", "command="],
              {
                encoding: "utf8",
              },
            );
            // In the mutant, --no-sandbox is present and --seatbelt-client= is absent
            expect(mutantCmd).toContain("--no-sandbox");
            expect(mutantCmd).not.toContain("--seatbelt-client=");

            // Direct Seatbelt libsandbox sandbox_check proof: mutant renderer is NOT sandboxed
            if (process.platform === "darwin") {
              expect(queryDarwinProcessSeatbeltState(mutantRenderer.id)).toBe(false);
            }

            // Causal proof that our sandbox baseline assertion fails on this mutant
            expect(() => assertProcessSandboxed(mutantCmd, "darwin")).toThrowError(
              /forbidden flag "--no-sandbox" detected/,
            );
          }
        } finally {
          await mutantBrowser.close();
        }
      },
      20_000,
    );
  });
});
