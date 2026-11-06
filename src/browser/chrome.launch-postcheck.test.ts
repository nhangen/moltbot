import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const spawnMock = vi.hoisted(() => vi.fn());

vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return { ...actual, spawn: spawnMock };
});
vi.mock("../infra/ports.js", () => ({ ensurePortAvailable: vi.fn(async () => {}) }));
vi.mock("./chrome.executables.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./chrome.executables.js")>();
  return {
    ...actual,
    resolveBrowserExecutableForPlatform: vi.fn(() => ({
      kind: "chrome",
      path: "/fake/never-executed/chrome",
      version: "156.0.8078.80",
    })),
  };
});

import type { ResolvedBrowserConfig, ResolvedBrowserProfile } from "./config.js";

function fakeProc() {
  return { pid: 4242, exitCode: null, killed: false, kill: vi.fn(() => true), on: vi.fn() };
}

const config = {
  enabled: true,
  evaluateEnabled: true,
  controlPort: 0,
  cdpProtocol: "http",
  cdpHost: "127.0.0.1",
  cdpIsLoopback: true,
  remoteCdpTimeoutMs: 1000,
  remoteCdpHandshakeTimeoutMs: 2000,
  color: "#000",
  headless: true,
  noSandbox: false,
  attachOnly: false,
  defaultProfile: "clawd",
  profiles: {},
} as unknown as ResolvedBrowserConfig;

const profile: ResolvedBrowserProfile = {
  name: "postcheck",
  cdpPort: 18999,
  cdpUrl: "http://127.0.0.1:18999",
  cdpHost: "127.0.0.1",
  cdpIsLoopback: true,
  color: "#FF4500",
  driver: "clawd",
};

let stateDir: string;

beforeEach(() => {
  stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "moltbot-postcheck-"));
  vi.stubEnv("MOLTBOT_STATE_DIR", stateDir);
  spawnMock.mockReset();
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  fs.rmSync(stateDir, { recursive: true, force: true });
});

async function launchWithVersionBody(
  body: Record<string, unknown>,
  overrides: Partial<ResolvedBrowserConfig> = {},
) {
  vi.resetModules();
  const chrome = await import("./chrome.js");
  const userDataDir = chrome.resolveClawdUserDataDir(profile.name);
  expect(userDataDir.startsWith(stateDir)).toBe(true);
  fs.mkdirSync(path.join(userDataDir, "Default"), { recursive: true });
  fs.writeFileSync(path.join(userDataDir, "Local State"), "{}");
  fs.writeFileSync(path.join(userDataDir, "Default", "Preferences"), "{}");

  const proc = fakeProc();
  spawnMock.mockReturnValue(proc);
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: unknown) =>
      String(url).includes("/json/version")
        ? ({ ok: true, json: async () => body } as unknown as Response)
        : ({ ok: false, json: async () => ({}) } as unknown as Response),
    ),
  );
  const result = chrome.launchClawdChrome({ ...config, ...overrides }, profile);
  return { proc, result };
}

describe("launchClawdChrome post-launch version verification", () => {
  it.each([
    [
      "missing Browser",
      { webSocketDebuggerUrl: "ws://x" },
      /failed to obtain \/json\/version proof/,
    ],
    ["unparseable Browser", { Browser: "SomethingElse" }, /unparseable Browser string/],
    [
      "below-baseline Browser",
      { Browser: "Chrome/145.0.7632.6" },
      /below minimum security baseline/,
    ],
  ])("kills the spawned process and refuses on %s", async (_label, body, message) => {
    const { proc, result } = await launchWithVersionBody(body);
    await expect(result).rejects.toThrowError(message);
    expect(spawnMock).toHaveBeenCalledTimes(1);
    expect(proc.kill).toHaveBeenCalledWith("SIGKILL");
  });

  it("refuses with a typed error and never echoes the endpoint Browser string", async () => {
    const { proc, result } = await launchWithVersionBody({ Browser: "Injected\nFAKE LOG LINE" });
    const err = await result.then(
      () => null,
      (e: unknown) => e,
    );
    const { BrowserSecurityRefusalError } = await import("./chrome.security.js");
    expect(err).toBeInstanceOf(BrowserSecurityRefusalError);
    expect(String((err as Error).message)).not.toContain("FAKE LOG LINE");
    expect(proc.kill).toHaveBeenCalledWith("SIGKILL");
  });

  it("refuses browser.noSandbox before spawning anything", async () => {
    const { result } = await launchWithVersionBody(
      { Browser: "Chrome/156.0.8078.80" },
      { noSandbox: true },
    );
    const err = await result.then(
      () => null,
      (e: unknown) => e,
    );
    const { BrowserSecurityRefusalError } = await import("./chrome.security.js");
    expect(err).toBeInstanceOf(BrowserSecurityRefusalError);
    expect(String((err as Error).message)).toContain("browser.noSandbox");
    expect(spawnMock).not.toHaveBeenCalled();
  });

  it("returns the running browser without killing it for a patched version", async () => {
    const { proc, result } = await launchWithVersionBody({ Browser: "Chrome/156.0.8078.80" });
    const running = await result;
    expect(running.pid).toBe(4242);
    expect(proc.kill).not.toHaveBeenCalled();
    const [, args] = spawnMock.mock.calls[0];
    expect(args).not.toContain("--no-sandbox");
    expect(args).not.toContain("--disable-setuid-sandbox");
  });
});
