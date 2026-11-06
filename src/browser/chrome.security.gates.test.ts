import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const cdpMocks = vi.hoisted(() => ({ createTargetViaCdp: vi.fn() }));
const chromeMocks = vi.hoisted(() => ({
  isChromeCdpReady: vi.fn(async () => true),
  isChromeReachable: vi.fn(async () => true),
}));

vi.mock("./cdp.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./cdp.js")>();
  return { ...actual, createTargetViaCdp: cdpMocks.createTargetViaCdp };
});

vi.mock("./chrome.js", () => ({
  isChromeCdpReady: chromeMocks.isChromeCdpReady,
  isChromeReachable: chromeMocks.isChromeReachable,
  launchClawdChrome: vi.fn(async () => {
    throw new Error("unexpected launch");
  }),
  resolveClawdUserDataDir: vi.fn(() => "/tmp/clawd"),
  stopClawdChrome: vi.fn(async () => {}),
}));

import {
  BrowserSecurityProofUnavailableError,
  BrowserSecurityRefusalError,
  assertCdpEndpointSecurity,
  clearCdpSecurityCache,
  redactCdpUrl,
} from "./chrome.security.js";
import type { BrowserServerState } from "./server-context.js";
import { createBrowserRouteContext } from "./server-context.js";

type FetchCall = { url: string; init?: RequestInit };

function stubFetch(versionBody: unknown) {
  const calls: FetchCall[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: unknown, init?: RequestInit) => {
      const u = String(url);
      calls.push({ url: u, init });
      if (u.includes("/json/version")) {
        const body =
          typeof versionBody === "function" ? (versionBody as () => unknown)() : versionBody;
        if (body instanceof Error) throw body;
        return { ok: true, json: async () => body } as unknown as Response;
      }
      if (u.includes("/json/new")) {
        return {
          ok: true,
          json: async () => ({ id: "NEW", url: "https://agent.example", type: "page" }),
        } as unknown as Response;
      }
      if (u.includes("/json/list")) {
        return { ok: true, json: async () => [] } as unknown as Response;
      }
      return { ok: false, status: 404, json: async () => ({}) } as unknown as Response;
    }),
  );
  return calls;
}

function makeState(profile: Record<string, unknown>, attachOnly = false): BrowserServerState {
  return {
    // biome-ignore lint/suspicious/noExplicitAny: test stub
    server: null as any,
    port: 0,
    resolved: {
      enabled: true,
      controlPort: 18791,
      cdpProtocol: "http",
      cdpHost: "127.0.0.1",
      cdpIsLoopback: true,
      color: "#FF4500",
      headless: true,
      noSandbox: false,
      attachOnly,
      defaultProfile: "work",
      profiles: { work: { color: "#00AA00", ...profile } },
    },
    profiles: new Map(),
  } as unknown as BrowserServerState;
}

describe("CDP security gate production paths", () => {
  beforeEach(() => {
    clearCdpSecurityCache();
    cdpMocks.createTargetViaCdp.mockReset();
    chromeMocks.isChromeCdpReady.mockReset().mockResolvedValue(true);
    chromeMocks.isChromeReachable.mockReset().mockResolvedValue(true);
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  describe("openTab", () => {
    it("propagates a createTarget security refusal instead of falling back to /json/new", async () => {
      const calls = stubFetch({ Browser: "Chrome/156.0.8078.80" });
      cdpMocks.createTargetViaCdp.mockRejectedValue(
        new BrowserSecurityRefusalError(
          "Refusing browser (version 145.0.7632.6) for CDP createTarget",
        ),
      );
      const ctx = createBrowserRouteContext({
        getState: () => makeState({ cdpUrl: "http://127.0.0.1:18800", cdpPort: 18800 }),
      });

      await expect(ctx.forProfile("work").openTab("https://agent.example")).rejects.toBeInstanceOf(
        BrowserSecurityRefusalError,
      );
      expect(calls.some((c) => c.url.includes("/json/new"))).toBe(false);
    });

    it("gates the /json/new fallback when createTarget fails for a non-security reason", async () => {
      const calls = stubFetch({ Browser: "Chrome/145.0.7632.6" });
      cdpMocks.createTargetViaCdp.mockRejectedValue(new Error("CDP websocket closed"));
      const ctx = createBrowserRouteContext({
        getState: () => makeState({ cdpUrl: "http://127.0.0.1:18800", cdpPort: 18800 }),
      });

      await expect(ctx.forProfile("work").openTab("https://agent.example")).rejects.toThrowError(
        /below minimum security baseline/,
      );
      expect(calls.some((c) => c.url.includes("/json/new"))).toBe(false);
    });

    it("still uses the /json/new fallback for a patched browser", async () => {
      const calls = stubFetch({ Browser: "Chrome/156.0.8078.80" });
      cdpMocks.createTargetViaCdp.mockRejectedValue(new Error("CDP websocket closed"));
      const ctx = createBrowserRouteContext({
        getState: () => makeState({ cdpUrl: "http://127.0.0.1:18800", cdpPort: 18800 }),
      });

      const tab = await ctx.forProfile("work").openTab("https://agent.example");
      expect(tab.targetId).toBe("NEW");
      expect(calls.some((c) => c.url.includes("/json/new"))).toBe(true);
    });
  });

  describe("tab list, focus and close", () => {
    it.each(["listTabs", "focusTab", "closeTab"] as const)(
      "%s refuses a below-baseline browser before touching /json/list",
      async (op) => {
        const calls = stubFetch({ Browser: "Chrome/145.0.7632.6" });
        const ctx = createBrowserRouteContext({
          getState: () => makeState({ cdpUrl: "http://127.0.0.1:18800", cdpPort: 18800 }),
        });
        const profileCtx = ctx.forProfile("work");
        const run = op === "listTabs" ? profileCtx.listTabs() : profileCtx[op]("ABC");
        await expect(run).rejects.toBeInstanceOf(BrowserSecurityRefusalError);
        expect(calls.some((c) => /\/json\/(list|activate|close)/.test(c.url))).toBe(false);
      },
    );

    it("lists tabs for a patched browser", async () => {
      const calls = stubFetch({ Browser: "Chrome/156.0.8078.80" });
      const ctx = createBrowserRouteContext({
        getState: () => makeState({ cdpUrl: "http://127.0.0.1:18800", cdpPort: 18800 }),
      });
      await expect(ctx.forProfile("work").listTabs()).resolves.toEqual([]);
      expect(calls.some((c) => c.url.includes("/json/list"))).toBe(true);
    });
  });

  describe("ensureBrowserAvailable", () => {
    it("refuses an unpatched browser reached through onEnsureAttachTarget", async () => {
      stubFetch({ Browser: "Chrome/145.0.7632.6" });
      chromeMocks.isChromeReachable.mockResolvedValueOnce(false).mockResolvedValue(true);
      const onEnsureAttachTarget = vi.fn(async () => {});
      const ctx = createBrowserRouteContext({
        getState: () => makeState({ cdpUrl: "http://127.0.0.1:18800", cdpPort: 18800 }, true),
        onEnsureAttachTarget,
      });

      await expect(ctx.forProfile("work").ensureBrowserAvailable()).rejects.toThrowError(
        /below minimum security baseline/,
      );
      expect(onEnsureAttachTarget).toHaveBeenCalledTimes(1);
    });

    it("refuses a reachable pre-existing browser that reports no Browser field", async () => {
      stubFetch({ webSocketDebuggerUrl: "ws://127.0.0.1:18800/devtools/browser/x" });
      const ctx = createBrowserRouteContext({
        getState: () => makeState({ cdpUrl: "http://127.0.0.1:18800", cdpPort: 18800 }),
      });

      await expect(ctx.forProfile("work").ensureBrowserAvailable()).rejects.toBeInstanceOf(
        BrowserSecurityProofUnavailableError,
      );
    });

    it("accepts a reachable patched browser", async () => {
      stubFetch({ Browser: "Chrome/156.0.8078.80" });
      const ctx = createBrowserRouteContext({
        getState: () => makeState({ cdpUrl: "http://127.0.0.1:18800", cdpPort: 18800 }),
      });

      await expect(ctx.forProfile("work").ensureBrowserAvailable()).resolves.toBeUndefined();
    });
  });

  describe("remote CDP authentication and redaction", () => {
    it("sends the gate request to the CDP path with token query and Basic auth", async () => {
      const calls = stubFetch({ Browser: "Chrome/156.0.8078.80" });

      await assertCdpEndpointSecurity("https://user:s3cret@browserless.example/chrome?token=abc");

      expect(calls).toHaveLength(1);
      expect(calls[0].url).toBe("https://browserless.example/chrome/json/version?token=abc");
      const headers = calls[0].init?.headers as Record<string, string>;
      expect(headers.Authorization).toBe(`Basic ${Buffer.from("user:s3cret").toString("base64")}`);
    });

    it("keeps the token and password out of every refusal message", async () => {
      const url = "https://user:s3cret@browserless.example/chrome?token=abc";
      for (const body of [
        new Error("network down"),
        { Browser: "Chrome/145.0.7632.6" },
        { Browser: "not a version" },
        { Browser: "Moltbot/extension-relay" },
      ]) {
        clearCdpSecurityCache();
        stubFetch(() => body);
        const err = await assertCdpEndpointSecurity(url).then(
          () => null,
          (e: unknown) => e as Error,
        );
        expect(err).toBeInstanceOf(Error);
        expect(err?.message).not.toContain("abc");
        expect(err?.message).not.toContain("s3cret");
        expect(err?.message).not.toContain("user:");
      }
    });

    it("refuses to follow redirects for the version proof request", async () => {
      const calls = stubFetch({ Browser: "Chrome/156.0.8078.80" });
      await assertCdpEndpointSecurity("https://browserless.example/chrome?token=abc");
      expect(calls[0].init?.redirect).toBe("error");
    });

    it("keeps the token out of the unreachable remote CDP error", async () => {
      stubFetch({ Browser: "Chrome/156.0.8078.80" });
      chromeMocks.isChromeReachable.mockResolvedValue(false);
      const ctx = createBrowserRouteContext({
        getState: () =>
          makeState({ cdpUrl: "https://user:s3cret@browserless.example/chrome?token=abc" }),
      });
      const err = await ctx
        .forProfile("work")
        .ensureBrowserAvailable()
        .then(
          () => null,
          (e: unknown) => e as Error,
        );
      expect(err?.message).toMatch(/is not reachable at https:\/\/browserless\.example\/chrome/);
      expect(err?.message).not.toContain("abc");
      expect(err?.message).not.toContain("s3cret");
    });

    it("keeps the token out of the non-loopback extension relay error", async () => {
      stubFetch({ Browser: "Chrome/156.0.8078.80" });
      const ctx = createBrowserRouteContext({
        getState: () =>
          makeState({
            driver: "extension",
            cdpUrl: "https://user:s3cret@relay.example/cdp?token=abc",
          }),
      });
      const err = await ctx
        .forProfile("work")
        .ensureBrowserAvailable()
        .then(
          () => null,
          (e: unknown) => e as Error,
        );
      expect(err?.message).toMatch(/cdpUrl is not loopback \(https:\/\/relay\.example\/cdp/);
      expect(err?.message).not.toContain("abc");
      expect(err?.message).not.toContain("s3cret");
    });

    it("redacts userinfo, query, and fragment", () => {
      expect(redactCdpUrl("https://u:p@h.example/c?token=abc#x")).toBe(
        "https://h.example/c [redacted]",
      );
      expect(redactCdpUrl("http://127.0.0.1:9222")).toBe("http://127.0.0.1:9222");
      expect(redactCdpUrl("::not a url::")).toBe("[unparseable CDP URL]");
    });
  });

  describe("pw-session retry classification", () => {
    it("retries a transient proof failure and connects once proof arrives", async () => {
      vi.resetModules();
      let versionCalls = 0;
      stubFetch(() => {
        versionCalls += 1;
        return versionCalls === 1 ? new Error("ECONNRESET") : { Browser: "Chrome/156.0.8078.80" };
      });
      const page = { on: vi.fn(), url: () => "about:blank" };
      const browser = {
        on: vi.fn(),
        close: vi.fn(async () => {}),
        contexts: () => [{ pages: () => [page], on: vi.fn() }],
      };
      const connectOverCDP = vi.fn(async () => browser);
      vi.doMock("playwright-core", () => ({ chromium: { connectOverCDP } }));
      vi.doMock("./chrome.js", () => ({ getChromeWebSocketUrl: vi.fn(async () => null) }));

      const mod = await import("./pw-session.js");
      await mod.getPageForTargetId({ cdpUrl: "http://127.0.0.1:18801" });
      expect(versionCalls).toBe(2);
      expect(connectOverCDP).toHaveBeenCalledTimes(1);
      await mod.closePlaywrightBrowserConnection();
      vi.doUnmock("playwright-core");
      vi.doUnmock("./chrome.js");
    });

    it("does not retry a positive refusal", async () => {
      vi.resetModules();
      let versionCalls = 0;
      stubFetch(() => {
        versionCalls += 1;
        return { Browser: "Chrome/145.0.7632.6" };
      });
      const connectOverCDP = vi.fn();
      vi.doMock("playwright-core", () => ({ chromium: { connectOverCDP } }));
      vi.doMock("./chrome.js", () => ({ getChromeWebSocketUrl: vi.fn(async () => null) }));

      const mod = await import("./pw-session.js");
      await expect(
        mod.getPageForTargetId({ cdpUrl: "http://127.0.0.1:18802" }),
      ).rejects.toThrowError(/below minimum security baseline/);
      expect(versionCalls).toBe(1);
      expect(connectOverCDP).not.toHaveBeenCalled();
      vi.doUnmock("playwright-core");
      vi.doUnmock("./chrome.js");
    });

    it("fails closed after every retry when proof never arrives", async () => {
      vi.resetModules();
      let versionCalls = 0;
      stubFetch(() => {
        versionCalls += 1;
        return new Error("ECONNREFUSED");
      });
      const connectOverCDP = vi.fn();
      vi.doMock("playwright-core", () => ({ chromium: { connectOverCDP } }));
      vi.doMock("./chrome.js", () => ({ getChromeWebSocketUrl: vi.fn(async () => null) }));

      const mod = await import("./pw-session.js");
      await expect(
        mod.getPageForTargetId({ cdpUrl: "http://127.0.0.1:18803" }),
      ).rejects.toThrowError(/failed to obtain \/json\/version proof/);
      expect(versionCalls).toBe(3);
      expect(connectOverCDP).not.toHaveBeenCalled();
      vi.doUnmock("playwright-core");
      vi.doUnmock("./chrome.js");
    });
  });
});
