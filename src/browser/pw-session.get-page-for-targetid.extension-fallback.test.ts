import { describe, expect, it, vi } from "vitest";

describe("pw-session getPageForTargetId", () => {
  it("falls back to the only page when CDP session attachment is blocked", async () => {
    vi.resetModules();

    const pageOn = vi.fn();
    const contextOn = vi.fn();
    const browserOn = vi.fn();
    const browserClose = vi.fn(async () => {});

    const context = {
      pages: () => [],
      on: contextOn,
      newCDPSession: vi.fn(async () => {
        throw new Error("Not allowed");
      }),
    } as unknown as import("playwright-core").BrowserContext;

    const page = {
      on: pageOn,
      context: () => context,
    } as unknown as import("playwright-core").Page;

    // Fill pages() after page exists.
    (context as unknown as { pages: () => unknown[] }).pages = () => [page];

    const browser = {
      contexts: () => [context],
      on: browserOn,
      close: browserClose,
    } as unknown as import("playwright-core").Browser;

    vi.doMock("playwright-core", () => ({
      chromium: {
        connectOverCDP: vi.fn(async () => browser),
      },
    }));

    vi.doMock("./chrome.js", () => ({
      getChromeWebSocketUrl: vi.fn(async () => null),
    }));

    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string | URL | Request) => {
        const urlStr = typeof url === "string" ? url : url instanceof URL ? url.href : url.url;
        if (urlStr.includes("/json/version")) {
          return new Response(JSON.stringify({ Browser: "Chrome/156.0.8078.80" }), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }
        return new Response("Not found", { status: 404 });
      }),
    );

    const mod = await import("./pw-session.js");
    const resolved = await mod.getPageForTargetId({
      cdpUrl: "http://127.0.0.1:18792",
      targetId: "NOT_A_TAB",
    });
    expect(resolved).toBe(page);

    await mod.closePlaywrightBrowserConnection();
    expect(browserClose).toHaveBeenCalled();
    vi.unstubAllGlobals();
  });

  it("refuses the real extension relay banner before connecting", async () => {
    vi.resetModules();
    const connectOverCDP = vi.fn(async () => {
      throw new Error("Sentinel: connectOverCDP must not be called");
    });
    vi.doMock("playwright-core", () => ({ chromium: { connectOverCDP } }));
    vi.doMock("./chrome.js", () => ({ getChromeWebSocketUrl: vi.fn(async () => null) }));
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string | URL | Request) => {
        const urlStr = typeof url === "string" ? url : url instanceof URL ? url.href : url.url;
        if (urlStr.includes("/json/version")) {
          return new Response(JSON.stringify({ Browser: "Moltbot/extension-relay" }), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }
        return new Response("Not found", { status: 404 });
      }),
    );

    const mod = await import("./pw-session.js");
    await expect(
      mod.getPageForTargetId({ cdpUrl: "http://127.0.0.1:18792", targetId: "NOT_A_TAB" }),
    ).rejects.toThrowError(/extension relay does not yet support verifiable/);
    expect(connectOverCDP).not.toHaveBeenCalled();
    vi.unstubAllGlobals();
  });
});
