import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { MoltbotConfig } from "../config/config.js";

const note = vi.hoisted(() => vi.fn());

vi.mock("../terminal/note.js", () => ({
  note,
}));

vi.mock("../channels/plugins/index.js", () => ({
  listChannelPlugins: () => [],
}));

import { noteSecurityWarnings } from "./doctor-security.js";

describe("noteSecurityWarnings gateway exposure", () => {
  let prevToken: string | undefined;
  let prevPassword: string | undefined;

  beforeEach(() => {
    note.mockClear();
    prevToken = process.env.CLAWDBOT_GATEWAY_TOKEN;
    prevPassword = process.env.CLAWDBOT_GATEWAY_PASSWORD;
    delete process.env.CLAWDBOT_GATEWAY_TOKEN;
    delete process.env.CLAWDBOT_GATEWAY_PASSWORD;
  });

  afterEach(() => {
    if (prevToken === undefined) delete process.env.CLAWDBOT_GATEWAY_TOKEN;
    else process.env.CLAWDBOT_GATEWAY_TOKEN = prevToken;
    if (prevPassword === undefined) delete process.env.CLAWDBOT_GATEWAY_PASSWORD;
    else process.env.CLAWDBOT_GATEWAY_PASSWORD = prevPassword;
  });

  const lastMessage = () => String(note.mock.calls.at(-1)?.[0] ?? "");

  it("warns when exposed without auth", async () => {
    const cfg = { gateway: { bind: "lan" } } as MoltbotConfig;
    await noteSecurityWarnings(cfg);
    const message = lastMessage();
    expect(message).toContain("CRITICAL");
    expect(message).toContain("without authentication");
  });

  it("uses env token to avoid critical warning", async () => {
    process.env.CLAWDBOT_GATEWAY_TOKEN = "token-123";
    const cfg = { gateway: { bind: "lan" } } as MoltbotConfig;
    await noteSecurityWarnings(cfg);
    const message = lastMessage();
    expect(message).toContain("WARNING");
    expect(message).not.toContain("CRITICAL");
  });

  it("treats whitespace token as missing", async () => {
    const cfg = {
      gateway: { bind: "lan", auth: { mode: "token", token: "   " } },
    } as MoltbotConfig;
    await noteSecurityWarnings(cfg);
    const message = lastMessage();
    expect(message).toContain("CRITICAL");
  });

  it("skips warning for loopback bind", async () => {
    const cfg = { gateway: { bind: "loopback" } } as MoltbotConfig;
    await noteSecurityWarnings(cfg);
    const message = lastMessage();
    expect(message).toContain("No channel security warnings detected");
    expect(message).not.toContain("Gateway bound");
  });
});

describe("noteSecurityWarnings browser", () => {
  beforeEach(() => {
    note.mockClear();
  });

  const lastMessage = () => String(note.mock.calls.at(-1)?.[0] ?? "");

  it("warns that browser.noSandbox is refused", async () => {
    await noteSecurityWarnings({ browser: { noSandbox: true } } as MoltbotConfig);
    const message = lastMessage();
    expect(message).toContain("browser.noSandbox");
    expect(message).toContain("refuse");
  });

  it("warns when the default profile is the refused extension relay", async () => {
    await noteSecurityWarnings({ browser: { defaultProfile: "chrome" } } as MoltbotConfig);
    const message = lastMessage();
    expect(message).toContain('browser.defaultProfile "chrome"');
    expect(message).toContain("extension relay");
  });

  it("stays quiet about the browser on the default configuration", async () => {
    await noteSecurityWarnings({} as MoltbotConfig);
    expect(lastMessage()).not.toContain("browser.");
  });
});
