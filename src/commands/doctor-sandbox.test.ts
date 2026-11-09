import { beforeEach, describe, expect, it, vi } from "vitest";

import type { MoltbotConfig } from "../config/config.js";
import type { RuntimeEnv } from "../runtime.js";
import type { DoctorPrompter } from "./doctor-prompter.js";

const note = vi.hoisted(() => vi.fn());
const runExec = vi.hoisted(() => vi.fn());
const browserLabel = vi.hoisted(() => ({ value: "" }));

vi.mock("../terminal/note.js", () => ({ note }));
vi.mock("../process/exec.js", () => ({
  runExec,
  runCommandWithTimeout: vi.fn(),
}));

import { maybeRepairSandboxImages } from "./doctor-sandbox.js";

const cfg = {
  agents: { defaults: { sandbox: { mode: "all", browser: { enabled: true } } } },
} as MoltbotConfig;

const prompter = {
  confirmSkipInNonInteractive: vi.fn(async () => false),
} as unknown as DoctorPrompter;

const runtime = { log: vi.fn(), error: vi.fn(), exit: vi.fn() } as unknown as RuntimeEnv;

describe("maybeRepairSandboxImages browser security label", () => {
  beforeEach(() => {
    note.mockClear();
    runExec.mockReset();
    runExec.mockImplementation(async (_cmd: string, args: string[]) => {
      if (args.includes("--format") && args[0] === "image") {
        return { stdout: `${browserLabel.value}\n`, stderr: "" };
      }
      return { stdout: "", stderr: "" };
    });
  });

  const notes = () => note.mock.calls.map((call) => String(call[0])).join("\n");

  it("flags a browser image built before the sandboxed entrypoint", async () => {
    browserLabel.value = "";
    await maybeRepairSandboxImages(cfg, runtime, prompter);
    expect(notes()).toContain("moltbot.sandbox-browser.security=sandboxed-v2");
    expect(notes()).toContain("scripts/sandbox-browser-setup.sh");
  });

  it("stays quiet when the browser image carries the current label", async () => {
    browserLabel.value = "sandboxed-v2";
    await maybeRepairSandboxImages(cfg, runtime, prompter);
    expect(notes()).not.toContain("sandbox-browser.security");
  });
});
