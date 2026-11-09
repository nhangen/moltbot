import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const ENTRYPOINT = path.resolve("scripts/sandbox-browser-entrypoint.sh");

let tmpDir: string;
let argsLog: string;

function writeStub(name: string, body: string) {
  fs.writeFileSync(path.join(tmpDir, "bin", name), `#!/bin/sh\n${body}\n`, { mode: 0o755 });
}

function runEntrypoint(extraEnv: Record<string, string>) {
  return spawnSync("bash", [ENTRYPOINT], {
    encoding: "utf8",
    timeout: 20_000,
    env: {
      PATH: `${path.join(tmpDir, "bin")}:/usr/bin:/bin`,
      HOME: path.join(tmpDir, "home"),
      ARGS_LOG: argsLog,
      CLAWDBOT_BROWSER_HEADLESS: "1",
      CLAWDBOT_BROWSER_ENABLE_NOVNC: "0",
      ...extraEnv,
    },
  });
}

describe.skipIf(process.platform === "win32")("sandbox browser entrypoint", () => {
  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "moltbot-entrypoint-"));
    argsLog = path.join(tmpDir, "chromium-args.log");
    fs.mkdirSync(path.join(tmpDir, "bin"));
    writeStub(
      "chromium",
      `if [ "$1" = "--version" ]; then echo "Google Chrome for Testing 156.0.8078.80"; exit 0; fi
printf '%s\\n' "$@" > "$ARGS_LOG.tmp" && mv "$ARGS_LOG.tmp" "$ARGS_LOG"`,
    );
    writeStub("curl", `[ -f "$ARGS_LOG" ]`);
    writeStub("Xvfb", "exit 0");
    writeStub("socat", "exit 0");
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it.each(["1", "true", "yes"])("refuses CLAWDBOT_BROWSER_NO_SANDBOX=%s", (value) => {
    const result = runEntrypoint({ CLAWDBOT_BROWSER_NO_SANDBOX: value });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("CLAWDBOT_BROWSER_NO_SANDBOX is not supported");
    expect(fs.existsSync(argsLog)).toBe(false);
  });

  it.each([
    ["unset", {}],
    ["0", { CLAWDBOT_BROWSER_NO_SANDBOX: "0" }],
  ])("starts Chromium sandboxed when the variable is %s", (_label, env) => {
    runEntrypoint(env);

    const args = fs.readFileSync(argsLog, "utf8").split("\n");
    expect(args).toContain("--remote-debugging-address=127.0.0.1");
    expect(args).not.toContain("--no-sandbox");
  });
  it("exits non-zero instead of serving a dead Chromium when CDP never comes up", () => {
    writeStub(
      "chromium",
      `if [ "$1" = "--version" ]; then echo "Google Chrome for Testing 156.0.8078.80"; exit 0; fi
echo "FATAL: No usable sandbox!" >&2; exit 134`,
    );
    writeStub("curl", "exit 7");
    const started = Date.now();
    const result = runEntrypoint({});

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("Chromium exited before exposing CDP");
    expect(Date.now() - started).toBeLessThan(8_000);
  });
});
