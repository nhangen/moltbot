import fs from "node:fs";
import { beforeEach, describe, expect, it, vi } from "vitest";

const dockerMocks = vi.hoisted(() => ({
  execDocker: vi.fn(),
  dockerContainerState: vi.fn(),
  readDockerPort: vi.fn(async () => null),
}));

vi.mock("./docker.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./docker.js")>();
  return { ...actual, ...dockerMocks };
});

import { ensureSandboxBrowser } from "./browser.js";
import {
  SANDBOX_BROWSER_SECURITY_LABEL,
  SANDBOX_BROWSER_SECURITY_LABEL_VALUE,
} from "./constants.js";
import type { SandboxConfig } from "./types.js";

const cfg = {
  scope: "shared",
  workspaceAccess: "rw",
  docker: { workdir: "/workspace", tmpfs: [], capDrop: ["ALL"], env: {} },
  browser: {
    enabled: true,
    image: "moltbot-sandbox-browser:test",
    containerPrefix: "moltbot-sbx-browser-",
    cdpPort: 9222,
    vncPort: 5900,
    noVncPort: 6080,
    headless: true,
    enableNoVnc: false,
  },
  tools: { allow: ["browser"] },
} as unknown as SandboxConfig;

const params = { scopeKey: "s", workspaceDir: "/w", agentWorkspaceDir: "/w", cfg };

function labelResponder(label: string | null) {
  dockerMocks.execDocker.mockImplementation(async (args: string[]) => {
    if (args.includes("--format") && (args[0] === "image" || args[0] === "container")) {
      return label === null
        ? { stdout: "", stderr: "No such object", code: 1 }
        : { stdout: `${label}\n`, stderr: "", code: 0 };
    }
    return { stdout: "", stderr: "", code: 0 };
  });
}

const created = () => dockerMocks.execDocker.mock.calls.some(([args]) => args[0] === "create");
const started = () => dockerMocks.execDocker.mock.calls.some(([args]) => args[0] === "start");

describe("sandbox browser image security label", () => {
  beforeEach(() => {
    dockerMocks.execDocker.mockReset();
    dockerMocks.dockerContainerState.mockReset();
  });

  it.each([
    ["an unlabeled image", "<no value>"],
    ["an older label", "legacy"],
  ])("refuses to create a container from %s", async (_label, value) => {
    dockerMocks.dockerContainerState.mockResolvedValue({ exists: false, running: false });
    labelResponder(value);
    await expect(ensureSandboxBrowser(params)).rejects.toThrowError(/predates the sandboxed/);
    expect(created()).toBe(false);
  });

  it("refuses to start an existing container created from an unlabeled image", async () => {
    dockerMocks.dockerContainerState.mockResolvedValue({ exists: true, running: false });
    labelResponder("<no value>");
    await expect(ensureSandboxBrowser(params)).rejects.toThrowError(/docker rm -f/);
    expect(started()).toBe(false);
  });

  it("proceeds past the label check for a labeled image", async () => {
    dockerMocks.dockerContainerState.mockResolvedValue({ exists: false, running: false });
    labelResponder(SANDBOX_BROWSER_SECURITY_LABEL_VALUE);
    await expect(ensureSandboxBrowser(params)).rejects.toThrowError(/CDP port mapping/);
    expect(created()).toBe(true);
  });

  it("matches the label baked into Dockerfile.sandbox-browser", () => {
    const dockerfile = fs.readFileSync("Dockerfile.sandbox-browser", "utf8");
    const match = dockerfile.match(/^LABEL\s+([\w.-]+)="([^"]+)"\s*$/m);
    expect(match?.[1]).toBe(SANDBOX_BROWSER_SECURITY_LABEL);
    expect(match?.[2]).toBe(SANDBOX_BROWSER_SECURITY_LABEL_VALUE);
  });
});
