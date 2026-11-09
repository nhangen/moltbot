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

import { ensureSandboxBrowser, resolveSandboxBrowserSeccompProfile } from "./browser.js";
import { SANDBOX_BROWSER_SECURITY_LABEL_VALUE } from "./constants.js";
import type { SandboxConfig } from "./types.js";

type SeccompRule = {
  names: string[];
  action: string;
  args?: unknown[];
  comment?: string;
  includes?: { caps?: string[] };
  excludes?: { caps?: string[] };
};

function makeCfg(seccompProfile?: string) {
  return {
    scope: "shared",
    workspaceAccess: "rw",
    docker: { workdir: "/workspace", tmpfs: [], capDrop: ["ALL"], env: {}, seccompProfile },
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
}

async function createArgs(cfg: SandboxConfig): Promise<string[]> {
  dockerMocks.dockerContainerState.mockResolvedValue({ exists: false, running: false });
  dockerMocks.execDocker.mockImplementation(async (args: string[]) =>
    args.includes("--format")
      ? { stdout: `${SANDBOX_BROWSER_SECURITY_LABEL_VALUE}\n`, stderr: "", code: 0 }
      : { stdout: "", stderr: "", code: 0 },
  );
  await expect(
    ensureSandboxBrowser({ scopeKey: "s", workspaceDir: "/w", agentWorkspaceDir: "/w", cfg }),
  ).rejects.toThrowError(/CDP port mapping/);
  const call = dockerMocks.execDocker.mock.calls.find(([args]) => args[0] === "create");
  return call?.[0] ?? [];
}

const seccompOpts = (args: string[]) =>
  args.filter((arg, i) => args[i - 1] === "--security-opt" && arg.startsWith("seccomp="));

describe("sandbox browser seccomp profile", () => {
  beforeEach(() => {
    dockerMocks.execDocker.mockReset();
    dockerMocks.dockerContainerState.mockReset();
  });

  it("applies the bundled Chromium profile when none is configured", async () => {
    const args = await createArgs(makeCfg());
    expect(seccompOpts(args)).toEqual([`seccomp=${resolveSandboxBrowserSeccompProfile()}`]);
    expect(args).toContain("no-new-privileges");
    expect(args.join(" ")).toContain("--cap-drop ALL");
  });

  it("keeps an explicitly configured profile", async () => {
    const args = await createArgs(makeCfg("/etc/moltbot/custom.json"));
    expect(seccompOpts(args)).toEqual(["seccomp=/etc/moltbot/custom.json"]);
  });

  it("is Docker's default profile plus only the namespace-sandbox syscalls", () => {
    const profile = JSON.parse(fs.readFileSync(resolveSandboxBrowserSeccompProfile(), "utf8")) as {
      defaultAction: string;
      syscalls: SeccompRule[];
    };
    expect(profile.defaultAction).toBe("SCMP_ACT_ERRNO");
    const unconditional = profile.syscalls.filter(
      (rule) =>
        rule.action === "SCMP_ACT_ALLOW" && !rule.args && !rule.includes?.caps && !rule.excludes,
    );
    const widened = unconditional.filter((rule) =>
      rule.names.some((name) =>
        ["chroot", "clone", "clone3", "unshare", "setns", "mount", "pivot_root"].includes(name),
      ),
    );
    expect(widened.map((rule) => rule.names)).toEqual([["chroot"]]);

    const CLONE_NEWNS = 0x00020000;
    const CLONE_NEWCGROUP = 0x02000000;
    const CLONE_NEWUTS = 0x04000000;
    const CLONE_NEWIPC = 0x08000000;
    const namespaceRules = profile.syscalls.filter(
      (rule) =>
        rule.comment?.startsWith("Chromium namespace sandbox: allow only") &&
        rule.names.some((name) => name === "clone" || name === "unshare"),
    );
    expect(namespaceRules.flatMap((rule) => rule.names).sort()).toEqual([
      "clone",
      "clone",
      "unshare",
      "unshare",
    ]);
    for (const rule of namespaceRules) {
      expect(rule.args).toEqual([
        {
          index: expect.any(Number),
          value: CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS | CLONE_NEWIPC,
          valueTwo: 0,
          op: "SCMP_CMP_MASKED_EQ",
        },
      ]);
    }
    expect(
      profile.syscalls.find((rule) => rule.names.length === 1 && rule.names[0] === "clone3")
        ?.action,
    ).toBe("SCMP_ACT_ERRNO");
  });
});
