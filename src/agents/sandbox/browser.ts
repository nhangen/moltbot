import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { startBrowserBridgeServer, stopBrowserBridgeServer } from "../../browser/bridge-server.js";
import { type ResolvedBrowserConfig, resolveProfile } from "../../browser/config.js";
import {
  DEFAULT_BROWSER_EVALUATE_ENABLED,
  DEFAULT_CLAWD_BROWSER_COLOR,
} from "../../browser/constants.js";
import { BROWSER_BRIDGES } from "./browser-bridges.js";
import {
  DEFAULT_SANDBOX_BROWSER_IMAGE,
  SANDBOX_AGENT_WORKSPACE_MOUNT,
  SANDBOX_BROWSER_SECURITY_LABEL,
  SANDBOX_BROWSER_SECURITY_LABEL_VALUE,
} from "./constants.js";
import {
  buildSandboxCreateArgs,
  dockerContainerState,
  execDocker,
  readDockerPort,
} from "./docker.js";
import { updateBrowserRegistry } from "./registry.js";
import { slugifySessionKey } from "./shared.js";
import { isToolAllowed } from "./tool-policy.js";
import type { SandboxBrowserContext, SandboxConfig } from "./types.js";

async function waitForSandboxCdp(params: { cdpPort: number; timeoutMs: number }): Promise<boolean> {
  const deadline = Date.now() + Math.max(0, params.timeoutMs);
  const url = `http://127.0.0.1:${params.cdpPort}/json/version`;
  while (Date.now() < deadline) {
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 1000);
      try {
        const res = await fetch(url, { signal: ctrl.signal });
        if (res.ok) return true;
      } finally {
        clearTimeout(t);
      }
    } catch {
      // ignore
    }
    await new Promise((r) => setTimeout(r, 150));
  }
  return false;
}

function buildSandboxBrowserResolvedConfig(params: {
  controlPort: number;
  cdpPort: number;
  headless: boolean;
  evaluateEnabled: boolean;
}): ResolvedBrowserConfig {
  const cdpHost = "127.0.0.1";
  return {
    enabled: true,
    evaluateEnabled: params.evaluateEnabled,
    controlPort: params.controlPort,
    cdpProtocol: "http",
    cdpHost,
    cdpIsLoopback: true,
    remoteCdpTimeoutMs: 1500,
    remoteCdpHandshakeTimeoutMs: 3000,
    color: DEFAULT_CLAWD_BROWSER_COLOR,
    executablePath: undefined,
    headless: params.headless,
    noSandbox: false,
    attachOnly: true,
    defaultProfile: "clawd",
    profiles: {
      clawd: { cdpPort: params.cdpPort, color: DEFAULT_CLAWD_BROWSER_COLOR },
    },
  };
}

// Docker's default profile denies the user-namespace clone/unshare and chroot calls that
// Chromium's namespace sandbox needs under --cap-drop ALL, so Chromium aborts with
// "No usable sandbox". The bundled profile is that default plus those three syscalls.
export function resolveSandboxBrowserSeccompProfile(): string {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const profile = path.resolve(here, "../../../assets/sandbox-browser-seccomp.json");
  if (!fs.existsSync(profile)) {
    throw new Error(
      `Sandbox browser seccomp profile not found at ${profile}; the Chromium sandbox cannot start without it.`,
    );
  }
  return profile;
}

const SECURITY_LABEL_FORMAT = `{{ index .Config.Labels "${SANDBOX_BROWSER_SECURITY_LABEL}" }}`;

async function readSecurityLabel(inspectArgs: string[]): Promise<string | null> {
  const result = await execDocker([...inspectArgs, "--format", SECURITY_LABEL_FORMAT], {
    allowFailure: true,
  });
  if (result.code !== 0) return null;
  return result.stdout.trim();
}

async function ensureSandboxBrowserImage(image: string) {
  const label = await readSecurityLabel(["image", "inspect", image]);
  if (label === null) {
    throw new Error(
      `Sandbox browser image not found: ${image}. Build it with scripts/sandbox-browser-setup.sh.`,
    );
  }
  if (label !== SANDBOX_BROWSER_SECURITY_LABEL_VALUE) {
    throw new Error(
      `Sandbox browser image ${image} predates the sandboxed Chromium entrypoint (missing ${SANDBOX_BROWSER_SECURITY_LABEL}=${SANDBOX_BROWSER_SECURITY_LABEL_VALUE}). Rebuild it with scripts/sandbox-browser-setup.sh.`,
    );
  }
}

async function ensureSandboxBrowserContainerLabel(containerName: string) {
  const label = await readSecurityLabel(["container", "inspect", containerName]);
  if (label === SANDBOX_BROWSER_SECURITY_LABEL_VALUE) return;
  throw new Error(
    `Sandbox browser container ${containerName} was created from an image without ${SANDBOX_BROWSER_SECURITY_LABEL}=${SANDBOX_BROWSER_SECURITY_LABEL_VALUE}. Remove it (docker rm -f ${containerName}) and rebuild the image with scripts/sandbox-browser-setup.sh.`,
  );
}

export async function ensureSandboxBrowser(params: {
  scopeKey: string;
  workspaceDir: string;
  agentWorkspaceDir: string;
  cfg: SandboxConfig;
  evaluateEnabled?: boolean;
}): Promise<SandboxBrowserContext | null> {
  if (!params.cfg.browser.enabled) return null;
  if (!isToolAllowed(params.cfg.tools, "browser")) return null;

  const slug = params.cfg.scope === "shared" ? "shared" : slugifySessionKey(params.scopeKey);
  const name = `${params.cfg.browser.containerPrefix}${slug}`;
  const containerName = name.slice(0, 63);
  const state = await dockerContainerState(containerName);
  if (!state.exists) {
    await ensureSandboxBrowserImage(params.cfg.browser.image ?? DEFAULT_SANDBOX_BROWSER_IMAGE);
    const args = buildSandboxCreateArgs({
      name: containerName,
      cfg: {
        ...params.cfg.docker,
        seccompProfile: params.cfg.docker.seccompProfile ?? resolveSandboxBrowserSeccompProfile(),
      },
      scopeKey: params.scopeKey,
      labels: { "moltbot.sandboxBrowser": "1" },
    });
    const mainMountSuffix =
      params.cfg.workspaceAccess === "ro" && params.workspaceDir === params.agentWorkspaceDir
        ? ":ro"
        : "";
    args.push("-v", `${params.workspaceDir}:${params.cfg.docker.workdir}${mainMountSuffix}`);
    if (params.cfg.workspaceAccess !== "none" && params.workspaceDir !== params.agentWorkspaceDir) {
      const agentMountSuffix = params.cfg.workspaceAccess === "ro" ? ":ro" : "";
      args.push(
        "-v",
        `${params.agentWorkspaceDir}:${SANDBOX_AGENT_WORKSPACE_MOUNT}${agentMountSuffix}`,
      );
    }
    args.push("-p", `127.0.0.1::${params.cfg.browser.cdpPort}`);
    if (params.cfg.browser.enableNoVnc && !params.cfg.browser.headless) {
      args.push("-p", `127.0.0.1::${params.cfg.browser.noVncPort}`);
    }
    args.push("-e", `CLAWDBOT_BROWSER_HEADLESS=${params.cfg.browser.headless ? "1" : "0"}`);
    args.push("-e", `CLAWDBOT_BROWSER_ENABLE_NOVNC=${params.cfg.browser.enableNoVnc ? "1" : "0"}`);
    args.push("-e", `CLAWDBOT_BROWSER_CDP_PORT=${params.cfg.browser.cdpPort}`);
    args.push("-e", `CLAWDBOT_BROWSER_VNC_PORT=${params.cfg.browser.vncPort}`);
    args.push("-e", `CLAWDBOT_BROWSER_NOVNC_PORT=${params.cfg.browser.noVncPort}`);
    args.push(params.cfg.browser.image);
    await execDocker(args);
    await execDocker(["start", containerName]);
  } else {
    await ensureSandboxBrowserContainerLabel(containerName);
    if (!state.running) {
      await execDocker(["start", containerName]);
    }
  }

  const mappedCdp = await readDockerPort(containerName, params.cfg.browser.cdpPort);
  if (!mappedCdp) {
    throw new Error(`Failed to resolve CDP port mapping for ${containerName}.`);
  }

  const mappedNoVnc =
    params.cfg.browser.enableNoVnc && !params.cfg.browser.headless
      ? await readDockerPort(containerName, params.cfg.browser.noVncPort)
      : null;

  const existing = BROWSER_BRIDGES.get(params.scopeKey);
  const existingProfile = existing ? resolveProfile(existing.bridge.state.resolved, "clawd") : null;
  const shouldReuse =
    existing && existing.containerName === containerName && existingProfile?.cdpPort === mappedCdp;
  if (existing && !shouldReuse) {
    await stopBrowserBridgeServer(existing.bridge.server).catch(() => undefined);
    BROWSER_BRIDGES.delete(params.scopeKey);
  }

  const bridge = (() => {
    if (shouldReuse && existing) return existing.bridge;
    return null;
  })();

  const ensureBridge = async () => {
    if (bridge) return bridge;

    const onEnsureAttachTarget = params.cfg.browser.autoStart
      ? async () => {
          const state = await dockerContainerState(containerName);
          if (state.exists && !state.running) {
            await execDocker(["start", containerName]);
          }
          const ok = await waitForSandboxCdp({
            cdpPort: mappedCdp,
            timeoutMs: params.cfg.browser.autoStartTimeoutMs,
          });
          if (!ok) {
            throw new Error(
              `Sandbox browser CDP did not become reachable on 127.0.0.1:${mappedCdp} within ${params.cfg.browser.autoStartTimeoutMs}ms.`,
            );
          }
        }
      : undefined;

    return await startBrowserBridgeServer({
      resolved: buildSandboxBrowserResolvedConfig({
        controlPort: 0,
        cdpPort: mappedCdp,
        headless: params.cfg.browser.headless,
        evaluateEnabled: params.evaluateEnabled ?? DEFAULT_BROWSER_EVALUATE_ENABLED,
      }),
      onEnsureAttachTarget,
    });
  };

  const resolvedBridge = await ensureBridge();
  if (!shouldReuse) {
    BROWSER_BRIDGES.set(params.scopeKey, {
      bridge: resolvedBridge,
      containerName,
    });
  }

  const now = Date.now();
  await updateBrowserRegistry({
    containerName,
    sessionKey: params.scopeKey,
    createdAtMs: now,
    lastUsedAtMs: now,
    image: params.cfg.browser.image,
    cdpPort: mappedCdp,
    noVncPort: mappedNoVnc ?? undefined,
  });

  const noVncUrl =
    mappedNoVnc && params.cfg.browser.enableNoVnc && !params.cfg.browser.headless
      ? `http://127.0.0.1:${mappedNoVnc}/vnc.html?autoconnect=1&resize=remote`
      : undefined;

  return {
    bridgeUrl: resolvedBridge.baseUrl,
    noVncUrl,
    containerName,
  };
}
