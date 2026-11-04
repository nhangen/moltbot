import { execFileSync } from "node:child_process";
import fs from "node:fs";
import { playwright } from "@vitest/browser-playwright";
import { defineConfig } from "vitest/config";

const MIN_CHROMIUM_SECURITY_VERSION = "156.0.8078.73";

function parseChromiumVersion(raw: string): number[] | null {
  const match = raw.match(/(\d+)\.(\d+)\.(\d+)\.(\d+)/);
  if (!match) return null;
  return [
    Number.parseInt(match[1], 10),
    Number.parseInt(match[2], 10),
    Number.parseInt(match[3], 10),
    Number.parseInt(match[4], 10),
  ];
}

function isVersionSecure(versionStr: string): boolean {
  const v = parseChromiumVersion(versionStr);
  const min = parseChromiumVersion(MIN_CHROMIUM_SECURITY_VERSION);
  if (!v || !min) return false;
  for (let i = 0; i < 4; i += 1) {
    if (v[i] > min[i]) return true;
    if (v[i] < min[i]) return false;
  }
  return true;
}

function resolveSecureBrowser(): { channel?: string; executablePath?: string; version: string } {
  // 1. Explicit env var
  const customExe = process.env.MOLTBOT_BROWSER_EXECUTABLE;
  if (customExe) {
    if (!fs.existsSync(customExe)) {
      throw new Error(`MOLTBOT_BROWSER_EXECUTABLE not found: ${customExe}`);
    }
    const out = execFileSync(customExe, ["--version"], {
      encoding: "utf8",
      timeout: 3000,
      stdio: ["pipe", "pipe", "ignore"],
    });
    const match = out.match(/(\d+\.\d+\.\d+\.\d+)/);
    const ver = match?.[1];
    if (!ver || !isVersionSecure(ver)) {
      throw new Error(
        `MOLTBOT_BROWSER_EXECUTABLE (${customExe}) version ${ver ?? "unknown"} is below security baseline ${MIN_CHROMIUM_SECURITY_VERSION}`,
      );
    }
    return { executablePath: customExe, version: ver };
  }

  // 2. Installed Google Chrome on macOS
  const macChrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
  if (process.platform === "darwin" && fs.existsSync(macChrome)) {
    try {
      const out = execFileSync(macChrome, ["--version"], {
        encoding: "utf8",
        timeout: 3000,
        stdio: ["pipe", "pipe", "ignore"],
      });
      const match = out.match(/(\d+\.\d+\.\d+\.\d+)/);
      const ver = match?.[1];
      if (ver && isVersionSecure(ver)) {
        return { channel: "chrome", executablePath: macChrome, version: ver };
      }
    } catch {
      // ignore
    }
  }

  // 3. Installed Google Chrome on Linux
  const linuxChrome = "/usr/bin/google-chrome";
  if (process.platform === "linux" && fs.existsSync(linuxChrome)) {
    try {
      const out = execFileSync(linuxChrome, ["--version"], {
        encoding: "utf8",
        timeout: 3000,
        stdio: ["pipe", "pipe", "ignore"],
      });
      const match = out.match(/(\d+\.\d+\.\d+\.\d+)/);
      const ver = match?.[1];
      if (ver && isVersionSecure(ver)) {
        return { channel: "chrome", executablePath: linuxChrome, version: ver };
      }
    } catch {
      // ignore
    }
  }

  throw new Error(
    `No secure browser found meeting baseline ${MIN_CHROMIUM_SECURITY_VERSION} (CVE-2026-118306). ` +
      `Playwright bundled Chromium (rev 1208 / 145.0) is unpatched and fallback is disabled. ` +
      `Install Google Chrome >= 156.0.8078.73 or set MOLTBOT_BROWSER_EXECUTABLE.`,
  );
}

const secureBrowser = resolveSecureBrowser();
console.log(
  `[UI vitest] Selected verified secure browser at "${secureBrowser.executablePath ?? secureBrowser.channel}" (version ${secureBrowser.version}) with chromiumSandbox=true`,
);

export default defineConfig({
  test: {
    include: ["src/**/*.test.ts"],
    browser: {
      enabled: true,
      provider: playwright({
        launchOptions: {
          ...(secureBrowser.executablePath ? { executablePath: secureBrowser.executablePath } : {}),
          ...(secureBrowser.channel ? { channel: secureBrowser.channel } : {}),
          chromiumSandbox: true,
        },
      }),
      instances: [{ browser: "chromium", name: "chromium" }],
      headless: true,
      ui: false,
    },
  },
});
