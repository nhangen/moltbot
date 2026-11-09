import { execFileSync } from "node:child_process";
import fs from "node:fs";
import { playwright } from "@vitest/browser-playwright";
import { defineConfig } from "vitest/config";
import {
  CHROMIUM_SECURITY_CNA_RECORDS,
  MIN_CHROMIUM_SECURITY_VERSION,
  isChromiumVersionAtLeast,
  parseChromiumProductVersion,
} from "../src/browser/chromium-version";

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
    const ver = parseChromiumProductVersion(out)?.join(".");
    if (!ver || !isChromiumVersionAtLeast(ver)) {
      throw new Error(
        `MOLTBOT_BROWSER_EXECUTABLE (${customExe}) version ${ver ?? "unproven (--version must name Chrome or Chromium)"} does not meet security baseline ${MIN_CHROMIUM_SECURITY_VERSION}`,
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
      const ver = parseChromiumProductVersion(out)?.join(".");
      if (ver && isChromiumVersionAtLeast(ver)) {
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
      const ver = parseChromiumProductVersion(out)?.join(".");
      if (ver && isChromiumVersionAtLeast(ver)) {
        return { channel: "chrome", executablePath: linuxChrome, version: ver };
      }
    } catch {
      // ignore
    }
  }

  throw new Error(
    `No secure browser found meeting baseline ${MIN_CHROMIUM_SECURITY_VERSION} (Chrome CNA records ${CHROMIUM_SECURITY_CNA_RECORDS.join("/")}). ` +
      `Playwright bundled Chromium (rev 1208 / 145.0) is unpatched and fallback is disabled. ` +
      `Install Google Chrome >= ${MIN_CHROMIUM_SECURITY_VERSION} or set MOLTBOT_BROWSER_EXECUTABLE.`,
  );
}

const secureBrowser = resolveSecureBrowser();
console.log(
  `[UI vitest] Selected browser proving the version baseline at "${secureBrowser.executablePath ?? secureBrowser.channel}" (version ${secureBrowser.version}) with chromiumSandbox=true`,
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
