import fs from "node:fs";
import { describe, expect, it } from "vitest";

import { parseChromiumProductVersion } from "./chromium-version.js";

describe("parseChromiumProductVersion", () => {
  it.each([
    ["Google Chrome 156.0.8078.80", [156, 0, 8078, 80]],
    ["Google Chrome for Testing 156.0.8078.80", [156, 0, 8078, 80]],
    ["Chromium 156.0.8078.80 built on Debian", [156, 0, 8078, 80]],
  ])("accepts %j", (raw, expected) => {
    expect(parseChromiumProductVersion(raw)).toEqual(expected);
  });

  it.each([
    "Brave Browser 156.1.85.118",
    "Microsoft Edge 156.0.3485.54",
    "Vivaldi 7.9.3970.41",
    "127.0.5765.4",
    "",
  ])("refuses %j", (raw) => {
    expect(parseChromiumProductVersion(raw)).toBeNull();
  });
});

// Executing ui/vitest.config.ts launches host Chrome at import time, so this pins
// the resolver to the shared parser statically instead.
describe("ui/vitest.config.ts browser resolver", () => {
  it("parses --version only through the shared product parser", () => {
    const src = fs.readFileSync("ui/vitest.config.ts", "utf8");
    expect(src).toMatch(
      /import \{[^}]*\bparseChromiumProductVersion\b[^}]*\} from "\.\.\/src\/browser\/chromium-version";/,
    );
    expect(src).not.toMatch(/\.match\(\s*\/\(?\\d\+/);
    expect(src).not.toMatch(/\bparseChromiumVersion\(/);
    expect(src).not.toMatch(/\bspawnSync\(|\bexecSync\(|\bspawn\(|\bexec\(/);
    expect(src.match(/execFileSync\(/g)?.length ?? 0).toBe(3);
    expect(src.match(/parseChromiumProductVersion\(out\)/g)?.length ?? 0).toBe(3);
  });
});
