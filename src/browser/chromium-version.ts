// Dependency-free so ui/vitest.config.ts can share the runtime baseline and parsers.

export const MIN_CHROMIUM_SECURITY_VERSION = "156.0.8078.73";

export const CHROMIUM_SECURITY_CNA_RECORDS = ["118306", "118331", "118348", "118344"] as const;

// `--version` must name a Chromium or Chrome product; a bare quad is how forks
// such as Opera print their own release number.
export function parseChromiumProductVersion(raw: string): [number, number, number, number] | null {
  if (typeof raw !== "string" || /^\s*\d+\.\d+\.\d+\.\d+\s*$/.test(raw)) return null;
  return parseChromiumVersion(raw);
}

export function parseChromiumVersion(raw: string): [number, number, number, number] | null {
  if (!raw || typeof raw !== "string") return null;

  const trimmed = raw.trim();

  const wholeMatch = trimmed.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (wholeMatch) {
    return [
      Number.parseInt(wholeMatch[1], 10),
      Number.parseInt(wholeMatch[2], 10),
      Number.parseInt(wholeMatch[3], 10),
      Number.parseInt(wholeMatch[4], 10),
    ];
  }

  const chromiumMatch = trimmed.match(/\bChromium[:\s/]+(\d+)\.(\d+)\.(\d+)\.(\d+)\b/i);
  if (chromiumMatch) {
    return [
      Number.parseInt(chromiumMatch[1], 10),
      Number.parseInt(chromiumMatch[2], 10),
      Number.parseInt(chromiumMatch[3], 10),
      Number.parseInt(chromiumMatch[4], 10),
    ];
  }

  const chromeMatch = trimmed.match(
    /\b(?:Google Chrome(?:\s+(?:Canary|for Testing))?\s+|(?:Headless)?Chrome\/)(\d+)\.(\d+)\.(\d+)\.(\d+)\b/i,
  );
  if (chromeMatch) {
    return [
      Number.parseInt(chromeMatch[1], 10),
      Number.parseInt(chromeMatch[2], 10),
      Number.parseInt(chromeMatch[3], 10),
      Number.parseInt(chromeMatch[4], 10),
    ];
  }

  return null;
}

export function compareChromiumVersions(a: string, b: string): number {
  const partsA = parseChromiumVersion(a);
  const partsB = parseChromiumVersion(b);
  if (!partsA || !partsB) {
    throw new Error(`Cannot compare invalid Chromium versions: "${a}" and "${b}"`);
  }
  for (let i = 0; i < 4; i += 1) {
    if (partsA[i] > partsB[i]) return 1;
    if (partsA[i] < partsB[i]) return -1;
  }
  return 0;
}

export function isChromiumVersionAtLeast(
  version: string,
  minimum = MIN_CHROMIUM_SECURITY_VERSION,
): boolean {
  try {
    return compareChromiumVersions(version, minimum) >= 0;
  } catch {
    return false;
  }
}
