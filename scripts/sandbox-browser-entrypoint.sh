#!/usr/bin/env bash
set -euo pipefail

export DISPLAY=:1
export HOME="${HOME:-/tmp/moltbot-home}"
export XDG_CONFIG_HOME="${HOME}/.config"
export XDG_CACHE_HOME="${HOME}/.cache"

CDP_PORT="${CLAWDBOT_BROWSER_CDP_PORT:-9222}"
VNC_PORT="${CLAWDBOT_BROWSER_VNC_PORT:-5900}"
NOVNC_PORT="${CLAWDBOT_BROWSER_NOVNC_PORT:-6080}"
ENABLE_NOVNC="${CLAWDBOT_BROWSER_ENABLE_NOVNC:-1}"
HEADLESS="${CLAWDBOT_BROWSER_HEADLESS:-0}"

if [[ -n "${CLAWDBOT_BROWSER_NO_SANDBOX:-}" && "${CLAWDBOT_BROWSER_NO_SANDBOX}" != "0" ]]; then
  echo "ERROR: CLAWDBOT_BROWSER_NO_SANDBOX is not supported: the Chromium sandbox cannot be disabled. Refusing to start." >&2
  exit 1
fi

mkdir -p "${HOME}" "${HOME}/.chrome" "${XDG_CONFIG_HOME}" "${XDG_CACHE_HOME}"

# Enforce minimum security baseline: Chrome CNA records 118306/118331/118348/118344 (156.0.8078.73+)
MIN_CHROMIUM_SECURITY_VERSION="156.0.8078.73"
CHROME_VERSION_RAW="$(chromium --version 2>/dev/null || true)"
echo "Sandbox browser binary version: ${CHROME_VERSION_RAW}"

CHROME_VER_NUM="$(echo "${CHROME_VERSION_RAW}" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || true)"
if [[ -z "${CHROME_VER_NUM}" ]]; then
  echo "ERROR: Unable to detect Chromium version from '${CHROME_VERSION_RAW}'. Refusing to start." >&2
  exit 1
fi

IFS='.' read -r v1 v2 v3 v4 <<< "${CHROME_VER_NUM}"
IFS='.' read -r m1 m2 m3 m4 <<< "${MIN_CHROMIUM_SECURITY_VERSION}"
if (( v1 < m1 || (v1 == m1 && (v2 < m2 || (v2 == m2 && (v3 < m3 || (v3 == m3 && v4 < m4))))))); then
  echo "ERROR: Sandbox Chromium version ${CHROME_VER_NUM} is below security baseline ${MIN_CHROMIUM_SECURITY_VERSION} (Chrome CNA records 118306/118331/118348/118344)." >&2
  exit 1
fi

Xvfb :1 -screen 0 1280x800x24 -ac -nolisten tcp &

if [[ "${HEADLESS}" == "1" ]]; then
  CHROME_ARGS=(
    "--headless=new"
    "--disable-gpu"
  )
else
  CHROME_ARGS=()
fi

if [[ "${CDP_PORT}" -ge 65535 ]]; then
  CHROME_CDP_PORT="$((CDP_PORT - 1))"
else
  CHROME_CDP_PORT="$((CDP_PORT + 1))"
fi

CHROME_ARGS+=(
  "--remote-debugging-address=127.0.0.1"
  "--remote-debugging-port=${CHROME_CDP_PORT}"
  "--user-data-dir=${HOME}/.chrome"
  "--no-first-run"
  "--no-default-browser-check"
  "--disable-dev-shm-usage"
  "--disable-background-networking"
  "--disable-features=TranslateUI"
  "--disable-breakpad"
  "--disable-crash-reporter"
  "--metrics-recording-only"
)

chromium "${CHROME_ARGS[@]}" about:blank &
CHROMIUM_PID=$!

CDP_READY=0
for _ in $(seq 1 100); do
  if curl -s --max-time 1 "http://127.0.0.1:${CHROME_CDP_PORT}/json/version" >/dev/null 2>&1; then
    CDP_READY=1
    break
  fi
  if ! kill -0 "${CHROMIUM_PID}" 2>/dev/null; then
    echo "ERROR: Chromium exited before exposing CDP. If the log above says 'No usable sandbox', run the container with the bundled seccomp profile (assets/sandbox-browser-seccomp.json); do not disable the sandbox." >&2
    exit 1
  fi
  sleep 0.1
done
if [[ "${CDP_READY}" != "1" ]]; then
  echo "ERROR: Chromium did not expose CDP on port ${CHROME_CDP_PORT} within 10 seconds." >&2
  exit 1
fi

socat \
  TCP-LISTEN:"${CDP_PORT}",fork,reuseaddr,bind=0.0.0.0 \
  TCP:127.0.0.1:"${CHROME_CDP_PORT}" &

if [[ "${ENABLE_NOVNC}" == "1" && "${HEADLESS}" != "1" ]]; then
  x11vnc -display :1 -rfbport "${VNC_PORT}" -shared -forever -nopw -localhost &
  websockify --web /usr/share/novnc/ "${NOVNC_PORT}" "localhost:${VNC_PORT}" &
fi

wait -n
