#!/usr/bin/env bash
# End-to-end test of the desktop app (real Tauri binary + bundled server) against the test Dovecot.
# Prereqs: docker compose --profile test up -d ; docker compose build malo (remote mode uses that image)
#          npx tauri build --debug --no-bundle ; cargo install tauri-driver
set -euo pipefail
cd "$(dirname "$0")/.."
rm -rf e2e/out && mkdir -p e2e/out
docker build -q -t malo-e2e e2e >/dev/null
# Remote mode runs against the real Docker image.
docker rm -fv malo-e2e-remote >/dev/null 2>&1 || true
docker run -d --name malo-e2e-remote -p 18443:8443 -e MALO_INSECURE_FAST_KDF=1 malo-server:latest >/dev/null
trap 'docker logs malo-e2e-remote 2>&1 | tail -15 > e2e/out/remote-server.log; docker rm -fv malo-e2e-remote >/dev/null 2>&1 || true' EXIT
for _ in $(seq 1 30); do docker logs malo-e2e-remote 2>&1 | grep -q "setup token" && break; sleep 0.5; done
REMOTE_TOKEN=$(docker logs malo-e2e-remote 2>&1 | sed -n 's/.*setup token \([0-9a-f]*\).*/\1/p' | head -1)
REMOTE_FP=$(docker logs malo-e2e-remote 2>&1 | sed -n 's/.*"fingerprint":"\([0-9A-F:]*\)".*/\1/p' | head -1)
# When the test asks, the remote server starts over with a new certificate (same address).
(
  while [ ! -f e2e/out/rotate-remote ]; do sleep 0.5; done
  docker rm -fv malo-e2e-remote >/dev/null 2>&1
  docker run -d --name malo-e2e-remote -p 18443:8443 -e MALO_INSECURE_FAST_KDF=1 malo-server:latest >/dev/null
  for _ in $(seq 1 30); do docker logs malo-e2e-remote 2>&1 | grep -q "setup token" && break; sleep 0.5; done
  touch e2e/out/remote-rotated
) &
docker run --rm --network host \
  -v "$PWD/target/debug:/app:ro" \
  -v "$HOME/.cargo/bin/tauri-driver:/usr/local/bin/tauri-driver:ro" \
  -v "$PWD/e2e:/work:ro" \
  -e MALO_INSECURE_FAST_KDF=1 \
  -v "$PWD/e2e/out:/tmp/saved" \
  -e MALO_AUTOSAVE_DIR=/tmp/saved \
  -e MALO_AUTOPICK_FILE=/tmp/saved/malo-recovery-kit-owner.json \
  -e MALO_E2E_OAUTH_USER="gui-oauth-$(date +%s%N)" \
  -e MALO_REMOTE_URL=https://127.0.0.1:18443 \
  -e MALO_REMOTE_TOKEN="$REMOTE_TOKEN" \
  -e MALO_REMOTE_FP="$REMOTE_FP" \
  malo-e2e bash -c '
    mkdir -p /tmp/saved
    Xvfb :99 -screen 0 1400x900x24 >/tmp/xvfb.log 2>&1 &
    export DISPLAY=:99
    sleep 1
    dbus-launch --exit-with-session bash -c "tauri-driver --port 4444 >/tmp/driver.log 2>&1 & sleep 2; python3 -u /work/test_gui.py; rc=\$?; [ \$rc -ne 0 ] && tail -40 /tmp/driver.log; exit \$rc"
  '
