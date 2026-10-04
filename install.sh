#!/usr/bin/env bash
# install.sh [--client-only] [--config FILE]
#   default        broker Mac: install bws-touchid + links, create the Secure Enclave identity,
#                  load the broker as a launchd user agent (gui/<uid>, so Touch ID can prompt)
#   --client-only  a Mac you ssh into from the broker Mac: just the bws-save / bws-gated clients
set -euo pipefail
cd "$(dirname "$0")"
CLIENT=0; CONFIG=""
while [ $# -gt 0 ]; do
  case "$1" in
    --client-only) CLIENT=1; shift ;;
    --config) CONFIG="${2:?}"; shift 2 ;;
    *) echo "unknown arg $1" >&2; exit 2 ;;
  esac
done
BIN="${PREFIX:-$HOME/.local/bin}"
CONF="$HOME/.config/bws-touchid"
mkdir -p "$BIN" "$CONF" "$HOME/.bws-broker"
chmod 700 "$CONF" "$HOME/.bws-broker"
install -m 755 bws-touchid "$BIN/bws-touchid.new" && mv -f "$BIN/bws-touchid.new" "$BIN/bws-touchid"
ln -sf bws-touchid "$BIN/bws-save"
ln -sf bws-touchid "$BIN/bws-gated"
[ -z "$CONFIG" ] || install -m 600 "$CONFIG" "$CONF/config.json"
echo "installed $BIN/bws-touchid (+ bws-save, bws-gated)"
[ "$CLIENT" -eq 1 ] && exit 0

for t in age age-plugin-se bws; do
  command -v "$t" >/dev/null 2>&1 || [ -x "$HOME/.local/bin/$t" ] || [ -x "/opt/homebrew/bin/$t" ] \
    || { echo "missing $t (brew install age age-plugin-se bws)" >&2; exit 1; }
done
PATH="/opt/homebrew/bin:/usr/local/bin:$PATH" "$BIN/bws-touchid" init
LABEL="${BWS_TOUCHID_LABEL:-bws-touchid.broker}"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
mkdir -p "$HOME/Library/LaunchAgents" "$HOME/Library/Logs"
cat > "$PLIST" <<XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key><array>
    <string>/usr/bin/python3</string><string>$BIN/bws-touchid</string><string>serve</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>LimitLoadToSessionType</key><string>Aqua</string>
  <key>ProcessType</key><string>Interactive</string>
  <key>StandardErrorPath</key><string>$HOME/Library/Logs/bws-touchid.err.log</string>
</dict></plist>
XML
uid="$(id -u)"
launchctl bootout "gui/$uid/$LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$uid" "$PLIST"
sleep 1
"$BIN/bws-touchid" status
