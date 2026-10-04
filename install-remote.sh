#!/usr/bin/env bash
# install-remote.sh HOST [--sshd-unlink | --reaper] [--config FILE]
# Run on the broker Mac. Installs the bws-save / bws-gated clients on HOST (a Mac you ssh into
# from here) and makes ~/.bws-broker/fwd.sock on HOST bindable by each new ssh session:
#   --sshd-unlink  HOST has passwordless sudo: StreamLocalBindUnlink yes in sshd_config.d
#   --reaper       no sudo: a LaunchAgent deletes a dead fwd.sock every 5 s (sshd will not bind
#                  over the stale socket the previous session left behind)
# Then add to THIS Mac's ~/.ssh/config, under that Host only:
#   RemoteForward <HOST $HOME>/.bws-broker/fwd.sock <this $HOME>/.bws-broker/broker.sock
# Or list HOST under "tunnels" in the broker config and run `bws-touchid tunnel install` (persistent;
# then do not also add the RemoteForward). Avoid RemoteForward on hosts used by other long-lived
# tunnels with ExitOnForwardFailure=yes.
set -euo pipefail
cd "$(dirname "$0")"
HOST="${1:?usage: install-remote.sh HOST [--sshd-unlink|--reaper] [--config FILE]}"; shift
MODE=""; CONFIG=""
while [ $# -gt 0 ]; do
  case "$1" in
    --sshd-unlink|--reaper) MODE="$1"; shift ;;
    --config) CONFIG="${2:?}"; shift 2 ;;
    *) echo "unknown arg $1" >&2; exit 2 ;;
  esac
done
S=(ssh -o BatchMode=yes -o ClearAllForwardings=yes "$HOST")
"${S[@]}" 'mkdir -p ~/.local/bin ~/.config/bws-touchid ~/.bws-broker && chmod 700 ~/.config/bws-touchid ~/.bws-broker'
scp -q -o ClearAllForwardings=yes bws-touchid "$HOST:.local/bin/bws-touchid.new"
[ -z "$CONFIG" ] || scp -q -o ClearAllForwardings=yes "$CONFIG" "$HOST:.config/bws-touchid/config.json"
"${S[@]}" 'cd ~/.local/bin && chmod 755 bws-touchid.new && mv -f bws-touchid.new bws-touchid && ln -sf bws-touchid bws-save \
  && ln -sf bws-touchid bws-gated && { chmod 600 ~/.config/bws-touchid/config.json 2>/dev/null || true; } && echo "clients installed on $(hostname -s)"'
case "$MODE" in
  --sshd-unlink)
    "${S[@]}" 'printf "# bws-touchid: a new ssh session may replace a stale forwarded unix socket\nStreamLocalBindUnlink yes\n" \
      | sudo tee /etc/ssh/sshd_config.d/010-bws-touchid.conf >/dev/null && sudo sshd -t && echo "sshd: StreamLocalBindUnlink yes"' ;;
  --reaper)
    "${S[@]}" 'L=bws-touchid.fwd-reaper; P=~/Library/LaunchAgents/$L.plist; mkdir -p ~/Library/LaunchAgents
cat > "$P" <<XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$L</string>
  <key>ProgramArguments</key><array><string>/usr/bin/python3</string><string>$HOME/.local/bin/bws-touchid</string><string>reap</string></array>
  <key>StartInterval</key><integer>5</integer>
  <key>RunAtLoad</key><true/>
</dict></plist>
XML
launchctl bootout gui/$(id -u)/$L 2>/dev/null || true; launchctl bootstrap gui/$(id -u) "$P" && echo "reaper loaded"' ;;
esac
