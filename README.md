# bws-touchid

Touch ID on every use of a [Bitwarden Secrets Manager](https://bitwarden.com/products/secrets-manager/)
machine-account token on macOS, including uses that come from other Macs over ssh.

AI agents and scripts that need Secrets Manager usually get a `BWS_ACCESS_TOKEN` in an env file or a
Keychain item they can read silently. With bws-touchid nothing on the Mac can use the token without you
touching the sensor, and agents on other machines can store new credentials or read existing ones without
ever holding the token.

## How it works

- Each token is an [age](https://age-encryption.org)-encrypted file, encrypted to a Secure Enclave key
  made by [age-plugin-se](https://github.com/remko/age-plugin-se) with `--access-control any-biometry`.
  Every decrypt needs Touch ID, and the Secure Enclave enforces that. Encrypting (storing) a token needs
  no Touch ID.
- A small broker (`bws-touchid serve`, a launchd user agent so the Touch ID sheet can show) listens on
  `~/.bws-broker/broker.sock` (dir 0700, socket 0600). For each request it posts a notification naming
  the requester and operation, decrypts the token (Touch ID), runs `bws` itself, and returns only the
  result. The token never leaves the broker process.
- `bws-save KEY` reads a value from stdin (never argv) and asks the broker to create the secret, or
  edit it if the key already exists in the project. Only projects in `save_projects` are allowed.
- `bws-gated` is a drop-in `bws` for read-only calls (`project list|get`, `secret list|get`, `-o json`).
  Point anything that takes a `BWS_BIN` at it. Other flags (`--access-token`, `--config-file`, unknown
  `--server-url`, write subcommands) are refused.
- Remote Macs reach your broker through `~/.bws-broker/fwd.sock` on the remote, carried either by a
  persistent tunnel from the broker Mac (`bws-touchid tunnel install`) or by a `RemoteForward` in your
  interactive ssh sessions. They get results, never the token.

Every request is logged to `~/Library/Logs/bws-touchid.log`: operation, key name, project, claimed host
and caller, and the process that actually connected (`via=local: ...` with its parent chain, or
`via=ssh session to HOST`). Values and tokens are never logged.

## Install (the Mac with Touch ID)

```bash
brew install age age-plugin-se bws
git clone https://github.com/sapoepsilon/bws-touchid && cd bws-touchid
cp config.example.json my-config.json   # edit: broker_name, save_projects, denies
./install.sh --config my-config.json    # Secure Enclave identity + launchd broker
bws-touchid store write                 # paste the read+write machine token (hidden prompt)
bws-touchid store read                  # optional: a read-only token for bws-gated
```

Then:

```bash
printf %s "$NEW_PASSWORD" | bws-save --note "created by agent X" SERVICE_PASSWORD
BWS_BIN=~/.local/bin/bws-gated some-tool-that-runs-bws
bws-touchid run -- bws secret list          # local only: token in that command's env
```

## Remote Macs

```bash
./install-remote.sh other-mac --reaper            # or --sshd-unlink if it has passwordless sudo
```

### Persistent tunnels (agents that run on their own)

List the hosts in the broker Mac's config and install one launchd user agent per host:

```json
"tunnels": ["other-mac", { "host": "build-box", "remote_sock": "/Users/builder/.bws-broker/fwd.sock" }]
```

```bash
bws-touchid tunnel install           # (re)writes ~/Library/LaunchAgents/bws-touchid.tunnel.<host>.plist
bws-touchid tunnel status --probe    # launchd state + a ping through each remote fwd.sock (no Touch ID)
bws-touchid tunnel uninstall
```

Each agent runs `ssh -N -o BatchMode=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=15
-o ServerAliveCountMax=3 -R <remote fwd.sock>:<broker.sock> <host>` with `KeepAlive` and a 10 s
`ThrottleInterval`, so a dropped or killed tunnel is back within seconds. `host` is an ssh alias (keys, user
and port come from `~/.ssh/config`; the key must work non-interactively). Without `remote_sock`, install
asks the host for its `$HOME` (sshd does not expand `~` in socket paths). `tunnel_ssh_options` adds `-o`
options. Start, exit code and duration of every tunnel run go to the log; ssh's own errors go to
`~/Library/Logs/bws-touchid.tunnel.<host>.err.log`. Install again after changing `tunnels`; hosts removed
from the list are unloaded.

Every request through a tunnel still needs your fingerprint, but the socket is there whenever the broker Mac
is awake and on the network, so any process on that host can ask at any time.

On a host that has a tunnel, do not also give your interactive sessions a `RemoteForward` to the same path:
with `--reaper` the session prints "remote port forwarding failed" (the tunnel holds the socket), and with
`--sshd-unlink` the session steals the socket and leaves it dead when it ends. The tunnel also cannot use
`ClearAllForwardings=yes`, which clears its own `-R` too. After the tunnel restarts, the remote end may
refuse the bind until the old socket is gone (sshd-unlink: immediately; reaper: within 5 s); the
restart loop retries.

A remote Mac that cannot show Touch ID (a laptop running lid-closed, a headless Mac) should not run its own
broker. Set `"local_broker": false` in its config so clients only ever use `fwd.sock`, unload its broker
(`launchctl bootout gui/$(id -u)/bws-touchid.broker`) and remove its tokens (`bws-touchid delete read`,
`... delete write`). To turn it back into a broker later (e.g. a Touch ID keyboard is attached), drop
`local_broker`, run `./install.sh` there and store the tokens again.

### Interactive sessions only

For a host without a tunnel, add to the broker Mac's `~/.ssh/config`:

```
Host other-mac
    RemoteForward /Users/<remote-user>/.bws-broker/fwd.sock /Users/<you>/.bws-broker/broker.sock
```

OpenSSH will not bind a forwarded socket over the stale one a previous session left behind. With
`--sshd-unlink` the remote sshd replaces it (newest session wins); with `--reaper` a LaunchAgent deletes
dead sockets every 5 s. Two simultaneous sessions to the same host: the first keeps the socket.

A Mac can also run its own broker. Clients pick a socket in this order: `$BWS_BROKER_SOCK`; inside an ssh
session (`SSH_CONNECTION` set) the forwarded socket, then the local broker; otherwise the local broker,
then the forwarded socket. So work started from the remote Mac's own keyboard prompts on that Mac, and
work in an ssh session from the broker Mac prompts there. `"local_broker": false` removes the local broker
from that list. When nothing is reachable, clients fail with "<broker_name> broker unreachable" and tell the
agent to ask the owner. `bws-touchid ping [SOCKET]` checks reachability without a Touch ID prompt.

## Config

`~/.config/bws-touchid/config.json`, see [config.example.json](config.example.json). On client-only
hosts only `broker_name` and `local_broker` are used.

| key | meaning |
|---|---|
| `broker_name` | how agents are told whose Touch ID they are waiting for |
| `read_token` / `write_token` | token names used by `bws-gated` / `bws-save` (default `read` / `write`) |
| `save_projects` | project names `bws-save` may write; the first is the default |
| `project_names` | id → name map, only for readable notifications |
| `denied_projects` / `denied_key_prefixes` | never read or written; also filtered out of `bws-gated` output |
| `server_urls` | `--server-url` values `bws-gated` accepts (default: Bitwarden US and EU cloud) |
| `local_broker` | clients: `false` = never use this Mac's own `broker.sock`, only `fwd.sock` (default `true`) |
| `tunnels` | broker Mac: hosts that get a persistent tunnel, `"alias"` or `{"host", "remote_sock"}` |
| `tunnel_ssh_options` | extra `-o` options for the tunnels, e.g. `["ConnectTimeout=5"]` |
| `approvers` | who may approve a gated op: `["touchid"]` (default, unchanged behaviour), `["touchid","iphone"]` (race), `["iphone"]` (lid-closed). Anything else refuses every save/read |
| `approvals_socket` | the whispera-link daemon's socket (default `~/.whispera-link/approvals.sock`) |
| `approvers_dir` | pinned iPhone approve keys, `<device_id>.pub` (default `~/.bws-broker/approvers`) |
| `iphone_token_identity` | no-biometry identity for the iPhone token copies (default `<conf dir>/identity-iphone.txt`) |
| `approval_wait_s` | how long the iPhone may answer, clamped 30–300 (default 300; the old name `phone_window_s` is still read) |
| `prefer_device_file` | file holding the last-active device id, forwarded to the daemon as a routing hint (default `~/.whispera-link/last_device`) |
| `provider` | secret backend behind the approval gate: `bitwarden` (default, the only one shipped). See [docs/PROVIDERS.md](docs/PROVIDERS.md) |

## iPhone approver (optional)

With the whispera-link daemon running on the broker Mac and the Whispera iPhone app
paired to it, every save/read can be approved either with Touch ID on the Mac or with Face ID on the phone,
whichever answers first (whispera-link `docs/PROTOCOL.md` §7, §8, §11):

- The broker builds a canonical request (op, key, summary, project, token, host, caller, via, broker, times,
  random nonce, `request_id`) and sends it to the daemon over `approvals_socket`. The daemon only relays it.
- The phone signs `WL1-APPROVE\n` + those exact bytes with a Secure Enclave key that needs Face ID. The
  broker verifies the signature itself with `/usr/bin/openssl` against the key pinned in
  `approvers/<device_id>.pub`; a bad signature, unknown device, or expired request is a **deny**.
- At the same time the Touch ID decrypt runs as before (notification text ends in "— or approve on iPhone").
  Whichever leg answers first wins; the other is cancelled (the Touch ID sheet is killed). A deny from either
  leg is a deny. Touch ID keeps its 120 s; the phone may answer for `approval_wait_s` (default 300 s), so the
  request is denied after 305 s when the phone leg is live, after 120 s when it is not.
- A phone approval decrypts `tokens/<name>.iphone.age` with a second Secure Enclave identity that has **no
  biometry**; it never falls back to the Touch ID copy.
- Daemon not running, running as another user, no paired device, no pinned key, no iPhone copy of the
  token, or no ack within 2 s: the iPhone leg is skipped and Touch ID works exactly as before, including
  its own error messages (the log line's `detail` gains `iphone-unavailable:<why>`).
- Pinned keys are refused when the pin file or `approvers_dir` is a symlink, not yours, or group/world-writable.
  A bad `approvers` list refuses every gated op, dry runs included.
- Log lines gain `approver=touchid|iphone:<device_id>|none` and `request_id=apr_…`; results `denied`,
  `timeout`, `no-approver`. With the default `["touchid"]` the log line is exactly as before (no new fields).

Setup (two Touch IDs, once):

```bash
bws-touchid iphone-setup                  # identity-iphone.txt + tokens/<read,write>.iphone.age
whispera-link pair                        # scan the QR with the Whispera app
bws-touchid approver add <device_id> ~/.whispera-link/keys/<device_id>.approve.pem   # one Touch ID
# set "approvers": ["touchid", "iphone"] in ~/.config/bws-touchid/config.json, then
launchctl kickstart -k gui/$(id -u)/bws-touchid.broker
bws-touchid status                        # approvers, pinned devices, iphone copies, approvals.sock
```

`bws-touchid approver list` shows pinned devices and fingerprints; `approver remove <device_id>` unpins one
(no Touch ID). `bws-touchid store NAME` also writes the iPhone copy once `iphone-setup` has run.

**Trade-off you accept with the iPhone approver:** the iPhone identity has no biometry, so any process
running as you on the Mac can decrypt the `.iphone.age` copies directly, without the broker and without
either prompt. The phone signature protects the broker path, not those files. Without `iphone-setup` (the
default) nothing changes: every token copy needs Touch ID.

## Async tickets (callers with a short timeout)

MCP tools are killed after 60 s, shorter than a 5-minute phone approval. Ask asynchronously and collect later:

```bash
bws-gated --async secret get <id>          # prints {"ticket": "tkt_…"} at once (exit 0)
printf %s "$V" | bws-save --async KEY      # same; or set BWS_TOUCHID_ASYNC=1 for either
bws-touchid ticket wait tkt_… [--timeout S] # long-polls (default 50 s); prints what bws-gated / bws-save would
bws-touchid ticket get tkt_…               # one look, no waiting
```

`ticket wait|get` exit codes: 0 approved, 5 denied, 6 expired / unknown / already collected / not yours,
75 still pending (run it again). On the socket: `{"op":"bws"|"save", …, "async":true}` → `{"ok":true,
"status":"pending","ticket":"tkt_…"}`, and `{"op":"ticket.get","ticket":…,"host":…,"caller":…,"wait":S}` →
`pending`, `approved` (`result` = the normal response), `denied` (`error`) or `expired`.

Results live in the broker's memory only (never on disk, never logged), are handed out **once**, and are
dropped 10 minutes after the request finished. A ticket only answers the same uid, host and caller that
asked (set `BWS_TOUCHID_CALLER` to the same value for both calls); anything else gets `expired`. Approvals
stay serial: async jobs queue behind each other, and a synchronous request waits up to 30 s for the
approval slot before it gets "broker busy".

Timeouts nest so a slow approval ends with a broker error, never a client that gave up first: Touch ID
120 s ≤ iPhone 300 s (+5 s grace) < broker connection 495 s < client 535 s.

## Threat model and limits

What it gives you: no process on the Mac can use a stored token silently, because the decrypt key lives
in the Secure Enclave and every decrypt needs a fingerprint. Remote machines never receive the token.
Each prompt is preceded by a notification and a log line naming who asked.

What it does not:

- **macOS's Touch ID sheet text is fixed by age-plugin-se**; the notification just before it is what
  tells you who is asking. Read it before you touch the sensor.
- **A process running as your user (or root) can still request a decrypt**, edit the broker script, or
  swap the `bws` binary, and wait for you to approve something. You will see a prompt and a notification
  for every use, but a modified broker can lie in them. This raises the bar from "silent" to "needs you
  to approve a prompt"; it does not defend against a fully compromised account.
- **Read results go to the requester.** `bws-gated` returns secret values to whoever asked, local or
  remote. That is the point of a read, so approve reads you expect.
- **bws 2.x only accepts the value on its command line** for `secret create/edit`. During a save the value
  is visible in the process list to processes of the same user on the broker Mac for the second `bws`
  runs. It is never logged and is redacted from errors.
- `bws-touchid store` needs no Touch ID, so a local process could overwrite a token file with a different
  token. That denies service or points writes at another account; it does not leak your token.
- Any process on a remote Mac can use the forwarded socket while your ssh session is open, or at any time
  if it has a persistent tunnel. Each request still needs your fingerprint, and the notification says which
  host it came from. Only add tunnels to hosts whose requests you are willing to see at any hour.
- Losing the Mac's Secure Enclave key (new Mac, reset) means re-storing the tokens; the `.age` files are
  useless elsewhere.

## Tests

```bash
python3 -m unittest -v      # temp HOME, fake age / age-plugin-se / bws, fake approvals socket; ~2 min
```

No Secure Enclave, real token, Touch ID prompt or Bitwarden call is involved. The cross-repo test
(`tests/e2e/integration_broker.sh` in whispera-link, with this repo checked out next to it) runs this
script as `serve` against the real whispera-link daemon with the same fakes in a temp HOME. The P-256 keys in
`tests/fakes/vectors_v1.json` (whispera-link's known-answer vectors) and the ones the tests generate are
throwaway test keys.

Requires macOS with a Secure Enclave and Touch ID, Python 3.9+ (`/usr/bin/python3`), `age`,
`age-plugin-se` and `bws` on the broker Mac. Clients need only Python.

## License

MIT
