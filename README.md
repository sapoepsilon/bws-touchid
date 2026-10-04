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
- Remote Macs: add a `RemoteForward` from the broker Mac's ssh config, and agents in those ssh sessions
  reach your broker through `~/.bws-broker/fwd.sock` on the remote. They get results, never the token.

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

and in the broker Mac's `~/.ssh/config`:

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
work in an ssh session from the broker Mac prompts there. When neither is reachable, clients fail with a
message telling the agent to ask the owner.

## Config

`~/.config/bws-touchid/config.json`, see [config.example.json](config.example.json). On client-only
hosts only `broker_name` is used.

| key | meaning |
|---|---|
| `broker_name` | how agents are told whose Touch ID they are waiting for |
| `read_token` / `write_token` | token names used by `bws-gated` / `bws-save` (default `read` / `write`) |
| `save_projects` | project names `bws-save` may write; the first is the default |
| `project_names` | id → name map, only for readable notifications |
| `denied_projects` / `denied_key_prefixes` | never read or written; also filtered out of `bws-gated` output |
| `server_urls` | `--server-url` values `bws-gated` accepts (default: Bitwarden US and EU cloud) |

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
- Any process on a remote Mac can use the forwarded socket while your ssh session is open. Each request
  still needs your fingerprint, and the notification says which host it came from.
- Losing the Mac's Secure Enclave key (new Mac, reset) means re-storing the tokens; the `.age` files are
  useless elsewhere.

Requires macOS with a Secure Enclave and Touch ID, Python 3.9+ (`/usr/bin/python3`), `age`,
`age-plugin-se` and `bws` on the broker Mac. Clients need only Python.

## License

MIT
