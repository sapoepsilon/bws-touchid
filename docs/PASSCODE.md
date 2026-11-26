# Passcode approver

An optional third approver for when Touch ID cannot answer: the lid is closed, the Mac has no sensor, you
are in an ssh session, or you simply prefer it. Off by default; with `"approvers": ["touchid"]` (or no
`approvers` key) nothing in this document runs.

## Crypto design

A passcode must *unlock* the token, not sit in front of it. So, like the iPhone approver, each token gets
a separate sealed copy, `tokens/<name>.passcode.age`, and the only way to the token in that copy is the
passcode:

- The copy is a normal [age](https://age-encryption.org) file with a single **scrypt passphrase recipient**
  (age's own format: random 16-byte salt per file, scrypt log2 N = 18 (256 MiB, about 1 s), the file key
  wrapped with ChaCha20-Poly1305, payload in age's STREAM). A wrong passcode fails age's authentication,
  so there is no hash to compare and nothing to bypass: no passcode, no token.
- The plaintext is `bws-touchid-passcode-v1\n` + `{"name": <token name>, "token": ...}`. The name is checked
  after decrypt, so `write.passcode.age` copied over `read.passcode.age` is a deny (`copy-mismatch`), not a
  silent write-token read.
- age only reads a passphrase from a terminal. age 1.3 ships `age-plugin-batchpass` for non-interactive use;
  bws-touchid runs `age -e|-d -j batchpass` and hands it the passcode through `AGE_PASSPHRASE_FD`: the read
  end of a pipe the broker filled and closed, inherited by that one child (`pass_fds`). The passcode is
  never in argv, never in the environment (`AGE_PASSPHRASE` is never set), never in a file, never logged.
  The environment only carries the fd number.

Why age and not `hashlib.scrypt` + our own cipher: the broker is Python standard library only, and the
standard library has scrypt but no authenticated encryption. Everything else in the repo is sealed by
age, so the passcode copies are too, with age's audited scrypt recipient, instead of new hand-rolled
crypto. The cost is a dependency on age ≥ 1.3 with `age-plugin-batchpass` (Homebrew's `age` ships it);
without the plugin the passcode leg is skipped (`passcode-unavailable:no-batchpass-plugin`) and `passcode
set` refuses.

## Commands

| command | needs | does |
|---|---|---|
| `bws-touchid passcode set` | Touch ID per token, a terminal | Touch ID first, then the passcode twice (getpass, no echo; ≥ 8 characters, no control characters or leading/trailing spaces), then seals a copy of every Touch ID token and creates the attempt counter |
| `bws-touchid passcode change` | same | new passcode for every copy (the old one is not asked for: Touch ID is the stronger factor); resets the counter |
| `bws-touchid passcode unlock` | one Touch ID | clears failed attempts and the lockout |
| `bws-touchid passcode remove` | nothing | deletes every `*.passcode.age` and the counter |
| `bws-touchid passcode status` | nothing | copies, attempts, approver on/off, plugin |

Then add `"passcode"` to `approvers` (any mix: `["touchid","passcode"]`, `["touchid","iphone","passcode"]`,
`["passcode"]`) and restart the broker. `set` and `change` refuse without a terminal (`/dev/tty`); they never
read a passcode from a pipe, argv or env. `bws-touchid store NAME` cannot seal a passcode copy (it never asks
for the passcode), so it deletes `NAME`'s stale copy and tells you to run `passcode change`. If a `store`
replaces a token while `set` / `change` is running, `set` / `change` notices (inode, mtime and size of
`tokens/NAME.age` differ from before its Touch ID decrypt), removes the copies it just sealed and stops with
nothing changed.

## At approval time

- **Broker (save / read):** the passcode leg races Touch ID and the iPhone like the phone leg does. The broker
  shows a macOS dialog (`osascript`, `display dialog … with hidden answer`, Deny / Approve) naming the
  request, for up to 120 s. The request text goes to AppleScript through `on run argv`; the answer comes back
  on osascript's stdout pipe, is read into a `bytearray`, written into the age pipe and zeroed. The first
  answer wins: a right passcode approves (Touch ID sheet and phone request are cancelled), **Deny** is a deny,
  Touch ID or the phone answering first closes the dialog. A wrong passcode re-opens the dialog ("Wrong
  passcode (n of 5 attempts used)") after the backoff. The notification ends in "— or enter passcode".
  Log lines: `approver=passcode`, notes `passcode-wrong:<n>`, `passcode-unavailable:<why>`.
- **`bws-touchid run --passcode -- CMD`** (local, interactive, e.g. in an ssh session to the broker Mac):
  getpass on the terminal instead of Touch ID, same counter. Refused unless `"passcode"` is in `approvers`.

The leg is skipped (Touch ID / iPhone unaffected) when: no copy for that token, the copy is not a 0600 file
you own or the tokens dir is group/world-writable, age or the plugin is missing, the dialog program is
missing, the passcode is locked, or the backoff is longer than the window.

## Brute-force limits

`~/.config/bws-touchid/passcode-state.json` (0600, `flock`ed, opened with `O_NOFOLLOW`):

- Every attempt is counted **before** the decrypt runs, so killing the verify does not save a try; a right
  passcode resets the count. If Touch ID or the phone answers while a verify is still running, the verify is
  killed at once and the attempt stays counted (`op=passcode result=abandoned … reason=<why>`); a lockout
  reached that way is notified like any other. A verify that exits on its own just as it is killed is
  settled by its real outcome instead (a right passcode still resets the count; its token is discarded).
- A passcode submitted before the 120 s deadline is always verified: the request waits for that verify
  (at most 30 s) instead of killing it at the deadline, so a late answer is not wasted as `abandoned`.
- A tool error (plugin crash, out of memory, missing plugin, a decrypt that takes over 30 s) is counted too,
  but it ends the passcode leg (`passcode-unavailable:error`, log `result=error`) instead of re-prompting
  "Wrong passcode".
- The counter's `flock` is non-blocking with a 2 s retry. If another process holds it longer, the passcode
  leg is skipped as locked (`locked(state-busy)`); Touch ID and the iPhone still work.
- Backoff after the n-th failure: 5 s · 4^(n−1) (5, 20, 80, 320 s).
- **Hard lockout after 5 failures.** Only Touch ID clears it (`passcode unlock` or `passcode change`); a right
  passcode is not even asked for while locked, and a Touch ID approval of some other request does not clear
  it either. A notification says so when it happens.
- Missing, corrupt, symlinked or wrongly owned/moded counter = locked (deleting it does not reset anything).
- Each failure is logged (`op=passcode result=wrong|locked token=… detail=failures=n/5 via=dialog|run`), never
  the passcode.

## Residual risks

- **Offline guessing.** The copies are files any process running as you can read. Such a process can guess
  passcodes offline at scrypt cost (about 1 s and 256 MiB per guess per core), ignoring the counter, which
  only limits the dialog and `run --passcode`. Use a long passphrase, not a PIN; 8 characters is the floor,
  not a recommendation. A Touch ID copy has no such weakness (its key never leaves the Secure Enclave).
- **The lockout does not stop anyone with a shell in your session.** The counter is a 0600 JSON file your
  user owns: any process running as you can write `{"v": 1, "failures": 0, "last_failure": 0, "locked":
  false}` and it is accepted. The counter only rate-limits guessing through the dialog and the `run
  --passcode` terminal prompt, i.e. someone at the keyboard. Against code running as you, the real limit is
  the passcode's strength against offline scrypt guessing (above).
- **Old copies in backups.** `passcode change` and `passcode remove` only replace or delete the files on disk.
  A copy already in a backup still opens with the passcode it was sealed with, and holds a token that is
  still valid. `passcode set` and `change` run `tmutil addexclusion` on each new copy (macOS; it warns, and
  you should exclude them by hand, if that fails; elsewhere it is a no-op), but copies made before that, or
  by other backup tools (iCloud Drive sync of `~/.config`, Backblaze, rsync, disk images), are not covered.
  **After a suspected passcode leak, rotate the Bitwarden machine-account access tokens** (new token in the
  Bitwarden web app, `bws-touchid store NAME`, revoke the old one, then `passcode change`); changing the
  passcode alone does not help against a copy someone already has.
- **Phishing.** Anything running as you can draw a look-alike dialog and ask for the passcode; Touch ID cannot
  be phished that way. Only type it when the notification just before the dialog names a request you expect.
- **Plaintext copies in memory.** getpass, UTF-8 decoding and osascript produce Python `str` / process copies
  that cannot be wiped; the `bytearray` buffers the broker controls are zeroed.
- **Not covered by the fakes:** the real AppleScript dialog under launchd (tests use a fake osascript; the
  real age + plugin protocol is tested when they are installed). No Linux broker exists; `run --passcode`
  is the terminal path.
