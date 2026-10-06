# Providers

The broker has two halves:

- **the approval gate** (`approve_gate`): who may approve (Touch ID, iPhone), the race, deadlines, the
  audit fields, and unsealing the credential the operation needs (`tokens/<name>.age`, or the
  `.iphone.age` copy after a verified phone signature);
- **the provider**: which credential an operation needs, how a request is parsed and summarised for the
  prompt, and how `list` / `get` / `save` talk to the backend.

The gate never looks at provider details and a provider never sees approvers. `"provider"` in
`config.json` picks one; the default and only shipped provider is `bitwarden` (the `bws` CLI, exactly the
behaviour from before providers existed). Unknown names and the skeletons below refuse every save/read,
dry runs included, before any prompt.

## The interface (`class Provider` in `bws-touchid`)

| member | contract |
|---|---|
| `name` | config value, e.g. `"bitwarden"` |
| `enabled` | only `True` providers can be selected |
| `token_env` | how the unsealed token is handed to the backend CLI (e.g. `BWS_ACCESS_TOKEN`) |
| `read_token(c, requested)` / `write_token(c)` | sealed credential names for reads / saves (default `read_token` / `write_token` from config) |
| `parse_read(raw, c)` | the client's argv (from `bws-gated`) → `None` (refused) or `{"kind": "list"\|"get", "args", "summary", "project", "project_id"}` (`project_id`: the project uuid a scoped read names, else `""`). `summary` is shown in the notification and signed by the phone; `project` must be a readable name. Apply `denied_projects` / `denied_key_prefixes` here |
| `list(op, token, c)` / `get(op, token, c)` | run the read; return `(exit_code, stdout_bytes, stderr_text)`. stderr must never contain the token |
| `save(key, value, note, project, token, c)` | create or update one secret; return `(result, detail, response)` where `result` is the audit word (`created`, `updated`, `rejected`, `error`) and `response` the client JSON. Never log or echo `value` |
| `scrub(stdout, c)` | drop denied projects / keys from read output (keys case-insensitively; when `c["allowed_project_ids"]` is set, also every item whose project is not in it) |
| `resolve_projects(op, token, c)` | after approval, when a denied project *name* has no id in `project_names`: the project ids visible to `token` minus denied ones, or `(None, why)`. The base class fails closed, so a provider without it refuses such reads |

Rules every provider keeps:

- The token exists only in the broker process for one operation: env of the child process, never argv,
  never a file. Run the CLI with an empty temp `HOME` (see `run_bws`) so no user config can redirect it.
- Values go to the backend on stdin or an inherited pipe when the CLI allows it; when it only takes argv
  (bws 2.x), say so in the README threat model.
- Policy (`save_projects`, `denied_projects`, `denied_key_prefixes`) applies to the provider's notion of a
  project (vault, service prefix, …). The broker checks `save_projects` and key rules before the gate;
  the provider re-checks anything only it can resolve (e.g. a project id) after.
- Every path is covered by tests with a fake CLI on `PATH` (see `tests/fakes/fake_bws.py`), including
  `TestDefaultUnchanged` staying green.

## Adding 1Password (`op`) — skeleton: `OnePasswordProvider`

- Credential: a 1Password **service account** token per sealed name: `tokens/read.age` (read-only
  vaults), `tokens/write.age` (the vaults agents may write). `token_env = "OP_SERVICE_ACCOUNT_TOKEN"`.
- `project` = vault name; `save_projects` lists writable vaults.
- `parse_read`: accept a small `op`-like surface, e.g. `item list --vault V --format json` (kind
  `list`) and `item get ID --vault V --format json` (kind `get`); refuse everything else
  (`--reveal` of other fields, `account`, `signin`, `read op://…` outside allowed vaults).
- `save`: `op item get KEY --vault V` → `op item edit` (update) or `op item create --category password
  --vault V --title KEY` (create). Pass the value through `--template -` on stdin rather than
  `password=<value>` on argv.
- Binary path: `op_path` config key, looked up like `bws_path` (`find_tool`).
- Register in `PROVIDERS`, set `enabled = True`, add tests with a fake `op`, document it in the README.

## Adding macOS Keychain (`security`) — skeleton: `KeychainProvider`

- No bearer token: the backend is the login keychain itself. Keep the sealed-token gate anyway (that
  decrypt *is* the Touch ID approval; for the phone path the `.iphone.age` copy is the proof the gate
  passed); the provider ignores the token (`token_env = ""`).
- `project` = a service prefix such as `agents.` ; items are generic passwords with service
  `<prefix><KEY>` and account `bws-touchid`.
- `parse_read`: `list` = names under the prefix (no values); `get KEY` = one value via
  `/usr/bin/security find-generic-password -s <service> -a bws-touchid -w`.
- `save`: `/usr/bin/security add-generic-password -U -s <service> -a bws-touchid -T '' -w` with the value
  on the interactive prompt fed through a pipe (not `-w VALUE` on argv).
- Big caveat to resolve before enabling: a generic password created by `security` is readable by
  `security` for any process running as the user unless its ACL is restricted (`-T ''` and no
  "allow all"), which would bypass the gate entirely. Decide and test the ACL first.
- Register, enable, test with a fake `security` (absolute path from config so tests can swap it).
