# Reinbox Server

The backend of **Reinbox**, an email-like orchestrator for CLI coding agents.
The client provides the interface; this half runs on the machine where the
agents live — it launches the runs (`claude -p` / `codex exec`), stores the
conversations, and pushes completion events. Sessions started directly in a
terminal are imported as well, and an agent set to **global scope** contributes
every session on the machine, whatever directory it ran in.

## Requirements

- Python 3.10+
- Claude Code and/or Codex, installed and authenticated on the same machine
- `pip install -r requirements.txt` (`pyqrcode` is optional — terminal QR)

## Setup

```bash
cp config.json.example config.json   # then edit — see below
python3 reinbox_server.py            # or: python3 reinbox_server.py other-config.json
```

First run generates an X25519 keypair: the private key is written to
`config.key` (mode 600) next to the config, and the public key is printed as
text and as a scannable terminal QR. That key is what the app scans to add this
server.

Several servers can run side by side with different config files and ports.

## config.json

Read once, at startup — edit it, then restart. A missing or invalid config stops
the server.

### Required

| Key | Meaning |
|---|---|
| `root_dir` | Scoped sessions run in subdirectories of this root and their paths are shown relative to it. A leading `/` marks a full path, used by global-scope agents (their root is effectively `/`). |
| `db_path` | SQLite file for sessions/messages. It runs in WAL mode, so a copy taken while the server runs also needs the `-wal` and `-shm` files beside it. |
| `bind` | Interface addresses to listen on, e.g. `["127.0.0.1"]`. `[]` listens on every interface; loopback plus a tunnel keeps the port off the network. |
| `open_server` | `true`: anyone holding the server public key can connect. `false`: only devices in `allowed_clients`. Encrypted either way. |
| `agents` | At least one — see below. |

### Optional

| Key | Meaning |
|---|---|
| `port` | HTTP port. Default 16861. |
| `base_path` | Sub-path when behind a reverse proxy, e.g. `"/reinbox"` for `https://host/reinbox → localhost:16861`. |
| `allowed_clients` | Closed mode: client public keys. Each device shows its key in the app; remove a key to revoke that device. |
| `private_key_file` | Path to the server's key file. Default `<config>.key`. |

### Agents

One entry per agent: `type` (`claude`/`codex`), `name`, `path` (executable),
`models`, `efforts`, `args`, plus:

- `scope` — `"workspace"`: only sessions under `root_dir`. `"global"`: every
  session of that agent wherever it ran, and runs in any directory the service
  user can reach. Global is the widest setting an agent can have.
- `home_dir` — the agent's data directory, when it isn't the stock one
  (`~/.claude`, `~/.codex`). Two agents of the same type are told apart by it;
  without one, the first listed owns the shared store.

The server hard-codes `-p --output-format stream-json --verbose` for Claude,
`exec --json --skip-git-repo-check` for codex, and the per-turn values picked in
the app (model, effort, resume). Everything else comes verbatim from `args`,
including the permission flags in the template — `--permission-mode
bypassPermissions` and `--dangerously-bypass-approvals-and-sandbox`. Runs are
asynchronous and non-interactive: nobody is at the terminal, so an agent that
stops to ask for permission stalls until it is cancelled.

## Security

A paired client can execute arbitrary code as the user running Reinbox. Reinbox
authenticates devices and encrypts traffic; it does not authorize individual
operations. Pairing is the whole trust boundary — treat a paired device as a
shell on the machine and draw the line in the OS: a dedicated unprivileged user,
container or VM, reaching only the intended workspace and agent data, with no
sudo, personal SSH keys or cloud credentials.

All traffic is AES-256-GCM encrypted end to end in both modes, keys included.
Every request carries a one-time HMAC signature binding its method, path, query
and body.

- **Open** (`open_server: true`) — the encryption keys derive from the server
  public key, so holding that key is the credential.
- **Closed** — every device gets its own ECDH-derived keys from the public key
  listed in `allowed_clients`. Registered devices keep working if the server is
  later flipped open.

`config.key` is the server identity: delete it and every client must re-scan.

Any TCP route to the port works — LAN, VPN (Tailscale, WireGuard), an SSH
forward, or a reverse-proxy tunnel. For a sub-path route set `base_path`.

## Terminal & cron runs

Sessions that don't start from the app reach it in two ways:

1. **Silent pickup (automatic).** Anything run with the plain `claude` / `codex`
   CLIs is imported by reconciliation on the app's next refresh, without a
   notification.
2. **`--notify` (deliberate signal).** Tells the running server to reconcile now
   and push a notification carrying the **full final response** of the latest
   fresh reply (the text the terminal printed — steps excluded).

   ```bash
   python3 reinbox_server.py --notify            # [config.json] if not the default
   # cron, with a plain CLI run:
   0 3 * * * claude -p "nightly refresh" ... ; /usr/bin/python3 /opt/reinbox-server/reinbox_server.py --notify
   ```
