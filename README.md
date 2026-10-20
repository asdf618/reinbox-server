# Reinbox Server

Run coding agents on your computer and manage their conversations from the
Reinbox Android app. Reinbox presents sessions as an inbox: start a task, read
streamed replies and tool output, send a follow-up, or pick up a conversation
started in your terminal.

The server supports **Claude Code, Codex, and Grok CLI**. It runs alongside your
installed agents and stores conversations in SQLite.

## Get started

You need Python 3.10+, the Reinbox app, and at least one supported CLI installed
and authenticated on the server machine. Check that the CLI works in your
terminal first.

### 1. Install

```bash
git clone https://github.com/asdf618/reinbox-server.git
cd reinbox-server
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
cp config.json.example config.json
```

### 2. Configure

Edit `config.json` using the [example configuration](config.json.example):

- Set `root_dir` to your projects directory and `db_path` to a writable location
  for the database. Use absolute paths.
- Keep the agents you have installed. Set each agent's `path` to its executable
  and give it a unique `name`.
- Choose how the app will reach the server. `bind: ["127.0.0.1"]` works with a
  local tunnel; `bind: []` listens on all IPv4 interfaces. The default port is
  `16861`.
- Review `open_server` and each agent's `args` before starting.

**The example enables permission bypass for Claude Code and Codex.** Anyone
with server access can run those agents as your OS user. Use a trusted network
or tunnel and read [Access and permissions](#access-and-permissions) below.

### 3. Start and connect

```bash
python3 reinbox_server.py
```

On first startup, the server creates `config.key` and prints its public key as
text and a QR code. Add a server in the app with an address it can reach, then
scan or paste the printed key.

Keep `config.key` private and back it up: it holds the server's identity.
Restart the server after changing its configuration. To use a different config:

```bash
python3 reinbox_server.py /path/to/config.json
```

## Using your agents

In the app, choose an agent and project directory, then send a prompt. Replies
and tool output appear as the agent works. You can reply to an existing session,
cancel a run, and send or download files.

Sessions started directly in a supported CLI are imported at startup and when
you refresh the app. Refreshing imports history without sending a notification.
To refresh and notify connected clients of the latest fresh reply, run:

```bash
python3 reinbox_server.py --notify
```

This contacts the running server and includes the full final response in the
notification event. An optional config path selects the server to contact.

### Agent settings

Each entry in `agents` selects a `type` (`claude`, `codex`, or `grok`), `name`,
and executable `path`. The other useful settings are:

| Setting | Purpose |
| --- | --- |
| `scope` | `workspace` limits sessions to `root_dir`; `global` includes sessions outside it and allows runs in other accessible directories. |
| `home_dir` | Selects a custom CLI data directory. An empty value uses the CLI's default location. |
| `models`, `efforts` | The choices offered in the app. Set these to values your CLI supports. |
| `args` | Extra CLI arguments, one list entry per argument. |

The server uses each CLI's own authentication and permission settings. Runs
are non-interactive; permission prompts cannot be answered through the app.
The Grok example adds no permission-bypass option.

## Access and permissions

Only give access to devices you trust to run code on the server machine.
Consider a dedicated OS account with access limited to your projects and agent
data.

- **Open mode** (`open_server: true`): possession of the server public key grants
  access. Treat the printed key as an access credential.
- **Closed mode** (`open_server: false`): add each device's public key from the
  app to `allowed_clients`.

Authenticated requests are signed; conversation responses and WebSocket
messages are encrypted. Restrict network access with a VPN, tunnel, or firewall.
For a reverse proxy, enable WebSocket forwarding and set `base_path` if serving
under a path such as `/reinbox`.

## Stored data

Conversations live in the SQLite database at `db_path`. The CLIs also keep their
own transcript stores. Back up the database using SQLite's backup facility, or
stop the server before copying it. Preserve the config, server key, and CLI data
when moving to another machine.

**Deleting a session also deletes its associated CLI transcripts.** Grok
cleanup removes the session directory and its local search entry; shared prompt
history is retained.

## Development

```bash
python3 -m unittest discover -s tests -v
```

## License

[MIT](LICENSE)
