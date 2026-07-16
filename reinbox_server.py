#!/usr/bin/env python3
import asyncio
import base64
from contextlib import asynccontextmanager
import errno
import hmac
import hashlib
import json
import logging
import mimetypes
import os
import re
import shutil
import signal
import sqlite3
import stat as stat_module
import sys
import time
import traceback
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey)
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("Reinbox")

CONFIG = {}
ACTIVE_CONNECTIONS = set()
# One queue per viewer so clients don't steal each other's chunks; None ends it.
STREAM_SUBSCRIBERS: Dict[str, Set[asyncio.Queue]] = {}
RUNNING_PROCESSES: Dict[str, asyncio.subprocess.Process] = {}  # session_id -> live subprocess
LIVE_STEPS: Dict[str, List[dict]] = {}  # run-in-progress steps, polled by /sessions/{id}/live
# Turn in flight: a second send is rejected, not raced onto one transcript.
ACTIVE_RUNS: Set[str] = set()
# Live runner tasks, retained so shutdown can cancel and await them.
RUNNER_TASKS: Set["asyncio.Task"] = set()
# Tombstones (id -> time): a late runner or ingest must not re-create the row.
DELETED_SESSIONS: Dict[str, float] = {}

# Non-matching ids are rejected before reaching the filesystem or a subprocess.
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def is_safe_id(value: Optional[str]) -> bool:
    return bool(value) and bool(SAFE_ID_RE.match(str(value)))


def push_stream(session_id: str, text: Optional[str]):
    """Fan a log line to every subscriber; drop-oldest per queue so one slow
    consumer can't block the runner or its peers."""
    for q in list(STREAM_SUBSCRIBERS.get(session_id, ())):
        try:
            q.put_nowait(text)
        except asyncio.QueueFull:
            try:
                q.get_nowait()
                q.put_nowait(text)
            except Exception:
                pass

SKIP_DIR_NAMES = {"node_modules", "__pycache__", "venv", ".venv", "build", "dist", "target", ".gradle"}
FOLDER_MAX_DEPTH = 3

# Optional keys and their defaults. Everything security-critical is absent here
# on purpose: each is REQUIRED in the config, so no reachable path can invent a
# workspace, a database, a listen address or an authentication posture.
OPTIONAL_CONFIG = {
    "port": 16861,
    # Sub-path when a reverse proxy routes a prefix here, e.g. "/reinbox".
    "base_path": "",
    # X25519 private key file; empty = "<config>.key" beside the config (0600).
    "private_key_file": "",
    "allowed_clients": [],     # closed mode: list of client public keys (base64)
}

# Every one must be stated in the config, with this type.
#   root_dir    — scoped sessions live here (root-relative); absolute = global
#   db_path     — the SQLite file
#   bind        — addresses to listen on; [] = all interfaces
#   open_server — True: knowing the server public key grants access
#   agents      — one section per agent; type: claude | codex
REQUIRED_CONFIG = {
    "root_dir": str,
    "db_path": str,
    "bind": list,
    "open_server": bool,
    "agents": list,
}

CONFIG_PATH_USED = "config.json"

AGENT_TYPES = ("claude", "codex")
AGENT_SCOPES = ("workspace", "global")


def _check_agents(agents: List[dict]) -> None:
    """Each section names a launchable type, a name unique among the agents, and
    an executable that resolves. "scope" and "home_dir" may be omitted for the
    defaults: workspace, and the type's stock store."""
    seen: Set[str] = set()
    for a in agents:
        name = str(a.get("name") or "").strip()
        if not name:
            raise ValueError('every agent needs a non-empty "name"')
        if name.lower() in seen:
            raise ValueError(f'two agents are named "{name}"; names must be unique')
        seen.add(name.lower())
        if a.get("type") not in AGENT_TYPES:
            raise ValueError(f'agent "{name}": "type" must be one of '
                             f'{" | ".join(AGENT_TYPES)}, got {a.get("type")!r}')
        scope = a.get("scope")
        if scope is not None and str(scope).strip().lower() not in AGENT_SCOPES:
            raise ValueError(f'agent "{name}": "scope" must be one of '
                             f'{" | ".join(AGENT_SCOPES)}, got {scope!r}')
        path = str(a.get("path") or "").strip()
        if not path:
            raise ValueError(f'agent "{name}" needs a "path" to its executable')
        if not shutil.which(os.path.expanduser(path)):
            raise ValueError(f'agent "{name}": "{path}" is not an executable on this machine')


def _check_clients(keys: List[str]) -> None:
    """Client identities are base64 X25519 public keys: 32 bytes, listed once."""
    seen: Set[str] = set()
    for k in keys:
        try:
            raw = base64.b64decode(str(k), validate=True)
        except Exception:
            raise ValueError(f'allowed_clients: "{k}" is not base64')
        if len(raw) != 32:
            raise ValueError(f'allowed_clients: "{k}" decodes to {len(raw)} bytes, '
                             f"not the 32 of an X25519 public key")
        if k in seen:
            raise ValueError(f'allowed_clients: "{k}" is listed twice')
        seen.add(k)


def _build_config(data: dict) -> dict:
    """Optional defaults + file contents, validated, as a NEW dict. Raises on
    anything missing, ill-typed or unusable."""
    if not isinstance(data, dict):
        raise ValueError("config must be a JSON object")
    cfg = dict(OPTIONAL_CONFIG)
    cfg.update(data)

    missing = [k for k in REQUIRED_CONFIG if k not in data]
    if missing:
        raise ValueError(f"missing required key(s): {', '.join(sorted(missing))}")
    for key, want in REQUIRED_CONFIG.items():
        if not isinstance(cfg[key], want):
            raise ValueError(f'"{key}" must be {want.__name__}, got '
                             f'{type(cfg[key]).__name__}')
    for key in ("root_dir", "db_path"):
        if not str(cfg[key]).strip():
            raise ValueError(f'"{key}" must name a path')
    if not all(isinstance(b, str) and b.strip() for b in cfg["bind"]):
        raise ValueError('"bind" must list addresses as strings, e.g. ["127.0.0.1"]')
    if not cfg["agents"]:
        raise ValueError('"agents" must list at least one agent')
    if not all(isinstance(a, dict) for a in cfg["agents"]):
        raise ValueError('"agents" must be a list of objects')
    _check_agents(cfg["agents"])
    if not isinstance(cfg["allowed_clients"], list):
        raise ValueError('"allowed_clients" must be a list of client keys')
    _check_clients(cfg["allowed_clients"])
    if not cfg["open_server"] and not cfg["allowed_clients"]:
        logger.warning("Closed server with an empty allowed_clients — "
                       "no client can authenticate until one is listed.")
    return cfg


def load_config(config_path: str = "config.json") -> dict:
    """The config is read once, at startup. Changing it means restarting."""
    global CONFIG, CONFIG_PATH_USED
    path = Path(config_path)
    CONFIG_PATH_USED = str(path)
    try:
        with open(path, "r") as f:
            cfg = _build_config(json.load(f))
    except FileNotFoundError:
        raise SystemExit(f"No config at {path} — copy config.json.example and edit it.")
    except Exception as e:
        raise SystemExit(f"Invalid config {path}: {e}")
    logger.info(f"Loaded config from {path.absolute()}")

    CONFIG = cfg
    os.makedirs(root_dir(), exist_ok=True)
    db_dir = os.path.dirname(CONFIG["db_path"])
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    return CONFIG


def get_agent(name: Optional[str]) -> dict:
    """Agent config section by name (case-insensitive); defaults to the first
    configured agent when no name is given."""
    agents = CONFIG.get("agents") or []
    if name:
        for a in agents:
            if str(a.get("name", "")).lower() == str(name).lower():
                return a
    return agents[0] if agents else {
        "type": "claude", "name": "Claude", "path": "claude",
        "models": [], "efforts": ["low", "medium", "high", "xhigh", "max"],
        "args": ["--permission-mode", "bypassPermissions"],
    }


def root_dir() -> str:
    return os.path.realpath(os.path.expanduser(CONFIG.get("root_dir", "~/workspace")))


def agent_scope_global(agent_cfg: Optional[dict]) -> bool:
    """"scope": "global" means all of the agent's sessions are imported and runs
    may target any absolute directory (root is essentially /)."""
    return bool(agent_cfg) and str(agent_cfg.get("scope", "workspace")).strip().lower() == "global"


def any_agent_global() -> bool:
    return any(agent_scope_global(a) for a in (CONFIG.get("agents") or []))


def stock_home_dirs(agent_type: str) -> List[str]:
    """Where an agent that names no "home_dir" keeps its data. codex has several
    candidates because its clones each pick their own."""
    home = os.path.expanduser("~")
    if agent_type == "codex":
        dirs = []
        if os.environ.get("CODEX_HOME"):
            dirs.append(os.environ["CODEX_HOME"])
        dirs.extend([os.path.join(home, ".trae", "cli"), os.path.join(home, ".codex")])
        return dirs
    return [os.path.join(home, ".claude")]


def agent_home_dirs(agent_cfg: Optional[dict]) -> List[str]:
    """One agent's data dirs: its own "home_dir", else the stock ones for its
    type."""
    configured = str((agent_cfg or {}).get("home_dir") or "").strip()
    if configured:
        return [os.path.expanduser(configured)]
    return stock_home_dirs((agent_cfg or {}).get("type", "claude"))


def agents_of_type(agent_type: str) -> List[dict]:
    return [a for a in (CONFIG.get("agents") or [])
            if a.get("type", "claude") == agent_type]


def homes_for_type(agent_type: str) -> List[str]:
    """Every data dir any agent of this type could be using — for lookups and
    deletion, which must search all of them."""
    dirs: List[str] = []
    for a in agents_of_type(agent_type):
        for d in agent_home_dirs(a):
            if d not in dirs:
                dirs.append(d)
    if not dirs:
        dirs = stock_home_dirs(agent_type)
    return dirs


def claude_home_dirs() -> List[str]:
    return homes_for_type("claude")


def codex_home_dirs() -> List[str]:
    return homes_for_type("codex")


def agent_store_pairs(agent_type: str) -> List[Tuple[dict, str]]:
    """(agent, home) pairs for discovery, so each transcript is attributed and
    scope-checked against the agent that actually owns its store. A store is
    claimed by the first agent listing it, keeping attribution deterministic when
    two agents of one type name no home_dir and share the stock candidates."""
    pairs: List[Tuple[dict, str]] = []
    claimed = set()
    for a in agents_of_type(agent_type):
        for d in agent_home_dirs(a):
            if d in claimed:
                continue
            claimed.add(d)
            pairs.append((a, d))
    return pairs


# X25519 server keypair. Every request carries a one-time HMAC binding method,
# path, query and body, and every payload is AES-GCM encrypted in both modes, so
# nothing readable travels on the wire, keys included.
#   Open mode:   keys derived from the server PUBLIC key — possessing it is the
#                credential, no identity.
#   Closed mode: per-client ECDH keys; the client key must be in allowed_clients.
#                The server's own key is an implicit client — only the key-file
#                holder can derive its keys (the --notify trigger).

SERVER_PRIV = None          # X25519PrivateKey
SERVER_PUB_B64 = ""
OPEN_AUTH_KEY = None        # HKDF of the public key (open-mode HMAC)
OPEN_ENC_KEY = None         # HKDF of the public key (open-mode AES-GCM)
_CLIENT_KEY_CACHE: Dict[str, Tuple[bytes, bytes]] = {}  # client_pub -> (auth, enc)
_CLIENT_KEY_CACHE_CAP = 1000
_SEEN_SIGS: Dict[str, float] = {}  # verified signature -> expiry (replay cache)
_SEEN_SIGS_CAP = 20000             # hard bound so bursts can't grow it forever
AUTH_WINDOW_SECONDS = 300


def key_file_path() -> str:
    """Private-key file: config's "private_key_file" if set, else "<config>.key"."""
    configured = str(CONFIG.get("private_key_file") or "").strip()
    if configured:
        return os.path.expanduser(configured)
    return str(Path(CONFIG_PATH_USED).with_suffix(".key"))


def _write_key_file(path: str, b64: str):
    p = Path(path)
    if p.parent and not p.parent.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w") as f:
        f.write(b64 + "\n")
    os.chmod(p, 0o600)


def ensure_server_keys():
    """Load the server X25519 private key from its key file, generating one
    (0600) on first run. Key material lives only in that file, never in the
    config."""
    global SERVER_PRIV, SERVER_PUB_B64
    if not HAS_CRYPTO:
        logger.error("python 'cryptography' package missing — install it "
                     "(pip install cryptography); no client can authenticate without it.")
        return
    kpath = key_file_path()
    priv_b64 = ""
    if os.path.exists(kpath):
        try:
            with open(kpath) as f:
                priv_b64 = f.read().strip()
        except Exception as e:
            logger.error(f"Could not read key file {kpath}: {e}")
    SERVER_PRIV = None
    if priv_b64:
        try:
            SERVER_PRIV = X25519PrivateKey.from_private_bytes(base64.b64decode(priv_b64))
        except Exception as e:
            logger.error(f"Invalid private key ({e}); generating a new one.")
    if SERVER_PRIV is None:
        SERVER_PRIV = X25519PrivateKey.generate()
        raw = SERVER_PRIV.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption())
        try:
            _write_key_file(kpath, base64.b64encode(raw).decode())
            logger.info(f"Generated new server private key at {kpath} (mode 600)")
        except Exception as e:
            logger.error(f"Could not write key file {kpath}: {e}")
    pub_raw = SERVER_PRIV.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    SERVER_PUB_B64 = base64.b64encode(pub_raw).decode()
    global OPEN_AUTH_KEY, OPEN_ENC_KEY
    OPEN_AUTH_KEY = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                         info=b"reinbox-open-auth").derive(pub_raw)
    OPEN_ENC_KEY = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                        info=b"reinbox-open-e2e").derive(pub_raw)


def client_registered(client_pub_b64: str) -> bool:
    """The server's own key is an implicit client: deriving its keys needs the
    key file, readable only by same-host tools (--notify)."""
    return (client_pub_b64 == SERVER_PUB_B64
            or client_pub_b64 in (CONFIG.get("allowed_clients") or []))


def derive_client_keys(client_pub_b64: str) -> Tuple[bytes, bytes]:
    """ECDH(server_priv, client_pub) -> (hmac auth key, aes-gcm key). Registered
    keys only: an unknown key must not cost a scalar mult or a cache entry."""
    if not client_registered(client_pub_b64):
        raise ValueError("unregistered client key")
    cached = _CLIENT_KEY_CACHE.get(client_pub_b64)
    if cached:
        return cached
    shared = SERVER_PRIV.exchange(
        X25519PublicKey.from_public_bytes(base64.b64decode(client_pub_b64)))
    auth = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"reinbox-auth").derive(shared)
    enc = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
               info=b"reinbox-e2e").derive(shared)
    # Oldest-first eviction (_CLIENT_KEY_CACHE is insertion-ordered).
    while len(_CLIENT_KEY_CACHE) >= _CLIENT_KEY_CACHE_CAP:
        _CLIENT_KEY_CACHE.pop(next(iter(_CLIENT_KEY_CACHE)), None)
    _CLIENT_KEY_CACHE[client_pub_b64] = (auth, enc)
    return auth, enc


def http_sign_payload(method: str, path: str, query: str, wire_body: bytes) -> str:
    """The signed string (after the timestamp): method, transmitted path, raw
    query, and a hash of the wire body (ciphertext when encrypted). Binding all
    of them stops a captured signature being replayed against a different route,
    target or body. WebSocket connects sign the literal "/ws" instead (no
    method/query/body to bind; the frames are encrypted)."""
    return f"{method}:{path}:{query}:{hashlib.sha256(wire_body).hexdigest()}"


def consume_signature(sig: str) -> bool:
    """One-time signatures: a verified value is remembered for its validity
    window and rejected if seen again (returns False). Expired entries are safe
    to forget (the timestamp check would reject them anyway). Hard-capped: over
    the limit, expired entries drop and — if still over — the oldest evict FIFO
    (a memory-DoS guard; _SEEN_SIGS is insertion-ordered so iteration is oldest
    first)."""
    now = time.time()
    if len(_SEEN_SIGS) >= _SEEN_SIGS_CAP:
        for k, exp in list(_SEEN_SIGS.items()):
            if exp < now:
                _SEEN_SIGS.pop(k, None)
        while len(_SEEN_SIGS) >= _SEEN_SIGS_CAP:
            _SEEN_SIGS.pop(next(iter(_SEEN_SIGS)), None)
    if sig in _SEEN_SIGS:
        return False
    _SEEN_SIGS[sig] = now + 2 * AUTH_WINDOW_SECONDS
    return True


def verify_client_signature(client_pub: str, ts: str, sig: str, payload: str) -> bool:
    if not client_registered(client_pub):
        return False
    try:
        if abs(time.time() - int(ts) / 1000.0) > AUTH_WINDOW_SECONDS:
            return False
        auth_key, _ = derive_client_keys(client_pub)
        expected = hmac.new(auth_key, f"{ts}:{payload}".encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, sig)
    except Exception:
        return False


def verify_open_signature(ts: str, sig: str, payload: str) -> bool:
    """Open scheme: HMAC key derived from the server public key, so a valid
    signature proves the caller knows it. Rejected on closed servers."""
    if OPEN_AUTH_KEY is None or not CONFIG.get("open_server", True):
        return False
    try:
        if abs(time.time() - int(ts) / 1000.0) > AUTH_WINDOW_SECONDS:
            return False
        expected = hmac.new(OPEN_AUTH_KEY, f"{ts}:{payload}".encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, sig)
    except Exception:
        return False


def payload_enc_key(client_pub: Optional[str]) -> bytes:
    """Per-client ECDH key for closed-style requests, the public-key-derived key
    for open-style ones."""
    if client_pub:
        return derive_client_keys(client_pub)[1]
    return OPEN_ENC_KEY


def encrypt_payload(client_pub: Optional[str], plaintext: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(payload_enc_key(client_pub)).encrypt(nonce, plaintext, None)


def decrypt_payload(client_pub: Optional[str], blob: bytes) -> bytes:
    return AESGCM(payload_enc_key(client_pub)).decrypt(blob[:12], blob[12:], None)


def now_ms() -> int:
    return int(time.time() * 1000)


def _forget_run(session_id: str):
    """Drop every trace of a run from memory, once. The end-of-stream sentinel
    releases live viewers waiting on a queue that will never deliver again."""
    RUNNING_PROCESSES.pop(session_id, None)
    ACTIVE_RUNS.discard(session_id)
    push_stream(session_id, None)
    STREAM_SUBSCRIBERS.pop(session_id, None)
    LIVE_STEPS.pop(session_id, None)


async def stop_run(session_id: str, grace: float = 3.0, interrupted: bool = True) -> bool:
    """Stop a session's agent and forget the run. The agent owns its process
    group and may ignore SIGTERM, so this escalates to SIGKILL and waits for the
    process to be reaped before returning. Returns True if one was running."""
    proc = RUNNING_PROCESSES.get(session_id)
    if proc is None:
        _forget_run(session_id)
        return False
    try:
        pgid = os.getpgid(proc.pid)
    except (ProcessLookupError, PermissionError):
        pgid = None
    if pgid is not None:
        try:
            os.killpg(pgid, signal.SIGTERM)
            logger.info(f"Terminated process group for session {session_id} (pid {proc.pid})")
        except (ProcessLookupError, PermissionError):
            pass
    try:
        # Also reaps, so no zombie is left behind to confuse a later signal.
        await asyncio.wait_for(proc.wait(), grace)
    except (asyncio.TimeoutError, TimeoutError):
        if pgid is not None:
            try:
                os.killpg(pgid, signal.SIGKILL)
                logger.warning(f"Agent group for {session_id} ignored SIGTERM — killed")
            except (ProcessLookupError, PermissionError):
                pass
        try:
            await asyncio.wait_for(proc.wait(), grace)
        except Exception as e:
            logger.error(f"Agent for {session_id} would not die: {e}")
    except Exception as e:
        logger.error(f"Waiting on agent for {session_id} failed: {e}")
    _forget_run(session_id)
    if interrupted:
        mark_session_interrupted(session_id)
    return True


def repair_stale_active_sessions():
    """Rows left 'active' by a process that died: nothing runs them now, and
    reconcile skips active rows. Runs before the first reconcile, while
    RUNNING_PROCESSES is necessarily empty."""
    try:
        conn = get_db()
        cur = conn.execute("UPDATE sessions SET status = 'cancelled' WHERE status = 'active'")
        conn.commit()
        if cur.rowcount:
            logger.info(f"Marked {cur.rowcount} interrupted session(s) from a previous run")
        conn.close()
    except Exception as e:
        logger.error(f"Could not repair stale active sessions: {e}")


def mark_session_interrupted(session_id: str):
    """A run that died without producing a result: 'active' reads as "still
    working" in the client, and reconcile skips active rows."""
    try:
        conn = get_db()
        conn.execute("""UPDATE sessions SET status = 'cancelled', updated_at = ?
                        WHERE id = ? AND status = 'active'""", (now_ms(), session_id))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Could not mark {session_id} interrupted: {e}")


def claude_project_dirs(abs_folder: str) -> List[str]:
    """All candidate <claude_home>/projects/<ident> dirs for a workspace path."""
    dirs = []
    for base in claude_home_dirs():
        for ident in (get_claude_project_identifier(abs_folder),
                      abs_folder.strip("/").replace("/", "-")):
            dirs.append(os.path.join(base, "projects", ident))
    return dirs


def resolve_in_root(rel_path: str) -> Optional[str]:
    """Resolve a scoped (no leading /) path strictly inside root_dir; None if it
    escapes. Uses commonpath so a sibling like '/root-evil' can't pass as a
    prefix match."""
    if rel_path is None or os.path.isabs(rel_path):
        return None
    root = root_dir()
    target = os.path.realpath(os.path.join(root, rel_path))
    try:
        if os.path.commonpath([root, target]) != root:
            return None
    except ValueError:
        return None
    return target


def resolve_session_folder(folder: Optional[str],
                           agent_cfg: Optional[dict] = None) -> Optional[str]:
    """Absolute run directory for a folder value. No leading / -> scoped, inside
    root_dir. Leading / -> full path, honored only for a global-scope agent (or,
    with no agent in play — artifacts — if any agent is global)."""
    if folder and os.path.isabs(folder):
        ok = agent_scope_global(agent_cfg) if agent_cfg else any_agent_global()
        if not ok:
            return None
        real = os.path.realpath(folder)
        return real if os.path.isdir(real) else None
    return resolve_in_root(folder or "")


def abs_folder_path(folder: Optional[str]) -> str:
    """Filesystem path for a folder: itself when absolute (global), else
    root_dir/<folder>."""
    f = folder or ""
    if os.path.isabs(f):
        return os.path.normpath(f)
    return os.path.normpath(os.path.join(root_dir(), f))


def get_db():
    db_path = CONFIG.get("db_path", os.path.expanduser("~/reinbox.db"))
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    # Both pragmas are per-connection, and foreign_keys is silently ignored
    # inside a transaction: they belong here, before any statement runs.
    # ON DELETE CASCADE carries a session's messages and attachments with it.
    conn.execute("PRAGMA foreign_keys=ON")
    # A writer waits up to 5s for a busy database before it gives up.
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,           -- stable app-assigned id; never changes
        subject TEXT,
        folder TEXT,
        model TEXT,
        thinking_level TEXT,
        status TEXT, -- active, completed, cancelled, archived
        last_message_by TEXT, -- me, claude
        is_read INTEGER DEFAULT 1, -- 1=read, 0=unread
        created_at INTEGER,
        updated_at INTEGER,
        claude_session_id TEXT, -- the CLI's real session id, for --resume / transcript lookup
        agent TEXT,
        origin TEXT DEFAULT 'app', -- app (created here) | external (imported)
        -- mtime of the backing transcript, so a CLI-side resume is picked up
        transcript_mtime INTEGER DEFAULT 0,
        -- set once a user renames, so a later agent aiTitle won't clobber it
        subject_locked INTEGER DEFAULT 0
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS messages (
        id TEXT PRIMARY KEY,
        session_id TEXT,
        sender TEXT, -- me, claude
        timestamp INTEGER,
        summary_output TEXT,
        expanded_thoughts TEXT, -- JSON array of parsed tool/thought objects
        carried INTEGER DEFAULT 0, -- 1 = copied from a forked source; hidden in flat lists
        FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
    )
    """)
    # Per-turn effort is NOT persisted per message (Claude Code doesn't track it);
    # only the session's latest is kept in sessions.thinking_level.
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS attachments (
        id TEXT PRIMARY KEY,
        session_id TEXT,
        message_id TEXT,
        name TEXT,
        media_type TEXT,
        size INTEGER,
        src_path TEXT,
        data BLOB,
        inline INTEGER DEFAULT 0,  -- 1: explicitly SENT (SendUserFile) -> bubble; 0: viewed -> step link
        FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
    )
    """)
    # The session list orders by updated_at and reads each session's newest
    # message; the thread view and the fork copy read one message's row set.
    cursor.execute("""
    CREATE INDEX IF NOT EXISTS idx_sessions_updated ON sessions(updated_at DESC)
    """)
    cursor.execute("""
    CREATE INDEX IF NOT EXISTS idx_messages_session_time ON messages(session_id, timestamp)
    """)
    cursor.execute("""
    CREATE INDEX IF NOT EXISTS idx_attachments_message ON attachments(message_id)
    """)
    conn.commit()
    conn.close()
    logger.info("Database initialized successfully.")


def get_claude_project_identifier(abs_path: str) -> str:
    # Claude's ~/.claude/projects/ dir name: / in the absolute path becomes -
    p = abs_path.strip("/")
    return "-" + p.replace("/", "-").replace(".", "-")


def find_session_jsonl(session_id: str, folder_rel: str) -> Optional[str]:
    """Exact-match transcript lookup only — a wrong mtime guess would let the
    delete endpoint remove someone else's transcript."""
    if not is_safe_id(session_id):
        return None
    folder_rel = folder_rel or ""
    abs_folder = folder_rel if os.path.isabs(folder_rel) else abs_folder_path(folder_rel)

    for pdir in claude_project_dirs(abs_folder):
        candidate = os.path.join(pdir, f"{session_id}.jsonl")
        if os.path.isfile(candidate):
            return candidate
    return None


def get_real_session_id(app_id: str) -> Optional[str]:
    """App session id -> the CLI's real session id (Claude uuid / codex thread
    id) for resume."""
    conn = get_db()
    try:
        row = conn.execute("SELECT claude_session_id FROM sessions WHERE id = ?", (app_id,)).fetchone()
    finally:
        conn.close()
    return row["claude_session_id"] if row and row["claude_session_id"] else None


def _iso_to_ms(value) -> int:
    """Claude transcripts use ISO-8601 timestamps; the app expects epoch ms."""
    if isinstance(value, (int, float)):
        return int(value if value > 1e12 else value * 1000)
    if isinstance(value, str):
        try:
            return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() * 1000)
        except Exception:
            pass
    return now_ms()


def _truncate(text: str, limit: int = 2000) -> str:
    text = text.strip()
    return text if len(text) <= limit else text[:limit] + " …"


def content_blocks_to_steps(blocks, ts_ms: int) -> List[dict]:
    """Claude content blocks -> the app's step model: thought (thinking), call
    (tool_use), response (tool_result), message (text)."""
    steps = []
    if isinstance(blocks, str):
        if blocks.strip():
            steps.append({"type": "message", "timestamp": ts_ms, "content": _truncate(blocks)})
        return steps
    if not isinstance(blocks, list):
        return steps
    for block in blocks:
        if not isinstance(block, dict):
            continue
        btype = block.get("type")
        if btype == "thinking" and block.get("thinking"):
            steps.append({"type": "thought", "timestamp": ts_ms, "content": _truncate(block["thinking"])})
        elif btype == "text" and block.get("text", "").strip():
            steps.append({"type": "message", "timestamp": ts_ms, "content": _truncate(block["text"])})
        elif btype == "tool_use":
            try:
                arg_str = json.dumps(block.get("input", {}), ensure_ascii=False)
            except Exception:
                arg_str = str(block.get("input"))
            steps.append({"type": "call", "timestamp": ts_ms,
                          "content": f"{block.get('name', 'tool')} {_truncate(arg_str, 1200)}"})
        elif btype == "tool_result":
            content = block.get("content")
            if isinstance(content, list):
                content = " ".join(c.get("text", "") for c in content if isinstance(c, dict))
            # Skip text-less embedded-media results: a bare dot on a blank line.
            if str(content or "").strip():
                steps.append({"type": "response", "timestamp": ts_ms, "content": _truncate(str(content or ""), 1200)})
    return steps


MAX_PROMPT_CHARS = 500_000  # bounds a single-request memory hit
MAX_ATTACHMENT_BYTES = 8 * 1024 * 1024
# Same bound for artifacts: every payload must buffer-and-encrypt in memory.
MAX_ARTIFACT_BYTES = 8 * 1024 * 1024
_MEDIA_EXT = {"image/png": ".png", "image/jpeg": ".jpg", "image/gif": ".gif",
              "image/webp": ".webp", "image/svg+xml": ".svg", "application/pdf": ".pdf"}


def _embedded_block_to_attachment(b, src_path: Optional[str]) -> Optional[dict]:
    """A base64 image/document content block -> attachment record (raw bytes)."""
    if not isinstance(b, dict) or b.get("type") not in ("image", "document"):
        return None
    src = b.get("source") or {}
    if src.get("type", "base64") != "base64" or not src.get("data"):
        return None
    try:
        raw = base64.b64decode(src["data"])
    except Exception:
        return None
    if not raw or len(raw) > MAX_ATTACHMENT_BYTES:
        return None
    media = src.get("media_type") or "application/octet-stream"
    name = os.path.basename(src_path) if src_path else f"attachment{_MEDIA_EXT.get(media, '')}"
    return {"name": name, "media_type": media, "data": raw,
            "size": len(raw), "path": src_path or ""}


def data_url_to_attachment(url: str, src_path: Optional[str]) -> Optional[dict]:
    """A data: URL -> attachment record (codex embeds viewed images as
    input_image items with data URLs)."""
    if not isinstance(url, str) or not url.startswith("data:"):
        return None
    head, _, b64 = url.partition(",")
    if not b64:
        return None
    media = head[5:].split(";")[0] or "application/octet-stream"
    try:
        raw = base64.b64decode(b64)
    except Exception:
        return None
    if not raw or len(raw) > MAX_ATTACHMENT_BYTES:
        return None
    name = os.path.basename(src_path) if src_path else f"attachment{_MEDIA_EXT.get(media, '')}"
    return {"name": name, "media_type": media, "data": raw,
            "size": len(raw), "path": src_path or ""}


def blocks_to_attachments(blocks, tool_paths: Optional[Dict[str, str]] = None) -> List[dict]:
    """Embedded binary blocks in Claude content -> attachment records (a Read of
    an image/PDF lands as a base64 block in the tool_result). tool_paths maps
    tool_use_id -> the Read's file path so the attachment keeps its filename."""
    out: List[dict] = []
    if not isinstance(blocks, list):
        return out
    for block in blocks:
        if not isinstance(block, dict):
            continue
        if block.get("type") == "tool_result":
            hint = (tool_paths or {}).get(block.get("tool_use_id") or "")
            inner = block.get("content")
            if isinstance(inner, list):
                for b in inner:
                    att = _embedded_block_to_attachment(b, hint)
                    if att:
                        out.append(_name_from_last_read(att, tool_paths))
        else:
            # Bare embed, no tool_use_id (a PDF Read): name it from the last Read.
            att = _embedded_block_to_attachment(block, None)
            if att:
                out.append(_name_from_last_read(att, tool_paths))
    return out


def _name_from_last_read(att: dict, tool_paths: Optional[Dict[str, str]]) -> dict:
    """For an embedded block with no id-matched source path, adopt the last Read
    file's name — but only if its extension agrees with the block's media type
    (never name a PNG after an unrelated Read)."""
    last = (tool_paths or {}).get("__last__")
    if not last or att.get("path"):
        return att
    ext = os.path.splitext(last)[1].lower()
    expected = _MEDIA_EXT.get(att["media_type"])
    if expected and (ext == expected or (expected == ".jpg" and ext == ".jpeg")):
        att["name"] = os.path.basename(last)
        att["path"] = last
    return att


# Explicitly SENT files embed their bytes, so they survive the source being
# deleted. A file too big to embed is skipped: a response is encrypted whole in
# memory, so its bytes could not be served anyway.
MAX_SENT_EMBED_BYTES = MAX_ATTACHMENT_BYTES


def sent_file_attachments(blocks) -> List[dict]:
    """Explicit attach intent: a SendUserFile tool_use (some Claude harnesses)
    names files the agent chose to SEND to the user — unlike an embedded Read,
    which is just the agent looking at a file."""
    out: List[dict] = []
    if not isinstance(blocks, list):
        return out
    for b in blocks:
        if not (isinstance(b, dict) and b.get("type") == "tool_use"
                and b.get("name") == "SendUserFile"):
            continue
        for fp in (b.get("input") or {}).get("files") or []:
            if not isinstance(fp, str) or not fp:
                continue
            try:
                if not os.path.isfile(fp):
                    continue
                size = os.path.getsize(fp)
                if size > MAX_SENT_EMBED_BYTES:
                    logger.info(f"Sent file {fp} is {size} bytes — too big to attach")
                    continue
                with open(fp, "rb") as fh:
                    data = fh.read()
                media = mimetypes.guess_type(fp)[0] or "application/octet-stream"
                out.append({"name": os.path.basename(fp), "media_type": media,
                            "data": data, "size": size, "path": fp, "sent": True})
            except Exception:
                continue
    return out


def note_tool_paths(blocks, tool_paths: Dict[str, str]):
    """Record tool_use id -> file path for file-reading tools, to name any
    attachment their result embeds. "__last__" tracks the most recent read for
    embeds that arrive without a tool_use_id."""
    if not isinstance(blocks, list):
        return
    for b in blocks:
        if isinstance(b, dict) and b.get("type") == "tool_use":
            inp = b.get("input") or {}
            path = inp.get("file_path") or inp.get("path") or inp.get("notebook_path")
            if b.get("id") and isinstance(path, str) and path:
                tool_paths[b["id"]] = path
                tool_paths["__last__"] = path


def dedup_attachments(atts: List[dict]) -> List[dict]:
    """A file read twice in a turn embeds twice — keep one per (name, size). If
    any duplicate was explicitly SENT, the kept record counts as sent."""
    seen: Dict[tuple, dict] = {}
    out = []
    for a in atts:
        key = (a["name"], a["size"])
        if key not in seen:
            seen[key] = a
            out.append(a)
        elif a.get("sent") and not seen[key].get("sent"):
            seen[key]["sent"] = True
            if seen[key].get("data") is None:
                seen[key]["data"] = a.get("data")
    return out


def insert_attachments(cursor, session_id: str, message_id: str, atts: Optional[List[dict]]):
    for a in dedup_attachments(atts or []):
        cursor.execute("""INSERT INTO attachments
            (id, session_id, message_id, name, media_type, size, src_path, data, inline)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (str(uuid.uuid4()), session_id, message_id, a["name"], a["media_type"],
             a["size"], a.get("path", ""), a.get("data"),
             1 if a.get("sent") else 0))


def parse_jsonl_thoughts(jsonl_path: str) -> List[dict]:
    """Parse Claude Code's transcript (user/assistant entries with
    message.content arrays) into the app's step list."""
    if not jsonl_path or not os.path.exists(jsonl_path):
        return []

    steps = []
    try:
        with open(jsonl_path, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                except Exception:
                    continue
                entry_type = data.get("type")
                if entry_type not in ("user", "assistant"):
                    continue
                msg = data.get("message") or {}
                ts_ms = _iso_to_ms(data.get("timestamp"))
                steps.extend(content_blocks_to_steps(msg.get("content"), ts_ms))
    except Exception as e:
        logger.error(f"Error parsing session JSONL: {e}")
    return steps


def extract_ai_title(jsonl_path: str) -> Optional[str]:
    if not jsonl_path or not os.path.exists(jsonl_path):
        return None
    try:
        with open(jsonl_path, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                except Exception:
                    continue
                for key in ("aiTitle", "title", "summary"):
                    if isinstance(data.get(key), str) and data[key].strip():
                        return data[key].strip()
    except Exception as e:
        logger.error(f"Error extracting aiTitle: {e}")
    return None


def subject_from_prompt(prompt: Optional[str]) -> str:
    """A Gmail-style subject line derived from the first line of a prompt."""
    if not prompt:
        return "Untitled Session"
    first = prompt.strip().splitlines()[0].strip()
    return (first[:60] + "…") if len(first) > 60 else (first or "Untitled Session")


def extract_claude_prompt(jsonl_path: str) -> Optional[str]:
    """First real user prompt in a Claude transcript — the imported session's
    original message (skips meta entries and injected <system>/<command>)."""
    try:
        with open(jsonl_path, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                except Exception:
                    continue
                if data.get("type") != "user" or data.get("isMeta"):
                    continue
                content = (data.get("message") or {}).get("content")
                text = None
                if isinstance(content, str):
                    text = content
                elif isinstance(content, list):
                    for b in content:
                        if isinstance(b, dict) and b.get("type") == "text" and b.get("text"):
                            text = b["text"]
                            break
                if text and text.strip() and not text.lstrip().startswith("<"):
                    return text.strip()
    except Exception:
        pass
    return None


def parse_claude_turns(jsonl_path: str) -> Tuple[List[dict], Optional[str]]:
    """Split a Claude transcript into conversation turns so an imported session
    reads like an app thread instead of one folded blob:
      me turn     = each real user prompt (meta / injected <command> skipped)
      claude turn = all the agent did until the next prompt (steps + last
                    assistant text as the reply summary).
    Also returns the model recorded in the transcript."""
    turns: List[dict] = []
    cur: Optional[dict] = None
    model: Optional[str] = None
    tool_paths: Dict[str, str] = {}  # tool_use id -> file path (names attachments)

    def close():
        nonlocal cur
        if cur and (cur["steps"] or cur["summary"]):
            turns.append({"sender": "claude", "timestamp": cur["ts"],
                          "summary": cur["summary"] or "(no output)",
                          "steps": cur["steps"],
                          "attachments": cur.get("attachments") or []})
        cur = None

    try:
        with open(jsonl_path, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                except Exception:
                    continue
                etype = data.get("type")
                if etype not in ("user", "assistant"):
                    continue
                msg = data.get("message") or {}
                content = msg.get("content")
                ts = _iso_to_ms(data.get("timestamp"))
                if etype == "user":
                    text = None
                    if not data.get("isMeta"):
                        if isinstance(content, str):
                            text = content
                        elif isinstance(content, list):
                            for b in content:
                                if isinstance(b, dict) and b.get("type") == "text" and b.get("text"):
                                    text = b["text"]
                                    break
                    if text and text.strip() and not text.lstrip().startswith("<"):
                        close()
                        turns.append({"sender": "me", "timestamp": ts,
                                      "summary": text.strip(), "steps": []})
                        continue
                    # tool results and meta entries belong to the agent's turn
                    steps = [s for s in content_blocks_to_steps(content, ts)
                             if s["type"] == "response"]
                    atts = blocks_to_attachments(content, tool_paths)
                    if steps or atts:
                        if cur is None:
                            cur = {"ts": ts, "steps": [], "summary": None, "attachments": []}
                        cur["ts"] = ts
                        cur["steps"].extend(steps)
                        cur.setdefault("attachments", []).extend(atts)
                else:  # assistant
                    model = msg.get("model") or model
                    if cur is None:
                        cur = {"ts": ts, "steps": [], "summary": None, "attachments": []}
                    cur["ts"] = ts
                    note_tool_paths(content, tool_paths)
                    cur.setdefault("attachments", []).extend(sent_file_attachments(content))
                    cur["steps"].extend(content_blocks_to_steps(content, ts))
                    # Full (untruncated) reply text for the bubble
                    if isinstance(content, list):
                        for b in content:
                            if isinstance(b, dict) and b.get("type") == "text" \
                                    and b.get("text", "").strip():
                                cur["summary"] = b["text"].strip()
    except Exception as e:
        logger.error(f"Error splitting Claude transcript into turns: {e}")
    close()
    return turns, model


def extract_claude_last_reply(jsonl_path: str) -> Optional[str]:
    """Last assistant text block in a Claude transcript — the reply preview for
    imported sessions."""
    last = None
    try:
        with open(jsonl_path, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                except Exception:
                    continue
                if data.get("type") != "assistant":
                    continue
                content = (data.get("message") or {}).get("content")
                if isinstance(content, list):
                    for b in content:
                        if isinstance(b, dict) and b.get("type") == "text" and b.get("text", "").strip():
                            last = b["text"].strip()
    except Exception:
        pass
    return last


def extract_claude_cwd(jsonl_path: str) -> Optional[str]:
    """Claude transcripts carry a cwd on most entries; return the first one."""
    try:
        with open(jsonl_path, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                except Exception:
                    continue
                if isinstance(data.get("cwd"), str) and data["cwd"]:
                    return data["cwd"]
    except Exception:
        pass
    return None


# codex rollouts (<codex home>/sessions/**/rollout-*.jsonl) are self-describing:
# session_meta has id + cwd, turn_context the model, event_msg the conversation.

def codex_session_roots() -> List[str]:
    roots = [os.path.join(h, "sessions") for h in codex_home_dirs()]
    return [r for r in roots if os.path.isdir(r)]


def codex_rollout_cwd(path: str) -> Optional[str]:
    """Cheap peek at session_meta (first non-blank line) for the cwd, so
    out-of-workspace rollouts are skipped without a full parse."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                data = json.loads(line)
                if data.get("type") == "session_meta":
                    return (data.get("payload") or {}).get("cwd")
                return None  # session_meta is always first; bail otherwise
    except Exception:
        return None
    return None


def find_codex_rollout(thread_id: str) -> Optional[str]:
    """Locate a codex thread's rollout file across the session stores."""
    if not is_safe_id(thread_id):
        return None
    for root in codex_session_roots():
        for dirpath, _dirs, files in os.walk(root):
            for fn in files:
                if fn.startswith("rollout-") and fn.endswith(f"-{thread_id}.jsonl"):
                    return os.path.join(dirpath, fn)
    return None


def codex_rollout_run_info(thread_id: str) -> Tuple[Optional[str], Optional[str], List[dict]]:
    """(model, effort, last-turn attachments) of a codex run, read from its
    rollout — the --json stdout stream states none of them. Effort is the
    latest turn_context value (codex tracks it per turn)."""
    path = find_codex_rollout(thread_id)
    if not path:
        return None, None, []
    rec = parse_codex_rollout(path)
    if not rec:
        return None, None, []
    turns = rec.get("turns") or []
    last_claude = next((t for t in reversed(turns) if t["sender"] == "claude"), None)
    atts = (last_claude or {}).get("attachments") or []
    return rec.get("model"), rec.get("effort"), atts


def _prune_empty_dirs(path: str, stop_at: str):
    """Remove `path` and each empty parent, walking up until `stop_at`."""
    path = os.path.abspath(path)
    stop_at = os.path.abspath(stop_at)
    while path.startswith(stop_at) and path != stop_at and os.path.isdir(path):
        try:
            os.rmdir(path)  # only succeeds if empty
        except OSError:
            break
        path = os.path.dirname(path)


def delete_claude_session_files(real_id: str, folder_rel: str):
    """Remove every Claude Code trace of a session (by real id): transcript,
    per-session sidecar dirs, and any now-empty workspace project dir. Memory
    dirs with content are preserved."""
    if not is_safe_id(real_id):
        return
    import glob as _glob

    # 1) transcript — found by id across ALL project dirs (a stale stored folder
    #    can't strand it).
    proj_dirs = set()
    for root in claude_home_dirs():
        for jsonl in _glob.glob(os.path.join(root, "projects", "*", f"{real_id}.jsonl")):
            proj_dirs.add(os.path.dirname(jsonl))
            try:
                os.remove(jsonl)
                logger.info(f"Deleted transcript {jsonl}")
            except Exception as e:
                logger.error(f"Failed to delete transcript {jsonl}: {e}")
        # Per-session subdir inside a project dir (tool-results, etc.)
        for sdir in _glob.glob(os.path.join(root, "projects", "*", real_id)):
            if os.path.isdir(sdir):
                proj_dirs.add(os.path.dirname(sdir))
                shutil.rmtree(sdir, ignore_errors=True)
                logger.info(f"Deleted session dir {sdir}")

    # 2) per-session sidecar files/dirs, named "<id>" or "<id>" plus a delimited
    #    suffix ("<id>-agent-<id>.json"). The delimiter keeps a short id from
    #    matching a longer neighbour ("a" vs "abc-...").
    for root in claude_home_dirs():
        for sub in ("session-env", "file-history", "tasks", "todos", "shell-snapshots"):
            matches = [m for m in _glob.glob(os.path.join(root, sub, f"{real_id}*"))
                       if os.path.basename(m) == real_id
                       or os.path.basename(m)[len(real_id):len(real_id) + 1] in ("-", ".")]
            for match in matches:
                try:
                    if os.path.isdir(match):
                        shutil.rmtree(match, ignore_errors=True)
                    else:
                        os.remove(match)
                    logger.info(f"Deleted {match}")
                except Exception as e:
                    logger.error(f"Failed to delete {match}: {e}")

    # 3) prune leftover project dirs once their last transcript is gone, keeping
    #    any memory/ with content. Folder-derived dirs included, so an
    #    already-emptied project dir is pruned too.
    if folder_rel is not None:
        abs_folder = folder_rel if os.path.isabs(folder_rel) else abs_folder_path(folder_rel)
        proj_dirs.update(d for d in claude_project_dirs(abs_folder) if os.path.isdir(d))
    for proj_dir in proj_dirs:
        if not os.path.isdir(proj_dir):
            continue
        if any(f.endswith(".jsonl") for f in os.listdir(proj_dir)):
            continue
        mem = os.path.join(proj_dir, "memory")
        if os.path.isdir(mem) and not os.listdir(mem):
            try:
                os.rmdir(mem)
            except OSError:
                pass
        if not os.listdir(proj_dir):
            try:
                os.rmdir(proj_dir)
                logger.info(f"Removed empty project dir {proj_dir}")
            except OSError:
                pass


def delete_codex_session_files(thread_id: str) -> int:
    """Remove every on-disk trace of a codex thread: rollout .jsonl, its
    .artifacts/ dir, its history.jsonl entries, and clone-specific hook
    snapshots. Returns the number of rollout files removed."""
    removed = 0
    if not is_safe_id(thread_id):
        return 0
    for root in codex_session_roots():
        for dirpath, _dirs, files in os.walk(root):
            for fn in files:
                if not (fn.startswith("rollout-") and fn.endswith(f"-{thread_id}.jsonl")):
                    continue
                path = os.path.join(dirpath, fn)
                try:
                    os.remove(path)
                    removed += 1
                    logger.info(f"Deleted rollout {path}")
                except Exception as e:
                    logger.error(f"Failed to delete rollout {path}: {e}")
                shutil.rmtree(path[:-len(".jsonl")] + ".artifacts", ignore_errors=True)
                _prune_empty_dirs(dirpath, root)  # the YYYY/MM/DD date dirs
        # Per-store prompt history (~/.trae/cli/history.jsonl, ~/.codex/history.jsonl)
        hist = os.path.join(os.path.dirname(root), "history.jsonl")
        if os.path.isfile(hist):
            try:
                with open(hist, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                kept = [l for l in lines if f'"session_id":"{thread_id}"' not in l]
                if len(kept) != len(lines):
                    with open(hist, "w", encoding="utf-8") as f:
                        f.writelines(kept)
            except Exception as e:
                logger.error(f"Failed pruning history.jsonl: {e}")
    # clone-specific (trae) hook turn-snapshots: "<thread_id>-<turn_id>.json"
    import glob as _glob
    for snapdir in _glob.glob(os.path.expanduser("~/.trae/hooks/*/turn-snapshots")):
        for fn in os.listdir(snapdir):
            if fn.startswith(f"{thread_id}-") or fn == thread_id:
                try:
                    os.remove(os.path.join(snapdir, fn))
                except Exception:
                    pass
    return removed


def parse_codex_rollout(path: str) -> Optional[dict]:
    """Parse a codex rollout file into a normalized session record."""
    thread_id = cwd = model = effort = None
    first_user = last_agent = None
    steps: List[dict] = []
    seen_msgs: Set[str] = set()  # agent text can appear as both event + item
    ts_ms = now_ms()
    turns: List[dict] = []  # mirrors parse_claude_turns' structure
    cur: Optional[dict] = None
    call_paths: Dict[str, str] = {}  # function call_id -> file path (Read of an image)

    def ensure_cur(entry_ts: int) -> dict:
        nonlocal cur
        if cur is None:
            cur = {"ts": entry_ts, "steps": [], "summary": None, "attachments": []}
        cur["ts"] = entry_ts
        return cur

    def close_turn():
        nonlocal cur
        if cur and (cur["steps"] or cur["summary"] or cur.get("attachments")):
            turns.append({"sender": "claude", "timestamp": cur["ts"],
                          "summary": cur["summary"] or "(no output)",
                          "steps": cur["steps"],
                          "attachments": cur.get("attachments") or []})
        cur = None

    def add_step(step: dict, entry_ts: int):
        if not str(step.get("content", "")).strip():
            return  # never emit a bare dot on a blank log line
        steps.append(step)
        ensure_cur(entry_ts)["steps"].append(step)

    def add_agent_message(text: str, entry_ts: int):
        nonlocal last_agent
        last_agent = text
        ensure_cur(entry_ts)["summary"] = text
        if text not in seen_msgs:
            seen_msgs.add(text)
            add_step({"type": "message", "timestamp": entry_ts,
                      "content": _truncate(text)}, entry_ts)
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                except Exception:
                    continue
                dtype = data.get("type")
                p = data.get("payload") or {}
                entry_ts = _iso_to_ms(data.get("timestamp"))
                if dtype == "session_meta":
                    thread_id = p.get("id") or thread_id
                    cwd = p.get("cwd") or cwd
                    ts_ms = _iso_to_ms(p.get("timestamp")) or ts_ms
                elif dtype == "turn_context":
                    model = p.get("model") or model
                    # codex records the reasoning effort per turn — keep the latest
                    effort = p.get("effort") or effort
                    cwd = p.get("cwd") or cwd
                elif dtype == "response_item" and p.get("type") == "message":
                    # Some rollouts carry the conversation only as response_items.
                    texts = [b.get("text") for b in (p.get("content") or [])
                             if isinstance(b, dict) and b.get("text")]
                    text = "\n".join(t for t in texts if t).strip()
                    if text and p.get("role") == "assistant":
                        add_agent_message(text, entry_ts)
                elif dtype == "response_item" and p.get("type") == "function_call":
                    # Remember each Read's file so an embedded image keeps its name.
                    try:
                        args = json.loads(p.get("arguments") or "{}")
                    except Exception:
                        args = {}
                    fp = args.get("file_path") or args.get("path")
                    if p.get("call_id") and isinstance(fp, str) and fp:
                        call_paths[p["call_id"]] = fp
                elif dtype == "response_item" and p.get("type") == "function_call_output":
                    # A Read of an image embeds it as an input_image data: URL.
                    out = p.get("output")
                    if isinstance(out, list):
                        for item in out:
                            if isinstance(item, dict) and item.get("type") == "input_image":
                                att = data_url_to_attachment(
                                    item.get("image_url") or "",
                                    call_paths.get(p.get("call_id") or ""))
                                if att:
                                    ensure_cur(entry_ts).setdefault("attachments", []).append(att)
                elif dtype == "event_msg":
                    et = p.get("type")
                    if et == "user_message" and p.get("message"):
                        if first_user is None:
                            first_user = p["message"]
                        close_turn()
                        turns.append({"sender": "me", "timestamp": entry_ts,
                                      "summary": p["message"], "steps": []})
                    elif et == "agent_reasoning_raw_content" and p.get("text"):
                        add_step({"type": "thought", "timestamp": entry_ts,
                                  "content": _truncate(p["text"])}, entry_ts)
                    elif et == "agent_message" and p.get("message"):
                        add_agent_message(p["message"], entry_ts)
                    elif et in ("exec_command_begin", "exec_command_end") and p.get("command"):
                        add_step({"type": "call", "timestamp": entry_ts,
                                  "content": _truncate(str(p["command"]), 1200)}, entry_ts)
                    elif et == "task_complete" and p.get("last_agent_message"):
                        last_agent = p["last_agent_message"]
                        ensure_cur(entry_ts)
                        if cur["summary"] is None:
                            cur["summary"] = last_agent
    except Exception as e:
        logger.error(f"Error parsing codex rollout {path}: {e}")
        return None
    if not thread_id:
        return None
    close_turn()
    return {
        "id": thread_id, "cwd": cwd, "model": model, "effort": effort,
        "prompt": first_user, "summary": last_agent or "(no output)",
        "steps": steps, "created_at": ts_ms, "turns": turns,
    }


def discover_transcripts() -> Dict[str, dict]:
    """Scan every configured agent's transcript store -> {real_session_id:
    record}. A cwd inside root_dir keeps the canonical scoped (relative) folder;
    one outside keeps its full path if the owning agent is "global", else is
    skipped.
    record = {folder, path, mtime, subject, summary, steps, model, agent_name,
              agent_type, prompt, created_at}."""
    ws_root = root_dir()
    found: Dict[str, dict] = {}

    def folder_for_cwd(abs_cwd: Optional[str], agent_cfg: Optional[dict]) -> Optional[str]:
        """Folder value for a transcript cwd. Inside root_dir the scoped
        (relative) form is used regardless of agent scope — one path string per
        directory. Outside: full path for a global agent, None (skip) for a
        scoped one."""
        if not abs_cwd:
            return None
        real = os.path.realpath(abs_cwd)
        try:
            if os.path.commonpath([ws_root, real]) == ws_root:
                rel = os.path.relpath(real, ws_root)
                return "" if rel == "." else rel
        except ValueError:
            pass
        return real if agent_scope_global(agent_cfg) else None

    for owner, base_home in agent_store_pairs("claude"):
        proj_root = os.path.join(base_home, "projects")
        if not os.path.isdir(proj_root):
            continue
        for proj in os.listdir(proj_root):
            pdir = os.path.join(proj_root, proj)
            if not os.path.isdir(pdir):
                continue
            for fn in os.listdir(pdir):
                if not fn.endswith(".jsonl"):
                    continue
                path = os.path.join(pdir, fn)
                sid = fn[:-6]
                if not is_safe_id(sid):
                    continue
                folder = folder_for_cwd(extract_claude_cwd(path), owner)
                if folder is None:
                    continue
                prompt = extract_claude_prompt(path)
                subject = extract_ai_title(path) \
                    or (subject_from_prompt(prompt) if prompt else "Claude Session")
                found[sid] = {
                    "folder": folder, "path": path,
                    "mtime": int(os.path.getmtime(path) * 1000),
                    "subject": subject, "summary": None, "steps": None,
                    "model": None, "agent_name": owner.get("name", "Claude"),
                    "agent_type": "claude",
                    "prompt": prompt, "created_at": int(os.path.getmtime(path) * 1000),
                }

    for owner, base_home in agent_store_pairs("codex"):
        root = os.path.join(base_home, "sessions")
        if not os.path.isdir(root):
            continue
        for dirpath, _dirs, files in os.walk(root):
            for fn in files:
                if not (fn.startswith("rollout-") and fn.endswith(".jsonl")):
                    continue
                path = os.path.join(dirpath, fn)
                # Cheap cwd peek first; only fully parse rollouts in scope.
                if folder_for_cwd(codex_rollout_cwd(path), owner) is None:
                    continue
                rec = parse_codex_rollout(path)
                if not rec or not is_safe_id(rec["id"]):
                    continue
                folder = folder_for_cwd(rec.get("cwd"), owner)
                if folder is None:
                    continue
                found[rec["id"]] = {
                    "folder": folder, "path": path,
                    "mtime": int(os.path.getmtime(path) * 1000),
                    # codex has no aiTitle — the thread id is the title
                    "subject": rec["id"],
                    "summary": rec.get("summary"), "steps": rec.get("steps"),
                    "turns": rec.get("turns"),
                    "model": rec.get("model"), "effort": rec.get("effort"),
                    "agent_name": owner.get("name", "Codex"),
                    "agent_type": "codex", "prompt": rec.get("prompt"),
                    "created_at": rec.get("created_at"),
                }
    return found


_LAST_RECONCILE = {"ts": 0}
RECONCILE_THROTTLE_MS = 4000


def reconcile_sessions(force: bool = False) -> List[Tuple[str, int]]:
    """Sync the DB with the agents' on-disk transcript stores: import sessions
    created outside the app, refresh ones whose transcript changed externally,
    prune imported ones whose transcript vanished. App-created sessions are
    never pruned (a missing transcript degrades gracefully at resume).
    Returns (session_id, reply_ts_ms) for sessions that gained a fresh agent
    reply — the manual trigger notifies from it."""
    fresh_replies: List[Tuple[str, int]] = []
    if not force and (now_ms() - _LAST_RECONCILE["ts"]) < RECONCILE_THROTTLE_MS:
        return fresh_replies
    _LAST_RECONCILE["ts"] = now_ms()

    try:
        discovered = discover_transcripts()
    except Exception as e:
        logger.error(f"Transcript discovery failed: {e}")
        return fresh_replies

    conn = get_db()
    cur = conn.cursor()
    try:
        rows = cur.execute(
            "SELECT id, claude_session_id, origin, transcript_mtime, status, subject,"
            " subject_locked FROM sessions"
        ).fetchall()

        # An app session re-imported as 'external' (reconcile beat the runner to the
        # real id) loses to the authoritative app row.
        app_real_ids = {r["claude_session_id"] for r in rows
                        if r["origin"] != "external" and r["claude_session_id"]}
        deduped = []
        for r in rows:
            if r["origin"] == "external" and r["id"] in app_real_ids:
                cur.execute("DELETE FROM sessions WHERE id = ?", (r["id"],))
                logger.info(f"Removed duplicate imported session {r['id']} "
                            f"(same underlying thread as an app session)")
            else:
                deduped.append(r)
        rows = deduped

        by_real = {}
        for r in rows:
            real = r["claude_session_id"] or r["id"]
            by_real[real] = r

        for real_id, rec in discovered.items():
            existing = by_real.get(real_id)
            if existing is not None and existing["status"] == "active":
                # Never touch a session mid-run: the runner owns it and would
                # duplicate its replies.
                continue
            # Claude may gain an aiTitle later — sync it unless the user renamed.
            if (existing is not None and existing["origin"] == "external"
                    and not existing["subject_locked"]
                    and rec["subject"] and rec["subject"] != existing["subject"]):
                cur.execute("UPDATE sessions SET subject = ? WHERE id = ?",
                            (rec["subject"], existing["id"]))
            # Backfill the original prompt for reply-only imported threads.
            if (existing is not None and existing["origin"] == "external"
                    and rec.get("prompt")):
                has_me = cur.execute(
                    "SELECT 1 FROM messages WHERE session_id = ? AND sender = 'me' LIMIT 1",
                    (existing["id"],)).fetchone()
                if not has_me:
                    first_ts = cur.execute(
                        "SELECT MIN(timestamp) FROM messages WHERE session_id = ?",
                        (existing["id"],)).fetchone()[0] or now_ms()
                    cur.execute("""INSERT INTO messages
                        (id, session_id, sender, timestamp, summary_output, expanded_thoughts)
                        VALUES (?, ?, 'me', ?, ?, '[]')""",
                        (str(uuid.uuid4()), existing["id"], first_ts - 1, rec["prompt"]))
                    logger.info(f"Backfilled original prompt for imported session {existing['id']}")
            if existing is None:
                # A fresh transcript during a run IS that run — the runner links
                # it, so importing now would duplicate it.
                if RUNNING_PROCESSES and now_ms() - rec["mtime"] < 120000:
                    continue
                if rec["agent_type"] == "claude":
                    turns, tmodel = parse_claude_turns(rec["path"])
                    model = tmodel or rec.get("model")
                else:
                    turns, model = rec.get("turns") or [], rec.get("model")
                ts = (turns[0]["timestamp"] if turns else rec.get("created_at")) or now_ms()
                last_by = turns[-1]["sender"] if turns else "claude"
                cur.execute("""
                INSERT INTO sessions (id, subject, folder, model, thinking_level, status,
                    last_message_by, is_read, created_at, updated_at, claude_session_id,
                    agent, origin, transcript_mtime)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'external', ?)
                """, (real_id, rec["subject"], rec["folder"], model,
                      # codex records the effort; Claude never persists it
                      rec.get("effort") or "default",
                      "completed", last_by, 0, ts, rec["mtime"], real_id,
                      rec["agent_name"], rec["mtime"]))
                if turns:
                    for t in turns:
                        mid = str(uuid.uuid4())
                        cur.execute("""INSERT INTO messages
                            (id, session_id, sender, timestamp, summary_output, expanded_thoughts)
                            VALUES (?, ?, ?, ?, ?, ?)""",
                            (mid, real_id, t["sender"], t["timestamp"],
                             t["summary"], json.dumps(t["steps"])))
                        insert_attachments(cur, real_id, mid, t.get("attachments"))
                else:
                    # Fallback: single-blob import (no parsable turns)
                    summary = rec.get("summary")
                    if summary is None and rec["agent_type"] == "claude":
                        summary = extract_claude_last_reply(rec["path"]) or "(imported session)"
                    if rec.get("prompt"):
                        cur.execute("""INSERT INTO messages
                            (id, session_id, sender, timestamp, summary_output, expanded_thoughts)
                            VALUES (?, ?, 'me', ?, ?, '[]')""",
                            (str(uuid.uuid4()), real_id, ts - 1, rec["prompt"]))
                    cur.execute("""INSERT INTO messages
                        (id, session_id, sender, timestamp, summary_output, expanded_thoughts)
                        VALUES (?, ?, 'claude', ?, ?, ?)""",
                        (str(uuid.uuid4()), real_id, ts, summary or "(imported session)",
                         json.dumps(rec.get("steps") or [])))
                if last_by == "claude":
                    fresh_replies.append((real_id, rec["mtime"]))
                logger.info(f"Imported external session {real_id} ({rec['agent_name']}) "
                            f"in '{rec['folder']}' ({len(turns)} turns)")
            elif not existing["transcript_mtime"] and existing["origin"] != "external":
                # First sighting of an app session's transcript: baseline the mtime
                # WITHOUT appending, so only genuine later edits refresh it.
                cur.execute("UPDATE sessions SET transcript_mtime = ? WHERE id = ?",
                            (rec["mtime"], existing["id"]))
            elif rec["mtime"] > (existing["transcript_mtime"] or 0) and existing["status"] != "active":
                # External resume: append only turns newer than our baseline.
                if rec["agent_type"] == "claude":
                    turns, _tmodel = parse_claude_turns(rec["path"])
                else:
                    turns = rec.get("turns") or []
                sid = existing["id"]
                baseline = existing["transcript_mtime"] or 0
                new_turns = [t for t in turns if t["timestamp"] > baseline]
                if not new_turns and turns:
                    # Timestamps inconclusive — fall back to the last agent turn
                    lastc = next((t for t in reversed(turns) if t["sender"] == "claude"), None)
                    new_turns = [lastc] if lastc else []
                # A merely-touched transcript must not produce a duplicate reply.
                last = cur.execute("""SELECT summary_output FROM messages
                    WHERE session_id = ? AND sender = 'claude'
                    ORDER BY timestamp DESC LIMIT 1""", (sid,)).fetchone()
                got_reply = False
                for t in new_turns:
                    if (t["sender"] == "claude" and last
                            and last["summary_output"] == t["summary"]):
                        continue
                    mid = str(uuid.uuid4())
                    cur.execute("""INSERT INTO messages
                        (id, session_id, sender, timestamp, summary_output, expanded_thoughts)
                        VALUES (?, ?, ?, ?, ?, ?)""",
                        (mid, sid, t["sender"], t["timestamp"],
                         t["summary"], json.dumps(t["steps"])))
                    insert_attachments(cur, sid, mid, t.get("attachments"))
                    got_reply = got_reply or t["sender"] == "claude"
                if got_reply:
                    cur.execute("""UPDATE sessions SET updated_at = ?, transcript_mtime = ?,
                        last_message_by = 'claude', is_read = 0 WHERE id = ?""",
                        (rec["mtime"], rec["mtime"], sid))
                    if rec.get("effort"):  # codex tracks effort per turn
                        cur.execute("UPDATE sessions SET thinking_level = ? WHERE id = ?",
                                    (rec["effort"], sid))
                    fresh_replies.append((sid, rec["mtime"]))
                    logger.info(f"Refreshed session {sid} from externally-updated transcript")
                else:
                    cur.execute("UPDATE sessions SET transcript_mtime = ? WHERE id = ?",
                                (rec["mtime"], sid))

        for r in rows:
            real = r["claude_session_id"] or r["id"]
            if r["origin"] == "external" and real not in discovered:
                cur.execute("DELETE FROM sessions WHERE id = ?", (r["id"],))
                logger.info(f"Pruned imported session {r['id']} (transcript removed externally)")

        conn.commit()
    except Exception as e:
        logger.error(f"reconcile_sessions error: {e}")
        traceback.print_exc()
    finally:
        conn.close()
    return fresh_replies


def unused_session_id(attempts: int = 20) -> str:
    """A short app id no session holds: 32 bits collide eventually."""
    conn = get_db()
    try:
        for _ in range(attempts):
            sid = str(uuid.uuid4())[:8]
            if conn.execute("SELECT 1 FROM sessions WHERE id = ?", (sid,)).fetchone() is None:
                return sid
    finally:
        conn.close()
    # 20 straight collisions is not chance — fall back to a full uuid.
    return str(uuid.uuid4())


def link_real_session_id(app_id: str, real_id: str):
    """Record the CLI's real session id as soon as it is known, so reconcile
    can't mistake the in-flight transcript for a new external session."""
    conn = get_db()
    try:
        conn.execute("UPDATE sessions SET claude_session_id = ? WHERE id = ?",
                     (real_id, app_id))
        # An agent with no aiTitle is titled with its session id, but at create
        # time only the app id exists. Now that the real one is known, show it —
        # matching an imported thread's title. Skipped once the user renames.
        conn.execute("""UPDATE sessions SET subject = ?
                        WHERE id = ? AND subject = ?
                          AND COALESCE(subject_locked, 0) = 0""",
                     (real_id, app_id, app_id))
        conn.commit()
    finally:
        conn.close()


def stream_event_readable(evt: dict) -> List[str]:
    """Human-readable one-liners for the live log stream (passive viewing)."""
    lines = []
    etype = evt.get("type")
    if etype == "system" and evt.get("subtype") == "init":
        lines.append(f"▸ session started (model: {evt.get('model', '?')})\n")
    elif etype == "assistant":
        for block in (evt.get("message") or {}).get("content") or []:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "thinking":
                lines.append("✻ thinking…\n")
            elif block.get("type") == "tool_use":
                lines.append(f"→ {block.get('name', 'tool')}\n")
            elif block.get("type") == "text" and block.get("text", "").strip():
                lines.append(block["text"].strip() + "\n")
    elif etype == "result":
        lines.append(f"✔ finished ({evt.get('subtype', 'success')})\n")
    return lines


def ingest_result_db(session_id: str, claude_session_id: Optional[str], folder: str,
                     subject: Optional[str], model: Optional[str], thinking: Optional[str],
                     prompt: Optional[str], summary: str, steps: List[dict],
                     status: str = "completed", agent: Optional[str] = None,
                     attachments: Optional[List[dict]] = None) -> str:
    """The runner's single write path for a finished turn: append the reply to a
    session. The app-assigned session id never changes; the agent's real id is
    stored separately as claude_session_id for --resume / transcript lookup."""
    conn = get_db()
    cursor = conn.cursor()
    ts = now_ms()
    try:
        cursor.execute("SELECT id, status FROM sessions WHERE id = ?", (session_id,))
        row = cursor.fetchone()
        if row is None and session_id in DELETED_SESSIONS:
            # Deleted after the turn started — a late result must not resurrect it.
            return session_id
        if row is None:
            cursor.execute("""
            INSERT INTO sessions (id, subject, folder, model, thinking_level, status,
                                  last_message_by, is_read, created_at, updated_at,
                                  claude_session_id, agent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (session_id, subject or "External Session", folder, model, thinking,
                  status, "claude", 0, ts, ts, claude_session_id,
                  agent or get_agent(None).get("name")))
            if prompt:
                cursor.execute("""
                INSERT INTO messages (id, session_id, sender, timestamp, summary_output, expanded_thoughts)
                VALUES (?, ?, ?, ?, ?, ?)
                """, (str(uuid.uuid4()), session_id, "me", ts - 1, prompt, "[]"))
        else:
            # Preserve 'cancelled' if the cancel endpoint already marked it
            if row["status"] == "cancelled" and status == "completed":
                status = "cancelled"
            if subject:
                # The aiTitle replaces the prompt-derived subject unless renamed.
                cursor.execute("""
                UPDATE sessions SET subject = ?
                WHERE id = ? AND COALESCE(subject_locked, 0) = 0
                """, (subject, session_id))
            if claude_session_id:
                cursor.execute("UPDATE sessions SET claude_session_id = ? WHERE id = ?",
                               (claude_session_id, session_id))
            # The model actually used replaces a placeholder like "Default (Omit)"
            if model and not is_placeholder(model):
                cursor.execute("UPDATE sessions SET model = ? WHERE id = ?", (model, session_id))
            norm_thinking = thinking if (thinking and not is_placeholder(thinking)) else "default"
            cursor.execute("UPDATE sessions SET thinking_level = ? WHERE id = ?",
                           (norm_thinking, session_id))

        reply_id = str(uuid.uuid4())
        cursor.execute("""
        INSERT INTO messages (id, session_id, sender, timestamp, summary_output, expanded_thoughts)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (reply_id, session_id, "claude", ts, summary, json.dumps(steps)))
        insert_attachments(cursor, session_id, reply_id, attachments)

        # Baseline transcript_mtime to now: the agent wrote its transcript before
        # exiting, and reconcile must not read that as an external edit.
        cursor.execute("""
        UPDATE sessions SET last_message_by = 'claude', updated_at = ?, status = ?,
                            is_read = 0, transcript_mtime = ?
        WHERE id = ?
        """, (ts, status, ts, session_id))

        conn.commit()
    finally:
        conn.close()
    return session_id


def safe_effort(effort: Optional[str]) -> Optional[str]:
    """Effort is a short known vocabulary (minimal/low/…/max), so keeping only
    lowercase letters stops a crafted value injecting into codex's
    `-c model_reasoning_effort="…"` config string."""
    if not effort:
        return None
    cleaned = re.sub(r"[^a-z]", "", str(effort).strip().lower())
    return cleaned or None


def build_claude_command(agent_cfg: dict, prompt: str, resume_real_id: Optional[str],
                         fork: bool, model: Optional[str],
                         effort: Optional[str]) -> List[str]:
    """Hard-coded: `-p`, the stream format the server must parse, and per-turn
    values (model, effort, resume/fork). Everything else — the permission mode
    included — comes from the agent's config `args`."""
    claude_bin = agent_cfg.get("path") or "claude"
    cmd = [claude_bin, "-p", prompt, "--output-format", "stream-json", "--verbose"]
    if model and not is_placeholder(model):
        cmd.extend(["--model", model])
    if effort and not is_placeholder(effort):
        eff = safe_effort(effort)
        if eff:
            cmd.extend(["--effort", eff])
    if resume_real_id:
        cmd.extend(["--resume", resume_real_id])
        if fork:
            cmd.append("--fork-session")
    cmd.extend(agent_cfg.get("args") or [])
    return cmd


def build_codex_command(agent_cfg: dict, prompt: str, resume_id: Optional[str],
                        model: Optional[str], effort: Optional[str]) -> List[str]:
    """Hard-coded: `exec` (plus `resume <id>`), the JSON stream the server must
    parse, the git-check skip (workspace dirs are rarely repos), and per-turn
    model/effort. Everything else — the sandbox/approval bypass included —
    comes from the agent's config `args`."""
    bin_path = agent_cfg.get("path", "codex")
    cmd = [bin_path, "exec"]
    if resume_id:
        cmd.extend(["resume", resume_id])
    cmd.extend(["--json", "--skip-git-repo-check"])
    if model and not is_placeholder(model):
        cmd.extend(["-m", model])
    if effort and not is_placeholder(effort):
        eff = safe_effort(effort)
        if eff:
            # eff is charset-restricted, so it can't break out of the quoted value.
            cmd.extend(["-c", f'model_reasoning_effort="{eff}"'])
    cmd.extend(agent_cfg.get("args") or [])
    # "--" so a prompt starting with "-" can never be parsed as a CLI flag
    cmd.extend(["--", prompt])
    return cmd


def codex_item_to_steps(item: dict, ts_ms: int) -> List[dict]:
    """A codex `item.*` event payload -> the app's step model."""
    steps = []
    itype = item.get("item_type") or item.get("type")
    if itype == "reasoning" and item.get("text"):
        steps.append({"type": "thought", "timestamp": ts_ms, "content": _truncate(item["text"])})
    elif itype == "agent_message" and item.get("text"):
        steps.append({"type": "message", "timestamp": ts_ms, "content": _truncate(item["text"])})
    elif itype == "command_execution":
        if item.get("command"):
            steps.append({"type": "call", "timestamp": ts_ms,
                          "content": _truncate(str(item["command"]), 1200)})
        if item.get("aggregated_output"):
            steps.append({"type": "response", "timestamp": ts_ms,
                          "content": _truncate(str(item["aggregated_output"]), 1200)})
    elif itype == "file_change":
        changes = item.get("changes") or item.get("path") or ""
        steps.append({"type": "call", "timestamp": ts_ms,
                      "content": _truncate(f"file_change {json.dumps(changes, ensure_ascii=False, default=str)}", 1200)})
    elif itype == "mcp_tool_call":
        name = item.get("tool") or item.get("server") or "mcp_tool"
        steps.append({"type": "call", "timestamp": ts_ms, "content": _truncate(str(name), 1200)})
    elif itype == "web_search":
        steps.append({"type": "call", "timestamp": ts_ms,
                      "content": _truncate(f"web_search {item.get('query', '')}", 1200)})
    elif itype == "error" and item.get("message"):
        steps.append({"type": "response", "timestamp": ts_ms, "content": _truncate(item["message"], 1200)})
    return [s for s in steps if s["content"].strip()]


def is_placeholder(val) -> bool:
    if not val:
        return True
    v = str(val).strip().lower()
    return v in ("", "default", "default (omit)", "default (system)", "none", "null")


async def run_agent_command(session_id: str, prompt: str, folder_rel: str,
                            resume_id: Optional[str] = None, fork: bool = False,
                            model: Optional[str] = None, thinking: Optional[str] = None,
                            agent: Optional[str] = None):
    """One agent turn, releasing the run slot however the turn ends. The slot is
    claimed in create_session before this task is scheduled, so a double-submit
    is rejected without a race."""
    try:
        await _run_agent_command(session_id, prompt, folder_rel, resume_id,
                                 fork, model, thinking, agent)
    finally:
        ACTIVE_RUNS.discard(session_id)


async def _run_agent_command(session_id: str, prompt: str, folder_rel: str,
                             resume_id: Optional[str] = None, fork: bool = False,
                             model: Optional[str] = None, thinking: Optional[str] = None,
                             agent: Optional[str] = None):
    """Spawn the configured agent CLI (claude or codex) with JSON stream output;
    the real session id and the step list come from the event stream itself, so
    there is no jsonl guessing."""
    agent_cfg = get_agent(agent)
    abs_folder = resolve_session_folder(folder_rel, agent_cfg)
    if abs_folder is None:
        logger.error(f"Rejected folder outside workspace sandbox: {folder_rel!r}")
        await asyncio.to_thread(
            ingest_result_db, session_id, None, folder_rel, None, model, thinking,
            None, "Rejected: folder escapes the workspace sandbox.", [], "completed", agent)
        return
    os.makedirs(abs_folder, exist_ok=True)

    agent_type = agent_cfg.get("type", "claude")
    agent_name = agent_cfg.get("name", "Claude")

    resume_real_id = get_real_session_id(resume_id) if resume_id else None
    env = os.environ.copy()
    # The CLI must write where discovery reads, so a configured home_dir reaches
    # the process too, not just the scan.
    home_override = str(agent_cfg.get("home_dir") or "").strip()
    if home_override:
        env["CODEX_HOME" if agent_type == "codex" else "CLAUDE_CONFIG_DIR"] = \
            os.path.expanduser(home_override)
    if agent_type == "codex":
        cmd = build_codex_command(agent_cfg, prompt, resume_real_id, model, thinking)
    else:
        # Never --resume an id whose transcript vanished — start fresh instead.
        if resume_real_id and find_session_jsonl(resume_real_id, folder_rel) is None:
            logger.warning(f"Resume transcript for {resume_real_id} not found "
                           f"(folder/file changed externally); starting a fresh session.")
            resume_real_id = None
            fork = False
        cmd = build_claude_command(agent_cfg, prompt, resume_real_id, fork, model, thinking)

    # cmd carries the prompt verbatim; conversation content stays out of
    # stdout/service logs, so only what identifies the run is logged.
    logger.info(f"Running {agent_name} ({cmd[0]}) in {abs_folder}: "
                f"model={model or 'default'} effort={thinking or 'default'} "
                f"resume={resume_real_id or '-'} prompt={len(prompt)} chars")

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=abs_folder,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=env,
            start_new_session=True,  # own process group so cancel can killpg
            # One JSON event can embed a whole file, far past the 64KB default.
            limit=16 * 1024 * 1024,
        )
        RUNNING_PROCESSES[session_id] = process

        real_id: Optional[str] = None
        real_model: Optional[str] = None
        linked_real_id = False
        steps: List[dict] = []
        LIVE_STEPS[session_id] = steps  # live view for /sessions/{id}/live
        result_text: Optional[str] = None
        plain_lines: List[str] = []
        attachments: List[dict] = []      # embedded files (image/pdf Reads)
        tool_paths: Dict[str, str] = {}   # tool_use id -> file path, names them

        def emit(text: str):
            push_stream(session_id, text)

        while True:
            try:
                line = await process.stdout.readline()
            except (asyncio.LimitOverrunError, ValueError):
                # Past even the raised limit: drain the buffer, don't abort the run.
                line = await process.stdout.read(1024 * 1024)
            if not line:
                break
            raw = line.decode("utf-8", errors="replace")
            evt = None
            try:
                evt = json.loads(raw)
            except Exception:
                pass

            if isinstance(evt, dict) and agent_type == "codex":
                etype = evt.get("type", "")
                if etype == "thread.started":
                    real_id = evt.get("thread_id") or real_id
                    emit(f"▸ session started ({agent_name})\n")
                elif etype.startswith("item.") and etype.endswith("completed"):
                    item = evt.get("item") or {}
                    new_steps = codex_item_to_steps(item, now_ms())
                    steps.extend(new_steps)
                    itype = item.get("item_type") or item.get("type")
                    if itype == "agent_message" and item.get("text"):
                        result_text = item["text"]
                        emit(item["text"].strip() + "\n")
                    elif itype == "reasoning":
                        emit("✻ thinking…\n")
                    elif itype == "command_execution" and item.get("command"):
                        emit(f"→ {str(item['command'])[:120]}\n")
                elif etype == "turn.completed":
                    emit("✔ finished\n")
                elif etype in ("turn.failed", "error"):
                    err = (evt.get("error") or {}).get("message") if etype == "turn.failed" \
                        else evt.get("message")
                    if err:
                        plain_lines.append(f"Error: {err}\n")
                        emit(f"✖ {err}\n")
            elif isinstance(evt, dict):
                real_id = evt.get("session_id") or real_id
                etype = evt.get("type")
                if etype == "system" and evt.get("subtype") == "init":
                    real_model = evt.get("model") or real_model
                if etype in ("assistant", "user"):
                    msg = evt.get("message") or {}
                    real_model = msg.get("model") or real_model
                    if etype == "assistant":
                        note_tool_paths(msg.get("content"), tool_paths)
                        attachments.extend(sent_file_attachments(msg.get("content")))
                    else:
                        attachments.extend(blocks_to_attachments(msg.get("content"), tool_paths))
                    steps.extend(content_blocks_to_steps(msg.get("content"), now_ms()))
                elif etype == "result":
                    result_text = evt.get("result") or result_text
                for readable in stream_event_readable(evt):
                    emit(readable)
            else:
                plain_lines.append(raw)
                emit(raw)

            # Persist the real id at once, or reconcile imports the in-flight
            # transcript as a duplicate.
            if real_id and not linked_real_id:
                linked_real_id = True
                await asyncio.to_thread(link_real_session_id, session_id, real_id)

        await process.wait()
        RUNNING_PROCESSES.pop(session_id, None)
        logger.info(f"Agent process finished with return code {process.returncode}")

        if session_id in DELETED_SESSIONS:
            # Deleted mid-shutdown: ingesting would re-create the row — scrub the
            # transcript the dying process re-wrote instead.
            for ident in {i for i in (real_id, session_id) if i}:
                delete_claude_session_files(ident, folder_rel)
                delete_codex_session_files(ident)
            push_stream(session_id, None)
            STREAM_SUBSCRIBERS.pop(session_id, None)
            LIVE_STEPS.pop(session_id, None)
            return

        summary = result_text or "".join(plain_lines).strip() or "(no output)"

        # codex states model/effort only in the rollout (Claude reports the model
        # in its event stream, captured above); its images become attachments.
        if agent_type == "codex" and real_id:
            r_model, r_effort, r_atts = await asyncio.to_thread(codex_rollout_run_info, real_id)
            real_model = real_model or r_model
            if r_effort:
                thinking = r_effort
            if r_atts and not attachments:
                attachments = r_atts

        discovered_title = None
        if agent_type != "codex":
            jsonl_path = find_session_jsonl(real_id, folder_rel) if real_id else None
            if jsonl_path:
                discovered_title = extract_ai_title(jsonl_path)
                if not steps:
                    steps = parse_jsonl_thoughts(jsonl_path)

        await asyncio.to_thread(
            ingest_result_db,
            session_id, real_id, folder_rel, discovered_title,
            real_model or model, thinking, None, summary, steps, "completed",
            agent_name, attachments,
        )

        push_stream(session_id, None)  # end-of-stream for live viewers
        STREAM_SUBSCRIBERS.pop(session_id, None)
        LIVE_STEPS.pop(session_id, None)

        await broadcast_event({
            "type": "session_completed",
            "session_id": session_id,
            "folder": folder_rel,
            "subject": discovered_title or "No Title",
            "output_preview": summary[:200],
            # Enough context for the client to build its "From" line
            "agent": agent_name,
            "model": real_model or model,
            "effort": thinking,
        })

    except asyncio.CancelledError:
        # CancelledError is a BaseException — the handler below does not cover it,
        # and the agent runs detached with permissions bypassed. A cancelled task
        # cannot count on its own awaits resuming, so the stop is shielded.
        logger.warning(f"Run for session {session_id} cancelled — stopping the agent")
        try:
            await asyncio.shield(asyncio.create_task(stop_run(session_id)))
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Could not stop agent for {session_id}: {e}")
        raise
    except Exception as e:
        logger.error(f"Error executing agent: {e}")
        traceback.print_exc()
        # An orphaned run keeps writing its transcript after the session is
        # recorded finished, and reconcile appends the growing tail as duplicate
        # replies. The result below records the outcome, so no interrupt mark.
        await stop_run(session_id, interrupted=False)
        try:
            await asyncio.to_thread(
                ingest_result_db,
                session_id, None, folder_rel, None, model, thinking, None,
                f"Error running agent: {e}", [], "completed", agent,
            )
        except Exception:
            pass


async def broadcast_event(data: dict):
    payload = json.dumps(data)
    to_remove = set()
    # Snapshot: connections churn while we await, and mutating a set mid-iteration
    # raises RuntimeError.
    for ws in list(ACTIVE_CONNECTIONS):
        try:
            await ws.send_text(payload)
        except Exception:
            to_remove.add(ws)

    for ws in to_remove:
        ACTIVE_CONNECTIONS.discard(ws)


try:
    import fastapi
    from fastapi import (FastAPI, WebSocket, WebSocketDisconnect, HTTPException,
                         Query, Depends, Request)
    from fastapi.responses import Response as FastResponse
    from fastapi.middleware.cors import CORSMiddleware
    import uvicorn
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

if HAS_FASTAPI:
    @asynccontextmanager
    async def lifespan(_app):
        yield
        # Agents run detached (own process group) with permissions bypassed, so
        # they outlive the server unless stopped here. Stopping precedes
        # cancelling the runners, so each agent is reaped by a task that can
        # still await; the runners then wind down with nothing left to kill.
        for sid in list(RUNNING_PROCESSES):
            logger.warning(f"Server shutting down — stopping agent for {sid}")
            try:
                await stop_run(sid)
            except Exception as e:
                # One agent's failure must not stop the rest being cleaned up.
                logger.error(f"Failed to stop agent for {sid}: {e}")
        for task in list(RUNNER_TASKS):
            task.cancel()
        if RUNNER_TASKS:
            await asyncio.gather(*RUNNER_TASKS, return_exceptions=True)

    app = FastAPI(title="Reinbox Server", lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    def require_auth(request: Request):
        """Every request carries X-Timestamp + X-Auth: a one-time HMAC over
        "ts:method:path:query:sha256(wire body)", time-window limited and
        replay-rejected. The E2E middleware verifies it (it is the only layer
        that sees the wire body) and records the verdict in the ASGI scope;
        this dependency just enforces it. With X-Client-Key the signature is
        checked against that client's ECDH keys (closed style — registered
        clients, plus the server's own key for the local --notify trigger;
        accepted in both modes). Without it the open scheme applies: the HMAC
        key is derived from the server public key, accepted only on open
        servers."""
        if not HAS_CRYPTO or SERVER_PRIV is None:
            raise HTTPException(status_code=401, detail="Server has no keys (cryptography package missing)")
        if not request.scope.get("reinbox_authed"):
            raise HTTPException(status_code=401, detail="Unauthorized")

    # E2E exemptions, each for a concrete reason:
    #   /server/mode — the pre-auth probe: a client must read it to learn HOW to
    #                  authenticate, so it cannot require the shared key.
    #   /ws          — WebSocket frames are encrypted separately (WrappedSocket).
    E2E_EXEMPT = ("/server/mode", "/ws")

    # Larger than a client could legitimately send — reject before buffering.
    MAX_WIRE_BODY = MAX_ARTIFACT_BYTES + 4 * 1024 * 1024
    # A response is encrypted in one shot, so it is held in memory whole plus a
    # ciphertext copy. Larger ones are refused — a sent-file reference can be
    # hundreds of MB.
    MAX_ENCRYPTED_RESPONSE = MAX_ARTIFACT_BYTES

    class E2EMiddleware:
        """Pure ASGI (so the swapped request body actually reaches the endpoint):
        verify the request signature (which covers the wire body), decrypt
        AES-GCM request bodies, encrypt every 2xx response — with the
        per-client ECDH keys for closed-style requests, the public-key-derived
        keys for open-style ones."""

        def __init__(self, asgi_app):
            self.asgi_app = asgi_app

        async def __call__(self, scope, receive, send):
            if scope["type"] != "http" or not HAS_CRYPTO or SERVER_PRIV is None:
                return await self.asgi_app(scope, receive, send)
            headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}

            async def reject(status: int, detail: str):
                await send({"type": "http.response.start", "status": status,
                            "headers": [(b"content-type", b"application/json")]})
                await send({"type": "http.response.body",
                            "body": json.dumps({"detail": detail}).encode()})

            # X-Client-Key ⇒ closed-style (per-client ECDH); without it, open-style,
            # allowed only when the server IS open.
            client_pub = headers.get("x-client-key", "") or None
            if client_pub is None and not CONFIG.get("open_server", True):
                return await self.asgi_app(scope, receive, send)  # will 401 in auth
            # Strip the reverse-proxy mount prefix so exempt-path checks match.
            root_path = scope.get("root_path", "") or ""
            path = scope.get("path", "")
            if root_path and path.startswith(root_path):
                path = path[len(root_path):] or "/"
            if (scope.get("method") == "OPTIONS"
                    or any(path.startswith(p) for p in E2E_EXEMPT)):
                return await self.asgi_app(scope, receive, send)

            try:
                if int(headers.get("content-length") or 0) > MAX_WIRE_BODY:
                    return await reject(413, "Request body too large")
            except ValueError:
                pass
            body = b""
            while True:
                msg = await receive()
                if msg["type"] != "http.request":
                    break
                body += msg.get("body", b"")
                if len(body) > MAX_WIRE_BODY:
                    return await reject(413, "Request body too large")
                if not msg.get("more_body"):
                    break

            # Verified here — the only layer with the wire body — and recorded in the
            # scope for require_auth. One-time per signature.
            ts = headers.get("x-timestamp", "")
            sig = headers.get("x-auth", "")
            # raw_path/query_string are the bytes as transmitted, so the canonical
            # string re-encodes to exactly what the client HMAC'd (a query can
            # carry raw UTF-8, e.g. a rename subject).
            raw_path = scope.get("raw_path")
            payload = http_sign_payload(
                scope.get("method", ""),
                raw_path.decode("utf-8", "replace") if raw_path else scope.get("path", ""),
                (scope.get("query_string") or b"").decode("utf-8", "replace"), body)
            ok = (verify_client_signature(client_pub, ts, sig, payload)
                  if client_pub else verify_open_signature(ts, sig, payload))
            authed = bool(ok and consume_signature(sig))
            scope["reinbox_authed"] = authed
            # Authentication ends here, before any decryption, so a
            # caller-supplied client key never reaches the ECDH. Only
            # /server/mode and /ws skip auth, and both are exempt from this
            # middleware.
            if not authed:
                return await reject(401, "Unauthorized")

            if headers.get("x-encrypted") == "1" and body:
                try:
                    body = decrypt_payload(client_pub, body)
                except Exception:
                    return await reject(400, "Bad ciphertext")
                # The wire body was octet-stream; X-Plain-Content-Type has the real type.
                plain_ct = headers.get("x-plain-content-type", "application/json")
                scope = dict(scope)
                scope["headers"] = [(k, v) for k, v in scope["headers"]
                                    if k.decode().lower() not in ("content-type", "content-length")]
                scope["headers"].append((b"content-type", plain_ct.encode()))
                scope["headers"].append((b"content-length", str(len(body)).encode()))

            plain_body = body

            async def wrapped_receive():
                nonlocal plain_body
                out = {"type": "http.request", "body": plain_body, "more_body": False}
                plain_body = b""
                return out

            state = {"start": None, "chunks": [], "size": 0,
                     "encrypt": False, "aborted": False}

            async def wrapped_send(message):
                # The exchange is over once the 413 below is sent: later chunks
                # from the app are dropped, not appended to what is on the wire.
                if state["aborted"]:
                    return
                if message["type"] == "http.response.start":
                    # Every 2xx is encrypted, JSON and binary alike (X-Encrypted).
                    ok = 200 <= message["status"] < 300
                    if ok:
                        declared = next((v for k, v in message.get("headers", [])
                                         if k.decode().lower() == "content-length"), None)
                        try:
                            # One-shot GCM needs the whole body in memory, so a
                            # declared oversize length is refused before the file
                            # is read at all.
                            if declared is not None and int(declared) > MAX_ENCRYPTED_RESPONSE:
                                state["aborted"] = True
                                return await reject(413, "Response too large to encrypt")
                        except ValueError:
                            pass
                        state["start"] = message
                        state["encrypt"] = True
                        return
                    await send(message)
                elif message["type"] == "http.response.body" and state["encrypt"]:
                    chunk = message.get("body", b"")
                    state["size"] += len(chunk)
                    # Streamed bodies may not declare a length — bound them here.
                    if state["size"] > MAX_ENCRYPTED_RESPONSE:
                        state["aborted"] = True
                        state["chunks"] = []
                        return await reject(413, "Response too large to encrypt")
                    state["chunks"].append(chunk)
                    if message.get("more_body"):
                        return
                    raw = b"".join(state["chunks"])
                    enc = encrypt_payload(client_pub, raw)
                    start = state["start"]
                    new_headers = [(k, v) for k, v in start.get("headers", [])
                                   if k.decode().lower() != "content-length"]
                    new_headers.append((b"content-length", str(len(enc)).encode()))
                    new_headers.append((b"x-encrypted", b"1"))
                    await send({"type": "http.response.start", "status": start["status"],
                                "headers": new_headers})
                    await send({"type": "http.response.body", "body": enc})
                else:
                    await send(message)

            await self.asgi_app(scope, wrapped_receive, wrapped_send)

    app.add_middleware(E2EMiddleware)

    @app.get("/server/mode")
    def get_server_mode():
        """Unauthenticated probe so clients know how to authenticate."""
        return {"open": bool(CONFIG.get("open_server", True))}

    @app.get("/server/info", dependencies=[Depends(require_auth)])
    def get_server_info():
        # Servers are nameless: the client names its own entries.
        return {
            "public_key": SERVER_PUB_B64,
            "open": bool(CONFIG.get("open_server", True)),
            "root": root_dir(),
            "agents": [{
                "name": a.get("name", "Agent"),
                "type": a.get("type", "claude"),
                "models": a.get("models", []),
                "efforts": a.get("efforts", []),
            } for a in (CONFIG.get("agents") or [])],
        }

    @app.get("/folders", dependencies=[Depends(require_auth)])
    def get_folders():
        root_ws = root_dir()
        folders = []
        try:
            for root, dirs, files in os.walk(root_ws):
                rel_root = os.path.relpath(root, root_ws)
                depth = 0 if rel_root == "." else rel_root.count(os.sep) + 1
                dirs[:] = [d for d in dirs
                           if not d.startswith(".") and d not in SKIP_DIR_NAMES and depth < FOLDER_MAX_DEPTH]
                for d in dirs:
                    folders.append(os.path.normpath(os.path.join(rel_root, d)))
        except Exception as e:
            return {"error": str(e)}

        return {"root": root_ws, "folders": sorted(folders)}

    @app.get("/sessions", dependencies=[Depends(require_auth)])
    def get_sessions(folder: Optional[str] = None, status: Optional[str] = None,
                     reconcile: int = 0):
        # Reconciliation is event-driven: ?reconcile=1 or the --notify trigger.
        if reconcile:
            reconcile_sessions()
        conn = get_db()
        cursor = conn.cursor()

        query = """
        SELECT s.*,
               (SELECT m.summary_output FROM messages m
                WHERE m.session_id = s.id ORDER BY m.timestamp DESC LIMIT 1) AS preview
        FROM sessions s
        """
        params = []
        conditions = []

        if folder:
            conditions.append("s.folder = ?")
            params.append(folder)
        if status:
            conditions.append("s.status = ?")
            params.append(status)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY s.updated_at DESC"

        cursor.execute(query, params)
        rows = cursor.fetchall()

        sessions = []
        for r in rows:
            preview = (r["preview"] or "").strip().replace("\n", " ")
            sessions.append({
                "id": r["id"],
                "subject": r["subject"],
                "folder": r["folder"],
                # Workspace-relative when scoped, absolute for global imports.
                "directory": r["folder"] or "",
                "model": r["model"],
                "thinking_level": r["thinking_level"],
                "agent": r["agent"] or get_agent(None).get("name"),
                "status": r["status"],
                "last_message_by": r["last_message_by"],
                "is_read": bool(r["is_read"]),
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
                "preview": preview[:160],
            })

        conn.close()
        return {"sessions": sessions}

    @app.get("/messages", dependencies=[Depends(require_auth)])
    def list_messages(sender: Optional[str] = None, limit: int = 300,
                      reconcile: int = 0):
        """Flat list of messages across all sessions (Gmail-style Inbox/Sent),
        newest first, each joined to its session's subject/folder."""
        if reconcile:
            reconcile_sessions()
        conn = get_db()
        cursor = conn.cursor()
        query = """
        SELECT m.id, m.session_id, m.sender, m.timestamp, m.summary_output,
               s.subject, s.folder, s.status, s.is_read, s.agent, s.model,
               s.thinking_level
        FROM messages m JOIN sessions s ON s.id = m.session_id
        WHERE COALESCE(m.carried, 0) = 0
        """
        params = []
        if sender:
            query += " AND m.sender = ?"
            params.append(sender)
        query += " ORDER BY m.timestamp DESC LIMIT ?"
        params.append(max(1, min(int(limit), 500)))
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        messages = []
        for r in rows:
            preview = (r["summary_output"] or "").strip().replace("\n", " ")
            messages.append({
                "id": r["id"],
                "session_id": r["session_id"],
                "sender": r["sender"],
                "timestamp": r["timestamp"],
                "subject": r["subject"],
                "folder": r["folder"],
                "directory": r["folder"] or "",
                "status": r["status"],
                "is_read": bool(r["is_read"]),
                "agent": r["agent"] or get_agent(None).get("name"),
                "model": r["model"],
                "thinking_level": r["thinking_level"],
                "preview": preview[:200],
            })
        return {"messages": messages}

    @app.get("/search", dependencies=[Depends(require_auth)])
    def search_messages(q: str = Query(...), sender: Optional[str] = None,
                        session_id: Optional[str] = None, limit: int = 200):
        """Substring search over message bodies and session subjects, newest
        first, same row shape as /messages. Scoped to one session when
        session_id is given (then fork-carried turns are included too)."""
        term = (q or "").strip()
        if not term:
            return {"messages": []}
        like = f"%{term}%"
        conn = get_db()
        cursor = conn.cursor()
        query = """
        SELECT m.id, m.session_id, m.sender, m.timestamp, m.summary_output,
               s.subject, s.folder, s.status, s.is_read, s.agent, s.model,
               s.thinking_level
        FROM messages m JOIN sessions s ON s.id = m.session_id
        WHERE (m.summary_output LIKE ? OR s.subject LIKE ?)
        """
        params: list = [like, like]
        if session_id:
            if not is_safe_id(session_id):
                raise HTTPException(status_code=400, detail="Invalid session id")
            query += " AND m.session_id = ?"
            params.append(session_id)
        else:
            query += " AND COALESCE(m.carried, 0) = 0"
        if sender:
            query += " AND m.sender = ?"
            params.append(sender)
        query += " ORDER BY m.timestamp DESC LIMIT ?"
        params.append(max(1, min(int(limit), 500)))
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        def snippet(text: str) -> str:
            """Window the body around the first match so the highlighted hit is
            visible even deep inside a long reply."""
            flat = (text or "").strip().replace("\n", " ")
            idx = flat.lower().find(term.lower())
            if idx <= 60:
                return flat[:200]
            start = max(0, idx - 60)
            return "… " + flat[start:start + 200]

        messages = []
        for r in rows:
            messages.append({
                "id": r["id"],
                "session_id": r["session_id"],
                "sender": r["sender"],
                "timestamp": r["timestamp"],
                "subject": r["subject"],
                "folder": r["folder"],
                "directory": r["folder"] or "",
                "status": r["status"],
                "is_read": bool(r["is_read"]),
                "agent": r["agent"] or get_agent(None).get("name"),
                "model": r["model"],
                "thinking_level": r["thinking_level"],
                "preview": snippet(r["summary_output"]),
            })
        return {"messages": messages}

    @app.get("/attachments/{attachment_id}", dependencies=[Depends(require_auth)])
    def download_attachment(attachment_id: str):
        """Raw bytes of an agent-embedded attachment (image/document)."""
        if not is_safe_id(attachment_id):
            raise HTTPException(status_code=400, detail="Invalid attachment id")
        conn = get_db()
        row = conn.execute("SELECT name, media_type, data FROM attachments WHERE id = ?",
                           (attachment_id,)).fetchone()
        conn.close()
        if row is None or row["data"] is None:
            raise HTTPException(status_code=404, detail="Attachment not found")
        safe_name = os.path.basename(row["name"] or "attachment")
        return FastResponse(
            content=row["data"], media_type=row["media_type"] or "application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{safe_name}"'},
        )

    def check_session_id(session_id: str):
        if not is_safe_id(session_id):
            raise HTTPException(status_code=400, detail="Invalid session id")

    @app.get("/sessions/{session_id}", dependencies=[Depends(require_auth)])
    def get_session_details(session_id: str):
        check_session_id(session_id)
        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM sessions WHERE id = ?", (session_id,))
        sess_row = cursor.fetchone()
        if not sess_row:
            conn.close()
            raise HTTPException(status_code=404, detail="Session not found")

        cursor.execute("SELECT * FROM messages WHERE session_id = ? ORDER BY timestamp ASC", (session_id,))
        msg_rows = cursor.fetchall()

        atts_by_msg: Dict[str, List[dict]] = {}
        for ar in cursor.execute(
                "SELECT id, message_id, name, media_type, size, "
                "COALESCE(inline, 0) AS sent FROM attachments "
                "WHERE session_id = ?", (session_id,)).fetchall():
            atts_by_msg.setdefault(ar["message_id"], []).append({
                "id": ar["id"], "name": ar["name"],
                "media_type": ar["media_type"], "size": ar["size"],
                "sent": bool(ar["sent"]),
            })

        messages = []
        for mr in msg_rows:
            try:
                thoughts = json.loads(mr["expanded_thoughts"])
            except Exception:
                thoughts = []
            messages.append({
                "id": mr["id"],
                "sender": mr["sender"],
                "timestamp": mr["timestamp"],
                "summary_output": mr["summary_output"],
                "expanded_thoughts": thoughts,
                "attachments": atts_by_msg.get(mr["id"], []),
            })

        if sess_row["status"] in ("completed", "cancelled") and messages:
            last_msg = messages[-1]
            if last_msg["sender"] == "claude" and not last_msg["expanded_thoughts"]:
                lookup_id = sess_row["claude_session_id"] or session_id
                jsonl_path = find_session_jsonl(lookup_id, sess_row["folder"])
                if jsonl_path:
                    thoughts = parse_jsonl_thoughts(jsonl_path)
                    if thoughts:
                        last_msg["expanded_thoughts"] = thoughts
                        cursor.execute("UPDATE messages SET expanded_thoughts = ? WHERE id = ?",
                                       (json.dumps(thoughts), last_msg["id"]))
                        conn.commit()

        conn.close()
        return {
            "session": {
                "id": sess_row["id"],
                "subject": sess_row["subject"],
                "folder": sess_row["folder"],
                "directory": sess_row["folder"] or "",
                "model": sess_row["model"],
                "thinking_level": sess_row["thinking_level"],
                "agent": sess_row["agent"] or get_agent(None).get("name"),
                "status": sess_row["status"],
                "last_message_by": sess_row["last_message_by"],
                "is_read": bool(sess_row["is_read"]),
                "created_at": sess_row["created_at"],
                "updated_at": sess_row["updated_at"],
                # The agent's real id on disk; equals the app id when imported.
                "real_session_id": sess_row["claude_session_id"] or sess_row["id"],
            },
            "messages": messages
        }

    @app.get("/sessions/{session_id}/live", dependencies=[Depends(require_auth)])
    def get_live_steps(session_id: str):
        """Streamed structured steps of a run in progress (both Claude's
        stream-json and codex --json emit events as they complete)."""
        check_session_id(session_id)
        return {
            "active": session_id in RUNNING_PROCESSES,
            "steps": list(LIVE_STEPS.get(session_id, ())),
        }

    @app.post("/sessions/create", dependencies=[Depends(require_auth)])
    async def create_session(data: dict):
        folder = str(data.get("folder", ""))
        subject = str(data.get("subject", "Unnamed Session"))[:300]
        prompt = str(data.get("prompt", ""))
        model = data.get("model")
        thinking_level = data.get("thinking_level")
        agent_cfg = get_agent(data.get("agent"))
        agent = agent_cfg.get("name")
        resume_id = data.get("resume_id")
        fork = bool(data.get("fork", False))

        # Scoped folders must stay inside root_dir; absolute ones are allowed only
        # for a global-scope agent (e.g. replying to a session imported from
        # elsewhere on the machine).
        if resolve_session_folder(folder, agent_cfg) is None:
            raise HTTPException(status_code=403, detail="Folder escapes the workspace sandbox")
        if resume_id is not None and not is_safe_id(resume_id):
            raise HTTPException(status_code=400, detail="Invalid resume_id")
        if not prompt.strip():
            raise HTTPException(status_code=400, detail="Empty prompt")
        if len(prompt) > MAX_PROMPT_CHARS:
            raise HTTPException(status_code=413,
                                detail=f"Prompt exceeds {MAX_PROMPT_CHARS} characters")

        # codex has no fork primitive: `resume` continues the same thread.
        if fork and agent_cfg.get("type") == "codex":
            fork = False

        timestamp_ms = now_ms()
        # Resuming is explicit. A fresh id carries only 32 bits, so a collision
        # is regenerated: it must not land on the session already holding that id.
        resuming = bool(resume_id) and not fork
        if resuming:
            session_id = resume_id
        else:
            session_id = await asyncio.to_thread(unused_session_id)

        # One agent per session: a reply while the previous turn still runs would
        # race two processes over one transcript. The slot is claimed BEFORE the
        # first await, so two simultaneous replies cannot both pass the check.
        if session_id in ACTIVE_RUNS:
            raise HTTPException(status_code=409, detail="Session is still running")
        ACTIVE_RUNS.add(session_id)

        # Claude's prompt-derived line is replaced by the aiTitle later; codex has
        # no aiTitle, so its title is its session id — the app id as a placeholder
        # here, swapped for the real one by link_real_session_id.
        if not subject or subject.strip() in ("", "Unnamed Session"):
            if agent_cfg.get("type") == "codex":
                subject = session_id
            else:
                subject = subject_from_prompt(prompt)

        def db_work():
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM sessions WHERE id = ?", (session_id,))
            # A resume whose row was pruned falls through and re-inserts it.
            if resuming and cursor.fetchone():
                # Resume: keep history, created_at and subject. The per-turn effort
                # becomes the session's latest at once, so the client's "previous
                # effort" default is right mid-run.
                cursor.execute("""
                UPDATE sessions SET status = 'active', last_message_by = 'me', updated_at = ?,
                    thinking_level = ?
                WHERE id = ?
                """, (timestamp_ms,
                      thinking_level if (thinking_level and not is_placeholder(thinking_level)) else "default",
                      session_id))
            else:
                # A fork (--fork-session) is a NEW session seeded with the source's
                # history, so copy its messages to mirror the forked transcript.
                if fork and resume_id:
                    src = cursor.execute(
                        "SELECT subject, folder, model, thinking_level, agent FROM sessions WHERE id = ?",
                        (resume_id,)).fetchone()
                    if src:
                        subj = subject if subject and subject != session_id else src["subject"]
                        cursor.execute("""
                        INSERT INTO sessions (id, subject, folder, model, thinking_level, status,
                                              last_message_by, is_read, created_at, updated_at, agent)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (session_id, subj, folder, model or src["model"],
                              thinking_level or src["thinking_level"], "active", "me", 1,
                              timestamp_ms, timestamp_ms, agent or src["agent"]))
                        for m in cursor.execute(
                            "SELECT id, sender, timestamp, summary_output, expanded_thoughts "
                            "FROM messages WHERE session_id = ? ORDER BY timestamp ASC",
                            (resume_id,)).fetchall():
                            # carried=1: shown in the branch, hidden from the flat
                            # lists so they don't duplicate the source thread.
                            new_mid = str(uuid.uuid4())
                            cursor.execute("""INSERT INTO messages
                                (id, session_id, sender, timestamp, summary_output,
                                 expanded_thoughts, carried)
                                VALUES (?, ?, ?, ?, ?, ?, 1)""",
                                (new_mid, session_id, m["sender"], m["timestamp"],
                                 m["summary_output"], m["expanded_thoughts"]))
                            for a in cursor.execute(
                                "SELECT name, media_type, size, src_path, data "
                                "FROM attachments WHERE message_id = ?",
                                (m["id"],)).fetchall():
                                cursor.execute("""INSERT INTO attachments
                                    (id, session_id, message_id, name, media_type,
                                     size, src_path, data)
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                                    (str(uuid.uuid4()), session_id, new_mid, a["name"],
                                     a["media_type"], a["size"], a["src_path"], a["data"]))
                    else:
                        fork_insert_fallback(cursor)
                else:
                    cursor.execute("""
                    INSERT INTO sessions (id, subject, folder, model, thinking_level, status,
                                          last_message_by, is_read, created_at, updated_at, agent)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (session_id, subject, folder, model, thinking_level,
                          "active", "me", 1, timestamp_ms, timestamp_ms, agent))

            cursor.execute("""
            INSERT INTO messages (id, session_id, sender, timestamp, summary_output, expanded_thoughts)
            VALUES (?, ?, ?, ?, ?, ?)
            """, (str(uuid.uuid4()), session_id, "me", timestamp_ms, prompt, "[]"))
            conn.commit()
            conn.close()

        def fork_insert_fallback(cursor):
            cursor.execute("""
            INSERT INTO sessions (id, subject, folder, model, thinking_level, status,
                                  last_message_by, is_read, created_at, updated_at, agent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (session_id, subject, folder, model, thinking_level,
                  "active", "me", 1, timestamp_ms, timestamp_ms, agent))

        try:
            await asyncio.to_thread(db_work)
        except Exception:
            ACTIVE_RUNS.discard(session_id)
            raise

        # Re-creating a session id supersedes any tombstone left by a delete.
        DELETED_SESSIONS.pop(session_id, None)
        STREAM_SUBSCRIBERS.setdefault(session_id, set())
        task = asyncio.create_task(run_agent_command(
            session_id=session_id,
            prompt=prompt,
            folder_rel=folder,
            resume_id=resume_id,
            fork=fork,
            model=model,
            thinking=thinking_level,
            agent=agent
        ))
        # Retained (asyncio only holds a weak reference) and self-removing, so
        # shutdown has the live set to cancel.
        RUNNER_TASKS.add(task)
        task.add_done_callback(RUNNER_TASKS.discard)

        return {"status": "started", "session_id": session_id}

    @app.post("/reconcile", dependencies=[Depends(require_auth)])
    async def trigger_reconcile(push: str = Query("latest")):
        """Manual reconcile trigger (`reinbox_server.py --notify`): import and
        refresh terminal sessions NOW, then push a notification for the
        latest fresh agent reply only. One deliberate signal when the user
        decides a session is worth announcing — never a per-turn nag while
        they are still working interactively (passive imports via
        ?reconcile=1 stay silent). push=none skips the notification."""
        fresh = await asyncio.to_thread(reconcile_sessions, True)
        notified = None
        if push == "latest" and fresh:
            sid = max(fresh, key=lambda f: f[1])[0]

            def read_session():
                conn = get_db()
                try:
                    s = conn.execute("SELECT * FROM sessions WHERE id = ?", (sid,)).fetchone()
                    m = conn.execute("""SELECT summary_output FROM messages
                        WHERE session_id = ? AND sender = 'claude'
                        ORDER BY timestamp DESC LIMIT 1""", (sid,)).fetchone()
                    return s, m
                finally:
                    conn.close()

            srow, mrow = await asyncio.to_thread(read_session)
            if srow is not None:
                await broadcast_event({
                    "type": "session_completed",
                    "session_id": sid,
                    "folder": srow["folder"],
                    "subject": srow["subject"] or "No Title",
                    # FULL final response, so the notification shows it whole.
                    "output_preview": (mrow["summary_output"] if mrow else ""),
                    "agent": srow["agent"],
                    "model": srow["model"],
                    "effort": srow["thinking_level"],
                })
                notified = sid
        return {"updated": len(fresh), "notified": notified}

    @app.post("/sessions/{session_id}/cancel", dependencies=[Depends(require_auth)])
    async def cancel_session(session_id: str):
        check_session_id(session_id)
        if session_id not in RUNNING_PROCESSES:
            raise HTTPException(status_code=404, detail="No running process for this session")

        # Returns once the agent is gone, so a client that cancels then resumes
        # cannot race a still-dying process onto the same transcript.
        await stop_run(session_id)
        logger.info(f"Cancelled session {session_id}")
        return {"status": "cancelled", "session_id": session_id}

    @app.delete("/sessions/{session_id}", dependencies=[Depends(require_auth)])
    async def delete_session(session_id: str):
        check_session_id(session_id)
        # Wait for the agent to be gone before removing its files: a live process
        # writes its transcript back as fast as it is deleted.
        await stop_run(session_id, interrupted=False)
        # Tombstone so a runner winding down (or a late ingest) can't re-create the
        # session; old ones age out.
        now = time.time()
        for k, t in list(DELETED_SESSIONS.items()):
            if now - t > 86400:
                DELETED_SESSIONS.pop(k, None)
        DELETED_SESSIONS[session_id] = now

        def db_work():
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT folder, claude_session_id FROM sessions WHERE id = ?",
                           (session_id,))
            row = cursor.fetchone()

            # Only ids this server owns reach the filesystem. Without a row there
            # is nothing to clean: an app id is not a transcript name.
            if row is not None:
                real = row["claude_session_id"] or session_id
                for ident in {real, session_id}:
                    delete_claude_session_files(ident, row["folder"])
                    delete_codex_session_files(ident)

            cursor.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
            conn.commit()
            conn.close()

        await asyncio.to_thread(db_work)
        return {"status": "deleted", "session_id": session_id}

    @app.patch("/sessions/{session_id}/read", dependencies=[Depends(require_auth)])
    def update_read_status(session_id: str, is_read: bool):
        check_session_id(session_id)
        conn = get_db()
        conn.execute("UPDATE sessions SET is_read = ? WHERE id = ?", (1 if is_read else 0, session_id))
        conn.commit()
        conn.close()
        return {"status": "updated", "session_id": session_id}

    @app.patch("/sessions/{session_id}/subject", dependencies=[Depends(require_auth)])
    def rename_session(session_id: str, subject: str = Query(...)):
        check_session_id(session_id)
        """Rename a session (the underlying server-side record, source of truth)."""
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM sessions WHERE id = ?", (session_id,))
        if not cursor.fetchone():
            conn.close()
            raise HTTPException(status_code=404, detail="Session not found")
        # No updated_at bump: list order/time must follow the last message.
        cursor.execute("UPDATE sessions SET subject = ?, subject_locked = 1 WHERE id = ?",
                       (subject, session_id))
        conn.commit()
        conn.close()
        return {"status": "renamed", "session_id": session_id, "subject": subject}

    def safe_artifact_path(folder: str, filename: str) -> str:
        """Sandboxed absolute path for a single artifact file. resolve_session_folder
        returns a fully realpath-resolved directory (no symlink components), and
        the filename may not contain path parts, so the only way to escape is a
        symlink AT the final component. That is not checked here — a pre-check is
        TOCTOU-racy (the link can be swapped between check and open); instead the
        read/write opens pass O_NOFOLLOW and delete uses a no-follow lstat, so the
        symlink is refused atomically at the syscall itself."""
        target_dir = resolve_session_folder(folder)
        if target_dir is None:
            raise HTTPException(status_code=403, detail="Sandbox violation")
        if not filename or os.path.basename(filename) != filename or filename.startswith("."):
            raise HTTPException(status_code=400, detail="Invalid filename")
        return os.path.join(target_dir, filename)

    @app.get("/artifacts", dependencies=[Depends(require_auth)])
    def list_artifacts(folder: str = Query(...)):
        target_dir = resolve_session_folder(folder)
        if target_dir is None:
            raise HTTPException(status_code=403, detail="Sandbox violation")

        artifacts = []
        try:
            if os.path.exists(target_dir):
                for f in os.listdir(target_dir):
                    fp = os.path.join(target_dir, f)
                    if os.path.isfile(fp):
                        stat = os.stat(fp)
                        artifacts.append({
                            "name": f,
                            "size": stat.st_size,
                            "updated_at": int(stat.st_mtime * 1000),
                            "ext": os.path.splitext(f)[1].lower()
                        })
        except Exception as e:
            return {"error": str(e)}

        return {"artifacts": sorted(artifacts, key=lambda x: x["updated_at"], reverse=True)}

    @app.post("/artifacts/upload", dependencies=[Depends(require_auth)])
    async def upload_artifact(folder: str, file: fastapi.UploadFile):
        dest_path = safe_artifact_path(folder, os.path.basename(file.filename or "upload.bin"))
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)

        try:
            content = await file.read()
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Upload failed: {e}")
        if len(content) > MAX_ARTIFACT_BYTES:
            raise HTTPException(status_code=413,
                                detail="File exceeds the 8 MB artifact limit")

        def write_no_follow():
            # O_NOFOLLOW: a symlink at dest_path fails the open, rather than being
            # written through to a target outside the folder.
            fd = os.open(dest_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(content)

        try:
            await asyncio.to_thread(write_no_follow)
        except OSError as e:
            if e.errno in (errno.ELOOP, errno.EMLINK):
                raise HTTPException(status_code=403, detail="Sandbox violation")
            raise HTTPException(status_code=500, detail=f"Upload failed: {e}")

        return {"status": "success", "file": file.filename}

    @app.get("/artifacts/download", dependencies=[Depends(require_auth)])
    def download_artifact(folder: str, filename: str):
        target_file = safe_artifact_path(folder, filename)
        # O_NOFOLLOW refuses a symlinked name atomically, so a link swapped in
        # after the sandbox check can't exfiltrate; the bytes are read through
        # this one fd rather than reopened by path.
        try:
            fd = os.open(target_file, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError as e:
            if e.errno in (errno.ELOOP, errno.EMLINK):
                raise HTTPException(status_code=403, detail="Sandbox violation")
            if e.errno == errno.ENOENT:
                raise HTTPException(status_code=404, detail="File not found")
            raise HTTPException(status_code=500, detail=f"Download failed: {e}")
        with os.fdopen(fd, "rb") as f:
            if os.fstat(f.fileno()).st_size > MAX_ARTIFACT_BYTES:
                raise HTTPException(status_code=413,
                                    detail="File exceeds the 8 MB artifact limit")
            data = f.read(MAX_ARTIFACT_BYTES + 1)
        if len(data) > MAX_ARTIFACT_BYTES:
            raise HTTPException(status_code=413,
                                detail="File exceeds the 8 MB artifact limit")
        return FastResponse(
            content=data, media_type="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{os.path.basename(filename)}"'})

    @app.delete("/artifacts", dependencies=[Depends(require_auth)])
    def delete_artifact(folder: str = Query(...), filename: str = Query(...)):
        target_file = safe_artifact_path(folder, filename)
        # lstat does not follow symlinks, so only a real regular file is deletable.
        try:
            st = os.lstat(target_file)
        except OSError:
            raise HTTPException(status_code=404, detail="File not found")
        if not stat_module.S_ISREG(st.st_mode):
            raise HTTPException(status_code=403, detail="Sandbox violation")
        try:
            os.remove(target_file)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Delete failed: {e}")
        return {"status": "deleted", "file": filename}

    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket, client: Optional[str] = None,
                                 ts: Optional[str] = None, sig: Optional[str] = None):
        """Upgrade auth mirrors HTTP: ?client=&ts=&sig= for closed style,
        ?ts=&sig= (signature from the public-key-derived HMAC key) for open
        style, each signature spent on one upgrade. Every frame in both
        directions is AES-GCM encrypted as {"enc": "<b64 nonce+ciphertext>"}."""
        if not HAS_CRYPTO or SERVER_PRIV is None:
            await websocket.close(code=4001, reason="Server has no keys")
            return
        if client:
            if not (ts and sig and verify_client_signature(client, ts, sig, "/ws")
                    and consume_signature(sig)):
                await websocket.close(code=4001, reason="Invalid client signature")
                return
        else:
            if not (ts and sig and verify_open_signature(ts, sig, "/ws")
                    and consume_signature(sig)):
                await websocket.close(code=4001, reason="Invalid signature")
                return

        await websocket.accept()
        conn_enc_key = payload_enc_key(client)

        class WrappedSocket:
            def __init__(self, ws: WebSocket, enc_key: bytes):
                self.ws = ws
                self.enc_key = enc_key

            async def send_text(self, text: str):
                nonce = os.urandom(12)
                blob = nonce + AESGCM(self.enc_key).encrypt(nonce, text.encode("utf-8"), None)
                await self.ws.send_text(json.dumps({"enc": base64.b64encode(blob).decode()}))

        wrapped = WrappedSocket(websocket, conn_enc_key)
        ACTIVE_CONNECTIONS.add(wrapped)
        logger.info(f"Mobile app authenticated and connected via WS. Count: {len(ACTIVE_CONNECTIONS)}")

        stream_tasks: List[asyncio.Task] = []
        try:
            while True:
                data = await websocket.receive_text()
                msg = json.loads(data)
                enc = msg.get("enc")
                if enc:
                    nonce_blob = base64.b64decode(enc)
                    msg = json.loads(AESGCM(conn_enc_key).decrypt(
                        nonce_blob[:12], nonce_blob[12:], None))
                action = msg.get("action")

                if action == "ping":
                    await wrapped.send_text(json.dumps({"type": "pong"}))
                elif action == "subscribe_stream":
                    sess_id = msg.get("session_id")
                    if sess_id and is_safe_id(sess_id):
                        stream_tasks.append(asyncio.create_task(stream_logs_task(wrapped, sess_id)))

        except WebSocketDisconnect:
            logger.info("Mobile app socket disconnected.")
        except Exception as e:
            logger.error(f"WebSocket error: {e}")
        finally:
            ACTIVE_CONNECTIONS.discard(wrapped)
            for t in stream_tasks:
                t.cancel()

    async def stream_logs_task(ws, session_id: str):
        subs = STREAM_SUBSCRIBERS.get(session_id)
        if subs is None:
            return  # not running (anymore); nothing to stream
        queue: asyncio.Queue = asyncio.Queue(maxsize=500)
        subs.add(queue)
        try:
            while True:
                chunk = await queue.get()
                if chunk is None:
                    break
                await ws.send_text(json.dumps({
                    "type": "log_chunk",
                    "session_id": session_id,
                    "chunk": chunk
                }))
        except (asyncio.CancelledError, Exception):
            pass
        finally:
            current = STREAM_SUBSCRIBERS.get(session_id)
            if current is not None:
                current.discard(queue)

else:
    logger.error("FastAPI or uvicorn is missing. Running in standby mock state. "
                 "Please run 'pip install fastapi uvicorn websockets' to start fully functional server.")


def _qr_terminal(key: str) -> Optional[str]:
    """Scannable terminal QR: modules as solid ANSI background cells, not
    foreground glyphs (those get broken up by font antialiasing/line spacing so
    cameras can't decode them). None if pyqrcode is missing."""
    try:
        import pyqrcode
    except Exception:
        return None
    rows = [line for line in pyqrcode.create(key, error="L").text(quiet_zone=2).splitlines() if line]
    if not rows:
        return None
    WHITE_BG, BLACK_BG, RESET = "\033[47m", "\033[40m", "\033[0m"
    return "\n".join(
        "".join((BLACK_BG if c == "1" else WHITE_BG) + "  " for c in row) + RESET
        for row in rows)


def print_qr_key(key: str, label: str = "SERVER PUBLIC KEY"):
    logger.info("\n" + "=" * 50)
    logger.info(f"           {label}")
    logger.info("=" * 50)
    logger.info(f" {key}")
    if not CONFIG.get("open_server", True):
        logger.info(" (closed server: add each client public key to")
        logger.info("  \"allowed_clients\" in config.json)")
    logger.info("=" * 50)
    qr = _qr_terminal(key)
    if qr:
        print(qr)
    else:
        logger.info("\n[Install pyqrcode for a scannable QR: pip install pyqrcode]")
        logger.info("Meanwhile, paste this key into the app's \"Server public key\" field:")
        logger.info("  ┌" + "─" * (len(key) + 2) + "┐")
        logger.info(f"  │ {key} │")
        logger.info("  └" + "─" * (len(key) + 2) + "┘")
    logger.info("=" * 50 + "\n")


def notify_running_server(config_path: str) -> int:
    """`reinbox_server.py --notify [config.json]`: tell the RUNNING server to
    reconcile now and push a notification for the latest fresh agent reply.
    Run it after finishing an interactive CLI session (or from cron, after a
    plain agent command) — it authenticates with the server's own key file."""
    load_config(config_path)
    kpath = key_file_path()
    try:
        priv_b64 = open(kpath).read().strip()
    except OSError:
        print(f"No key file at {kpath} — is the server initialized?", file=sys.stderr)
        return 1
    if not HAS_CRYPTO:
        print("The 'cryptography' package is required.", file=sys.stderr)
        return 1
    import urllib.request
    priv = X25519PrivateKey.from_private_bytes(base64.b64decode(priv_b64))
    pub_raw = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    pub_b64 = base64.b64encode(pub_raw).decode()
    shared = priv.exchange(priv.public_key())
    auth_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                    info=b"reinbox-auth").derive(shared)
    enc_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                   info=b"reinbox-e2e").derive(shared)
    base_path = str(CONFIG.get("base_path", "") or "").strip().rstrip("/")
    if base_path and not base_path.startswith("/"):
        base_path = "/" + base_path
    path = f"{base_path}/reconcile"
    ts = str(now_ms())
    payload = http_sign_payload("POST", path, "push=latest", b"")
    sig = hmac.new(auth_key, f"{ts}:{payload}".encode(), hashlib.sha256).hexdigest()
    # Target an address this config's server actually listens on.
    binds = CONFIG.get("bind") or []
    if isinstance(binds, str):
        binds = [binds] if binds else []
    host = "localhost"
    if binds and "0.0.0.0" not in binds:
        host = next((b for b in binds if b.startswith("127.") or b == "::1"), binds[0])
    url = f"http://{host}:{CONFIG.get('port', 16861)}{path}?push=latest"
    req = urllib.request.Request(url, data=b"", method="POST", headers={
        "X-Client-Key": pub_b64, "X-Timestamp": ts, "X-Auth": sig})
    try:
        resp = urllib.request.urlopen(req, timeout=60)
        raw = resp.read()
        if resp.headers.get("X-Encrypted") == "1":
            raw = AESGCM(enc_key).decrypt(raw[:12], raw[12:], None)
        out = json.loads(raw)
        print(f"Reconciled: {out.get('updated', 0)} session(s) with fresh replies; "
              f"notified: {out.get('notified') or 'none'}")
        return 0
    except Exception as e:
        print(f"Could not reach the running server: {e}", file=sys.stderr)
        return 1


def warn_if_bypass_exposed(binds: List[str]):
    """A loud reminder when permission-bypass agents are reachable off the local
    machine. The async design needs those flags (nobody is present to approve a
    prompt), so any authorized request runs code as the server user — on a
    non-loopback interface that is effectively remote code execution to anyone
    holding the key. Not an error (it is the documented model), just a warning
    so it is a deliberate choice."""
    BYPASS = ("bypasspermissions", "--dangerously-bypass-approvals-and-sandbox",
              "--dangerously-skip-permissions")
    bypass_agents = [a.get("name", "?") for a in (CONFIG.get("agents") or [])
                     if any(str(x).lower() in BYPASS for x in (a.get("args") or []))]
    public = any(b not in ("127.0.0.1", "::1", "localhost") for b in binds)
    if bypass_agents and public:
        logger.warning("=" * 60)
        logger.warning("Permission-bypass agents (%s) are reachable off this host.",
                       ", ".join(bypass_agents))
        logger.warning("Any authorized request runs code as this user with no approval")
        logger.warning("gate. Use closed mode + a trusted network/tunnel, or bind to")
        logger.warning("127.0.0.1 if only local clients need access.")
        logger.warning("=" * 60)


def main():
    # Optional config path argument so several servers can run side by side:
    #   python3 reinbox_server.py [config.json]
    #   python3 reinbox_server.py --notify [config.json]   -> trigger a running server
    argv = [a for a in sys.argv[1:] if a != "--notify"]
    config_path = argv[0] if argv else "config.json"
    if "--notify" in sys.argv:
        sys.exit(notify_running_server(config_path))
    load_config(config_path)
    init_db()
    repair_stale_active_sessions()
    ensure_server_keys()
    try:
        reconcile_sessions(force=True)
    except Exception as e:
        logger.error(f"Initial reconcile failed: {e}")
    if SERVER_PUB_B64:
        print_qr_key(SERVER_PUB_B64)
    else:
        logger.error("No server keypair — clients cannot authenticate.")

    if HAS_FASTAPI:
        port = CONFIG.get("port", OPTIONAL_CONFIG["port"])
        # The proxy forwards the prefix unchanged, so mount the whole app under it.
        base_path = str(CONFIG.get("base_path", "") or "").strip().rstrip("/")
        if base_path and not base_path.startswith("/"):
            base_path = "/" + base_path
        to_serve = app
        if base_path:
            # A mount does not run the child's lifespan, so the parent carries it
            # — otherwise nothing stops the agents when serving under a prefix.
            parent = FastAPI(lifespan=lifespan)
            parent.mount(base_path, app)
            to_serve = parent
            logger.info(f"Serving under base path {base_path!r} "
                        f"(e.g. https://<host>{base_path}/server/mode ; WS at {base_path}/ws)")
        binds = CONFIG.get("bind") or []
        if isinstance(binds, str):
            binds = [binds] if binds else []
        if not binds:
            binds = ["0.0.0.0"]
        warn_if_bypass_exposed(binds)
        logger.info(f"Starting server on {', '.join(binds)} port {port}...")
        if len(binds) == 1:
            uvicorn.run(to_serve, host=binds[0], port=port)
        else:
            # One uvicorn server per address in one event loop. Signal handlers are
            # per-process singletons, so only bare servers here; Ctrl+C lands as
            # KeyboardInterrupt and stops the loop whole.
            class _BareServer(uvicorn.Server):
                def install_signal_handlers(self):
                    pass

            async def serve_all():
                servers = [_BareServer(uvicorn.Config(to_serve, host=h, port=port))
                           for h in binds]
                await asyncio.gather(*(s.serve() for s in servers))

            try:
                asyncio.run(serve_all())
            except KeyboardInterrupt:
                pass
    else:
        logger.error("Failed to start FastAPI server due to missing pre-requisites.")


if __name__ == "__main__":
    main()
