import asyncio
from contextlib import closing
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import AsyncMock, patch
import uuid


SPEC = importlib.util.spec_from_file_location(
    "grok_test_server", Path(__file__).resolve().parents[1] / "reinbox_server.py")
srv = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(srv)
SID = "11111111-1111-4111-8111-111111111111"
OTHER = "22222222-2222-4222-8222-222222222222"
NEW = "33333333-3333-4333-8333-333333333333"
BASE_MS = 1_750_000_000_000


def update(kind, text=None, ts=BASE_MS, sid=SID, method="session/update", event_id=None, **fields):
    body = {"sessionUpdate": kind, **fields}
    if text is not None:
        body["content"] = {"type": "text", "text": text}
    meta = {"agentTimestampMs": ts}
    if event_id:
        meta["eventId"] = event_id
    return {"method": method, "timestamp": ts / 1000,
            "params": {"sessionId": sid, "_meta": meta, "update": body}}


class IsolatedStore:
    def setUp(self):
        super().setUp()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.workspace = self.base / "workspace"
        self.workspace.mkdir()
        self.home = self.base / "grok"
        self.owner = {"name": "Grok", "type": "grok", "path": "grok",
                      "home_dir": str(self.home), "scope": "workspace", "args": []}
        config = {"root_dir": str(self.workspace), "db_path": str(self.base / "app.sqlite"),
                  "agents": [self.owner]}
        for name, value in (("CONFIG", config), ("RUNNING_PROCESSES", {}),
                            ("DELETED_SESSIONS", {}), ("LIVE_STEPS", {}),
                            ("STREAM_SUBSCRIBERS", {}), ("ACTIVE_RUNS", set()),
                            ("_LAST_RECONCILE", {"ts": 0})):
            patcher = patch.object(srv, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        srv.init_db()

    def session(self, events=None, sid=SID, group="hashed-cwd-group", cwd=None, **meta):
        path = self.home / "sessions" / group / sid
        path.mkdir(parents=True, exist_ok=True)
        summary = {"info": {"id": sid, "cwd": cwd or str(self.workspace)},
                   "created_at": "2025-06-15T15:06:40Z", "updated_at": "2025-06-15T15:06:45Z",
                   "current_model_id": "grok-test", "reasoning_effort": "medium",
                   "agent_name": "internal-profile", "session_summary": "private recap excluded",
                   **meta}
        (path / "summary.json").write_text(json.dumps(summary))
        if events is not None:
            (path / "updates.jsonl").write_text("".join(json.dumps(e) + "\n" for e in events))
        return path

    def seed_app(self, app_id="short-id", real_id=None, agent="Grok", locked=0):
        with closing(srv.get_db()) as db, db:
            db.execute("""INSERT INTO sessions
                       (id, folder, agent, subject, status, claude_session_id, subject_locked)
                       VALUES (?, '', ?, 'Opening prompt', 'active', ?, ?)""",
                       (app_id, agent, real_id, locked))

    def rows(self, table="messages"):
        with closing(srv.get_db()) as db, db:
            return [dict(r) for r in db.execute("SELECT * FROM " + table)]

    def scoped_discovery(self):
        records = {}
        for owner, record, cwd in srv.discover_grok_transcripts():
            if record.get("unavailable"):
                records[record["id"]] = record
                continue
            real = os.path.realpath(cwd)
            if os.path.commonpath([srv.root_dir(), real]) == srv.root_dir():
                folder = os.path.relpath(real, srv.root_dir())
                folder = "" if folder == "." else folder
            elif srv.agent_scope_global(owner):
                folder = real
            else:
                continue
            record["folder"] = folder
            records[record["id"]] = record
        return records


class ParserTests(IsolatedStore, unittest.TestCase):
    def test_chunk_aggregation_boundaries_event_ids_and_metadata(self):
        events = [update("user_message_chunk", "Hello ", event_id="user-1"),
                  update("user_message_chunk", "world", ts=BASE_MS + 1),
                  update("agent_thought_chunk", "Think ", ts=BASE_MS + 2),
                  update("agent_thought_chunk", "carefully", ts=BASE_MS + 3),
                  update("agent_message_chunk", "First ", ts=BASE_MS + 4, event_id="reply-1"),
                  update("agent_message_chunk", "First ", ts=BASE_MS + 4, event_id="reply-1"),
                  update("session_recap", "not a user turn", ts=BASE_MS + 5),
                  update("agent_message_chunk", "reply", ts=BASE_MS + 6, method="_x.ai/session/update"),
                  update("turn_completed", ts=BASE_MS + 7, prompt_id="prompt-1", stop_reason="end_turn"),
                  update("user_message_chunk", "Hello world", ts=BASE_MS + 8),
                  update("agent_message_chunk", "First reply", ts=BASE_MS + 9),
                  update("turn_completed", ts=BASE_MS + 10)]
        path = self.session(events, generated_title="Human title")
        rec = srv.parse_grok_session(str(path))
        self.assertEqual([t["summary"] for t in rec["turns"]],
                         ["Hello world", "First reply", "Hello world", "First reply"])
        first = rec["turns"][1]
        self.assertEqual([s["content"] for s in first["steps"]], ["Think carefully", "First reply"])
        self.assertEqual(first["timestamp"], BASE_MS + 7)
        self.assertEqual(first["start"], BASE_MS + 2)
        self.assertEqual(rec["subject"], "Human title")
        self.assertEqual(rec["model"], "grok-test")
        self.assertEqual(rec["effort"], "medium")

    def test_tool_patches_emit_one_call_and_one_response(self):
        tool = {"toolCallId": "call-1"}
        events = [update("user_message_chunk", "Read"),
                  update("tool_call", ts=BASE_MS + 1, **tool, title="Read document",
                         rawInput={"path": "a.txt"}, _meta={"x.ai/tool": {"name": "read_file"}}),
                  update("tool_call_update", ts=BASE_MS + 2, **tool, rawInput={"path": "b.txt"}),
                  update("tool_call_update", ts=BASE_MS + 3, **tool, status="in_progress",
                         content=[{"type": "content", "content": {"type": "text", "text": "pending"}}]),
                  update("tool_call_update", ts=BASE_MS + 4, **tool, status="completed",
                         rawOutput={"type": "FileContent", "FileContent": {"content": "done"}}),
                  update("tool_call_update", ts=BASE_MS + 5, **tool, status="completed"),
                  update("agent_message_chunk", "Finished", ts=BASE_MS + 6)]
        rec = srv.parse_grok_session(str(self.session(events)))
        steps = rec["turns"][1]["steps"]
        self.assertEqual([s["type"] for s in steps], ["call", "response", "message"])
        self.assertEqual(steps[0]["content"], 'read_file {"path": "b.txt"}')
        self.assertEqual(steps[1]["content"], "done")
        self.assertEqual(steps[1]["timestamp"], BASE_MS + 4)

    def test_tool_metadata_patch_does_not_split_assistant_chunks(self):
        events = [update("user_message_chunk", "Q"),
                  update("tool_call", toolCallId="c", rawInput={"path": "a", "limit": 5},
                         _meta={"x.ai/tool": {"name": "read_file"}}),
                  update("agent_message_chunk", "Part "),
                  update("tool_call_update", toolCallId="c", status="completed", rawInput={"path": "b"},
                         _meta={"x.ai/tool": {"kind": "read"}}),
                  update("agent_message_chunk", "two")]
        rec = srv.parse_grok_session(str(self.session(events)))
        self.assertEqual(rec["summary"], "Part two")
        self.assertEqual(len(rec["steps"]), 2)
        self.assertEqual(rec["steps"][0]["content"], 'read_file {"path": "b", "limit": 5}')

    def test_unreadable_summary_and_updates_keep_identity(self):
        path = self.session([update("user_message_chunk", "Q")])
        (path / "summary.json").write_text('{"info":')
        owner, rec, cwd = list(srv.discover_grok_transcripts())[0]
        self.assertEqual(rec["id"], SID)
        self.assertTrue(rec["unavailable"])
        self.assertIsNone(cwd)
        self.session([])
        (path / "updates.jsonl").write_text('{"method":')
        rec = list(srv.discover_grok_transcripts())[0][1]
        self.assertEqual(rec["id"], SID)
        self.assertTrue(rec["unavailable"])
        self.session([], num_messages=3)
        self.assertTrue(list(srv.discover_grok_transcripts())[0][1]["unavailable"])
        native_open = open
        def unreadable(name, *args, **kwargs):
            if Path(name).name == "updates.jsonl":
                raise PermissionError("unreadable transcript")
            return native_open(name, *args, **kwargs)
        with patch("builtins.open", side_effect=unreadable):
            rec = list(srv.discover_grok_transcripts())[0][1]
        self.assertTrue(rec["unavailable"])
        self.assertEqual(rec["id"], SID)

    def test_raw_outputs(self):
        for raw, expected in [("plain", "plain"),
                              ({"output_for_prompt": "ready", "output": [65]}, "ready"),
                              ({"stdout": [65, 66], "stderr": [67]}, "AB\nC"),
                              ({"Result": {"message": "stopped"}}, "stopped"),
                              ({"EditsApplied": {"tool_output_for_prompt": "edited"}}, "edited")]:
            with self.subTest(raw=raw):
                self.assertEqual(srv.grok_output_text(raw), expected)

    def test_unfinished_turn_and_malformed_tail(self):
        events = [None, {}, {"method": "session/update", "params": []},
                  update("user_message_chunk", "Question"), update("agent_message_chunk", "Partial")]
        path = self.session(events)
        with (path / "updates.jsonl").open("a") as f:
            f.write('{"method":')
        rec = srv.parse_grok_session(str(path))
        self.assertEqual(len(rec["turns"]), 2)
        self.assertEqual(rec["summary"], "Partial")

    def test_seconds_and_iso_timestamps(self):
        events = [update("user_message_chunk", "Q"), update("agent_message_chunk", "A")]
        events[0]["params"]["_meta"] = {}
        events[1]["params"]["_meta"] = {}
        events[1]["timestamp"] = "2025-06-15T15:06:41Z"
        rec = srv.parse_grok_session(str(self.session(events)))
        self.assertEqual(rec["turns"][0]["timestamp"], BASE_MS)
        self.assertEqual(rec["turns"][1]["timestamp"], BASE_MS + 1000)

    def test_empty_internal_and_other_session_updates_excluded(self):
        for events in (None, [], [update("session_recap", "recap")],
                       [update("agent_message_chunk", "internal")],
                       [update("user_message_chunk", "foreign", sid=OTHER)]):
            with self.subTest(events=events):
                path = self.session(events, sid=str(uuid.uuid4()))
                self.assertIsNone(srv.parse_grok_session(str(path)))
        self.assertEqual(list(srv.discover_grok_transcripts()), [])

    def test_scope_owner_hashed_cwd_and_mtimes(self):
        outside = self.base / "outside"
        path = self.session([update("user_message_chunk", "Q")], cwd=str(outside))
        os.utime(path / "updates.jsonl", (1000, 1000))
        os.utime(path / "summary.json", (2000, 2000))
        self.assertEqual(self.scoped_discovery(), {})
        self.owner["scope"] = "global"
        rec = self.scoped_discovery()[SID]
        self.assertEqual(rec["folder"], str(outside.resolve()))
        self.assertEqual(rec["agent_name"], "Grok")
        self.assertEqual(rec["mtime"], 2_000_000)
        self.assertEqual(rec["path"], str(path.resolve()))
        self.assertNotIn("internal-profile", str(rec))
        self.assertNotIn("recap excluded", str(rec))

    def test_custom_home_and_shared_store_first_owner(self):
        self.session([update("user_message_chunk", "Q")])
        srv.CONFIG["agents"].append({**self.owner, "name": "Second"})
        self.assertEqual(len(list(srv.discover_grok_transcripts())), 1)
        self.assertEqual(srv.agent_home_dirs(self.owner), [str(self.home)])
        with patch.dict(os.environ, {"GROK_HOME": str(self.base / "env-store")}):
            self.assertEqual(srv.stock_home_dirs("grok"), [str(self.base / "env-store")])

    def test_default_home_and_partial_prompt_only(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(
                srv.os.path, "expanduser", side_effect=lambda p: "/test-home" if p == "~" else p):
            self.assertEqual(srv.stock_home_dirs("grok"), ["/test-home/.grok"])
        rec = srv.parse_grok_session(str(self.session([update("user_message_chunk", "Only a prompt")])))
        self.assertEqual(rec["subject"], "Only a prompt")
        self.assertEqual([t["sender"] for t in rec["turns"]], ["me"])
        self.assertIsNone(rec["summary"])

    def test_growing_reply_merges_on_reload(self):
        events = [update("user_message_chunk", "Q"), update("agent_message_chunk", "Partial", ts=BASE_MS + 1)]
        path = self.session(events)
        os.utime(path / "updates.jsonl", (2_000_000_000, 2_000_000_000))
        with patch.object(srv, "discover_transcripts", self.scoped_discovery):
            srv.reconcile_sessions(force=True)
            first = self.rows()
            self.session(events + [update("agent_message_chunk", " answer", ts=BASE_MS + 2),
                                   update("turn_completed", ts=BASE_MS + 3)])
            os.utime(path / "updates.jsonl", (2_000_000_001, 2_000_000_001))
            srv.reconcile_sessions(force=True)
            final = self.rows()
        self.assertEqual(len(final), 2)
        self.assertEqual([r["id"] for r in final], [r["id"] for r in first])
        self.assertEqual(final[-1]["summary_output"], "Partial answer")

    def test_distinct_turns_can_have_identical_replies(self):
        events = [update("user_message_chunk", "First"),
                  update("agent_message_chunk", "Yes", ts=BASE_MS + 1),
                  update("turn_completed", ts=BASE_MS + 2)]
        path = self.session(events)
        os.utime(path / "updates.jsonl", (2_000_000_000, 2_000_000_000))
        srv.reconcile_sessions(force=True)
        self.session(events + [update("user_message_chunk", "Second", ts=BASE_MS + 10),
                               update("agent_message_chunk", "Yes", ts=BASE_MS + 11),
                               update("turn_completed", ts=BASE_MS + 12)])
        os.utime(path / "updates.jsonl", (2_000_000_001, 2_000_000_001))
        srv.reconcile_sessions(force=True)
        self.assertEqual([r["summary_output"] for r in self.rows()], ["First", "Yes", "Second", "Yes"])

    def test_scope_wrapper_reconcile_idempotent_and_subject_lock(self):
        self.session([update("user_message_chunk", "Q"),
                      update("agent_message_chunk", "A", ts=BASE_MS + 1),
                      update("turn_completed", ts=BASE_MS + 2)], generated_title="Native title")
        with patch.object(srv, "discover_transcripts", self.scoped_discovery):
            self.assertEqual(srv.reconcile_sessions(force=True), [(SID, BASE_MS + 2)])
            messages = self.rows()
            with closing(srv.get_db()) as db, db:
                db.execute("UPDATE sessions SET subject='Custom', subject_locked=1, is_read=1")
            self.assertEqual(srv.reconcile_sessions(force=True), [])
            self.assertEqual(self.rows(), messages)
            self.assertEqual(self.rows("sessions")[0]["subject"], "Custom")
            self.assertEqual(self.rows("sessions")[0]["is_read"], 1)


class CommandTests(IsolatedStore, unittest.TestCase):
    def test_exact_new_argv_verbatim_and_native_permissions(self):
        prompt = '--literal "quotes"\nsecond line'
        cfg = {**self.owner, "args": ["--allowedTools", "read_file"]}
        self.assertEqual(srv.build_grok_command(cfg, prompt, None, False, "grok-test", "medium", NEW),
                         ["grok", "-p", prompt, "--output-format", "streaming-messages-json",
                          "--model", "grok-test", "--effort", "medium", "--session-id", NEW,
                          "--allowedTools", "read_file"])

    def test_resume_fork_and_validation(self):
        cmd = srv.build_grok_command(self.owner, "Q", SID, False, None, "Default (Omit)")
        self.assertEqual(cmd[-2:], ["--resume", SID])
        self.assertNotIn("--session-id", cmd)
        cmd = srv.build_grok_command(self.owner, "Q", SID, True, None, None, NEW)
        self.assertEqual(cmd[-5:], ["--resume", SID, "--fork-session", "--session-id", NEW])
        for resume, fork, child in ((None, False, "short-id"), ("short-id", False, None),
                                    (None, True, NEW), (SID, False, NEW)):
            with self.subTest(resume=resume, fork=fork, child=child), self.assertRaises(ValueError):
                srv.build_grok_command(self.owner, "Q", resume, fork, None, None, child)

    def test_effort_rejected_without_lossy_rewriting(self):
        for effort in ("HIGH", "me dium", "medium ", "medium;other"):
            with self.subTest(effort=effort), self.assertRaises(ValueError):
                srv.build_grok_command(self.owner, "Q", None, False, None, effort, NEW)
        cmd = srv.build_grok_command(self.owner, "Q", None, False, None, "medium", NEW)
        self.assertEqual(cmd[cmd.index("--effort") + 1], "medium")

    def test_legacy_command_shapes(self):
        self.assertEqual(srv.build_claude_command({"path": "claude", "args": []}, "Q", SID, True, None, None),
                         ["claude", "-p", "Q", "--output-format", "stream-json", "--verbose",
                          "--resume", SID, "--fork-session"])
        self.assertEqual(srv.build_codex_command({"path": "codex", "args": []}, "Q", SID, None, None),
                         ["codex", "exec", "resume", SID, "--json", "--skip-git-repo-check", "--", "Q"])

    def test_known_type_validation(self):
        with patch.object(srv.shutil, "which", return_value="/bin/grok"):
            srv._check_agents([self.owner])
        self.assertIn("grok", srv.AGENT_TYPES)


class FakeStdout:
    def __init__(self, events):
        self.lines = [((json.dumps(e) if not isinstance(e, str) else e) + "\n").encode() for e in events]

    async def readline(self):
        return self.lines.pop(0) if self.lines else b""


class FakeProcess:
    def __init__(self, events, code=0, on_wait=None):
        self.stdout = FakeStdout(events)
        self.returncode = code
        self.on_wait = on_wait

    async def wait(self):
        if self.on_wait:
            self.on_wait()
        return self.returncode


class RunnerTests(IsolatedStore, unittest.IsolatedAsyncioTestCase):
    async def run_mock(self, events=None, code=0, resume=None, fork=False, on_wait=None):
        self.events = []
        self.stream = []
        self.argv = None
        self.environment = None
        self.link_at_spawn = None

        async def spawn(*argv, **kwargs):
            self.argv = argv
            self.environment = kwargs["env"]
            self.link_at_spawn = srv.get_real_session_id("short-id")
            real_id = self.link_at_spawn
            actual = events if events is not None else [
                {"type": "system", "subtype": "init", "session_id": real_id, "model": "stream-model"},
                {"type": "assistant", "message": {"content": [
                    {"type": "thinking", "thinking": "Considering"},
                    {"type": "tool_use", "id": "tool-1", "name": "read_file", "input": {"path": "a"}}]}},
                {"type": "user", "message": {"content": [
                    {"type": "tool_result", "tool_use_id": "tool-1", "content": "Read output"}]}},
                {"type": "assistant", "message": {"content": [{"type": "text", "text": "Answer"}]}},
                {"type": "result", "result": "Answer", "subtype": "success", "is_error": False}]
            self.session([], sid=real_id, generated_title="Final title",
                         current_model_id="persisted-model", reasoning_effort="high")
            return FakeProcess(actual, code, on_wait)

        async def broadcast(e):
            self.events.append(e)

        with patch.object(srv.asyncio, "create_subprocess_exec", side_effect=spawn), \
                patch.object(srv, "broadcast_event", side_effect=broadcast), \
                patch.object(srv, "push_stream", side_effect=lambda sid, text: self.stream.append(text)), \
                patch.object(srv, "find_session_jsonl", side_effect=AssertionError("Claude metadata accessed")), \
                patch.object(srv, "delete_claude_session_files", side_effect=AssertionError("Claude cleanup accessed")), \
                patch.object(srv, "delete_codex_session_files", side_effect=AssertionError("Codex cleanup accessed")):
            await srv.run_agent_command("short-id", 'verbatim\n"prompt"', "", resume, fork,
                                        "requested-model", "medium", "Grok")

    async def test_success_uuid_link_env_steps_and_metadata(self):
        self.seed_app()
        await self.run_mock()
        self.assertTrue(srv.is_grok_session_id(self.link_at_spawn))
        self.assertNotEqual(self.link_at_spawn, "short-id")
        self.assertEqual(self.argv[self.argv.index("--session-id") + 1], self.link_at_spawn)
        self.assertEqual(self.argv[2], 'verbatim\n"prompt"')
        self.assertEqual(self.environment["GROK_HOME"], str(self.home))
        self.assertNotIn("--verbose", self.argv)
        self.assertNotIn("--include-partial-messages", self.argv)
        self.assertNotIn("--yolo", self.argv)
        row = self.rows("sessions")[0]
        self.assertEqual((row["model"], row["thinking_level"], row["subject"]),
                         ("persisted-model", "high", "Final title"))
        reply = self.rows()[0]
        self.assertEqual(reply["summary_output"], "Answer")
        self.assertEqual(reply["sender"], "claude")
        self.assertEqual([s["type"] for s in json.loads(reply["expanded_thoughts"])],
                         ["thought", "call", "response", "message"])
        self.assertEqual(self.events[-1]["type"], "session_completed")
        self.assertEqual(self.stream[-1], None)

    async def test_resume_and_fork(self):
        self.seed_app("source", SID)
        self.session([])
        self.seed_app(real_id=SID)
        await self.run_mock(resume="source")
        self.assertEqual(self.link_at_spawn, SID)
        self.assertNotIn("--session-id", self.argv)
        await self.run_mock(resume="source", fork=True)
        self.assertNotEqual(self.link_at_spawn, SID)
        self.assertEqual(self.argv[self.argv.index("--resume") + 1], SID)
        self.assertIn("--fork-session", self.argv)

    async def test_missing_resume_records_error_without_spawn(self):
        self.seed_app()
        await self.run_mock(resume="missing")
        self.assertIsNone(self.argv)
        self.assertIn("resume session is missing", self.rows()[0]["summary_output"])
        self.assertEqual(self.events[-1]["type"], "session_completed")

    async def test_result_errors_missing_terminal_and_exit_status(self):
        cases = [([{"type": "result", "result": "partial", "is_error": True,
                    "subtype": "error_during_execution", "errors": ["native failed"]}], 0, "native failed"),
                 ([{"type": "assistant", "message": {"content": [{"type": "text", "text": "partial"}]}}],
                  0, "without a terminal result"),
                 ([{"type": "result", "result": "looks fine", "subtype": "success"}], 7, "code 7"),
                 ([{"type": "result", "stop_reason": "cancelled"}], 0, "cancelled")]
        self.seed_app()
        for events, code, expected in cases:
            with self.subTest(expected=expected):
                with closing(srv.get_db()) as db, db:
                    db.execute("DELETE FROM messages")
                await self.run_mock(events, code)
                self.assertIn(expected, self.rows()[0]["summary_output"])
                self.assertTrue(self.rows()[0]["summary_output"].startswith("Error running Grok:"))
                self.assertEqual(self.events[-1]["type"], "session_completed")

    async def test_subject_lock_and_cancelled_state_preserved(self):
        self.seed_app(locked=1)
        with closing(srv.get_db()) as db, db:
            db.execute("UPDATE sessions SET status='cancelled'")
        await self.run_mock()
        self.assertEqual(self.rows("sessions")[0]["subject"], "Opening prompt")
        self.assertEqual(self.rows("sessions")[0]["status"], "cancelled")

    async def test_task_cancellation_stops_mock_process(self):
        self.seed_app()
        proc = FakeProcess([])
        proc.stdout.readline = AsyncMock(side_effect=asyncio.CancelledError)
        stop = AsyncMock(side_effect=lambda *a, **k: srv._forget_run("short-id"))
        srv.ACTIVE_RUNS.add("short-id")
        with patch.object(srv.asyncio, "create_subprocess_exec", return_value=proc), \
                patch.object(srv, "stop_run", stop):
            with self.assertRaises(asyncio.CancelledError):
                await srv.run_agent_command("short-id", "Q", "", agent="Grok")
        stop.assert_awaited_once_with("short-id")
        self.assertNotIn("short-id", srv.ACTIVE_RUNS)
        self.assertEqual(self.rows(), [])

    async def test_tombstone_exception_cleans_session_directory(self):
        self.seed_app()
        created = []
        async def spawn(*args, **kwargs):
            real = srv.get_real_session_id("short-id")
            created.append(self.session([], sid=real))
            proc = FakeProcess([])
            async def fail():
                srv.DELETED_SESSIONS["short-id"] = 1
                with closing(srv.get_db()) as db, db:
                    db.execute("DELETE FROM sessions")
                raise RuntimeError("broken stream")
            proc.stdout.readline = fail
            return proc
        stop = AsyncMock(side_effect=lambda *a, **k: srv._forget_run("short-id"))
        with patch.object(srv.asyncio, "create_subprocess_exec", side_effect=spawn), \
                patch.object(srv, "stop_run", stop), patch.object(srv.traceback, "print_exc"):
            await srv.run_agent_command("short-id", "Q", "", agent="Grok")
        self.assertFalse(created[0].exists())
        self.assertEqual(self.rows("sessions"), [])

    async def test_tombstone_late_result_exact_owner_cleanup(self):
        self.seed_app()
        neighbor = self.session([], sid=OTHER)
        def tombstone():
            srv.DELETED_SESSIONS["short-id"] = 1
            with closing(srv.get_db()) as db, db:
                db.execute("DELETE FROM sessions WHERE id='short-id'")
        await self.run_mock(on_wait=tombstone)
        self.assertEqual(self.rows("sessions"), [])
        self.assertIsNone(srv.find_grok_session(self.link_at_spawn, self.owner))
        self.assertTrue(neighbor.exists())
        self.assertEqual(self.events[-1]["type"], "session_steps")


class CleanupTests(IsolatedStore, unittest.TestCase):
    def test_directory_neighbors_shared_history_and_index_fts(self):
        target = self.session([])
        neighbor = self.session([], sid=OTHER)
        history = target.parent / "prompt_history.jsonl"
        history.write_text("shared prompts\n")
        index = self.home / "sessions" / "session_search.sqlite"
        with closing(sqlite3.connect(index)) as db, db:
            db.executescript("""
                CREATE TABLE session_docs(session_id TEXT PRIMARY KEY, cwd TEXT, title TEXT, content TEXT);
                CREATE VIRTUAL TABLE session_docs_fts USING fts5(title, content, content='session_docs');
                CREATE TRIGGER session_docs_ai AFTER INSERT ON session_docs BEGIN
                    INSERT INTO session_docs_fts(rowid,title,content) VALUES(new.rowid,new.title,new.content);
                END;
                CREATE TRIGGER session_docs_ad AFTER DELETE ON session_docs BEGIN
                    INSERT INTO session_docs_fts(session_docs_fts,rowid,title,content)
                    VALUES('delete',old.rowid,old.title,old.content);
                END;
            """)
            db.executemany("INSERT INTO session_docs VALUES(?,?,?,?)",
                           [(SID, str(self.workspace), "target", "alpha"),
                            (OTHER, str(self.workspace), "neighbor", "beta")])
        self.assertEqual(srv.delete_grok_session_files(SID, self.owner), 1)
        self.assertFalse(target.exists())
        self.assertTrue(neighbor.exists())
        self.assertEqual(history.read_text(), "shared prompts\n")
        with closing(sqlite3.connect(index)) as db, db:
            self.assertEqual(db.execute("SELECT session_id FROM session_docs").fetchall(), [(OTHER,)])
            self.assertEqual(db.execute("SELECT title FROM session_docs_fts WHERE session_docs_fts MATCH 'alpha'").fetchall(), [])
            self.assertEqual(db.execute("SELECT title FROM session_docs_fts WHERE session_docs_fts MATCH 'beta'").fetchall(), [("neighbor",)])

    def test_invalid_ids_and_metadata_mismatch_preserve_files(self):
        path = self.session([])
        for invalid in (None, "", "short-id", "../" + SID, SID + "/../" + OTHER):
            self.assertEqual(srv.delete_grok_session_files(invalid, self.owner), 0)
            self.assertTrue(path.exists())
        data = json.loads((path / "summary.json").read_text())
        data["info"]["id"] = OTHER
        (path / "summary.json").write_text(json.dumps(data))
        self.assertEqual(srv.delete_grok_session_files(SID, self.owner), 0)
        self.assertTrue(path.exists())

    def test_missing_index_is_not_created_and_wrong_cwd_row_remains(self):
        self.session([])
        index = self.home / "sessions" / "session_search.sqlite"
        srv.delete_grok_session_files(SID, self.owner)
        self.assertFalse(index.exists())
        self.session([])
        with closing(sqlite3.connect(index)) as db, db:
            db.execute("CREATE TABLE session_docs(session_id TEXT,cwd TEXT)")
            db.execute("INSERT INTO session_docs VALUES(?,?)", (SID, "/different-cwd"))
        srv.delete_grok_session_files(SID, self.owner)
        with closing(sqlite3.connect(index)) as db, db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM session_docs").fetchone()[0], 1)

    def test_symlink_session_group_summary_and_index_isolation(self):
        target = self.session([])
        outside = self.base / "outside"
        target.rename(outside)
        target.symlink_to(outside, target_is_directory=True)
        self.assertEqual(srv.delete_grok_session_files(SID, self.owner), 0)
        self.assertTrue(outside.exists())
        target.unlink()
        target.parent.rmdir()
        target.parent.symlink_to(outside.parent, target_is_directory=True)
        self.assertEqual(srv.delete_grok_session_files(SID, self.owner), 0)
        target.parent.unlink()
        target = self.session([])
        summary = target / "summary.json"
        copied = self.base / "summary.json"
        summary.rename(copied)
        summary.symlink_to(copied)
        self.assertEqual(srv.delete_grok_session_files(SID, self.owner), 0)
        summary.unlink()
        copied.rename(summary)
        external_index = self.base / "external.sqlite"
        with closing(sqlite3.connect(external_index)) as db, db:
            db.execute("CREATE TABLE session_docs(session_id TEXT,cwd TEXT)")
            db.execute("INSERT INTO session_docs VALUES(?,?)", (SID, str(self.workspace)))
        (self.home / "sessions" / "session_search.sqlite").symlink_to(external_index)
        srv.delete_grok_session_files(SID, self.owner)
        with closing(sqlite3.connect(external_index)) as db, db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM session_docs").fetchone()[0], 1)

    def test_store_root_symlink_and_owned_child_symlink(self):
        path = self.session([])
        root = self.home / "sessions"
        outside_root = self.base / "other-sessions"
        root.rename(outside_root)
        root.symlink_to(outside_root, target_is_directory=True)
        self.assertEqual(srv.delete_grok_session_files(SID, self.owner), 0)
        root.unlink()
        outside_root.rename(root)
        external_file = self.base / "unrelated.txt"
        external_file.write_text("preserved")
        (path / "linked-artifact").symlink_to(external_file)
        self.assertEqual(srv.delete_grok_session_files(SID, self.owner), 1)
        self.assertEqual(external_file.read_text(), "preserved")

    def test_dispatch_known_and_removed_agents(self):
        with patch.object(srv, "delete_claude_session_files") as claude, \
                patch.object(srv, "delete_codex_session_files") as codex, \
                patch.object(srv, "delete_grok_session_files") as grok:
            srv.delete_agent_session_files(SID, "short-id", "", "Grok")
            grok.assert_called_once_with(SID, self.owner)
            claude.assert_not_called()
            codex.assert_not_called()
            grok.reset_mock()
            srv.delete_agent_session_files(SID, "short-id", "", "Removed agent")
            self.assertEqual(claude.call_count, 2)
            self.assertEqual(codex.call_count, 2)
            grok.assert_not_called()
            claude.reset_mock()
            codex.reset_mock()
            srv.delete_agent_session_files(SID, "short-id", "", agent_cfg={"type": "claude"})
            self.assertEqual(claude.call_count, 2)
            codex.assert_not_called()
            claude.reset_mock()
            srv.delete_agent_session_files(SID, "short-id", "", agent_cfg={"type": "codex"})
            self.assertEqual(codex.call_count, 2)
            claude.assert_not_called()


@unittest.skipUnless(srv.HAS_FASTAPI, "FastAPI not installed")
class EndpointCleanupTests(IsolatedStore, unittest.IsolatedAsyncioTestCase):
    async def test_endpoint_stops_before_deleting_and_uses_exact_owner(self):
        path = self.session([])
        self.seed_app(real_id=SID)
        async def stop(*args, **kwargs):
            self.assertTrue(path.exists())
            self.assertTrue(self.rows("sessions"))
        with patch.object(srv, "stop_run", side_effect=stop) as stopped, \
                patch.object(srv, "delete_claude_session_files", side_effect=AssertionError), \
                patch.object(srv, "delete_codex_session_files", side_effect=AssertionError):
            await srv.delete_session("short-id")
        stopped.assert_awaited_once_with("short-id", interrupted=False)
        self.assertFalse(path.exists())
        self.assertEqual(self.rows("sessions"), [])
        self.assertIn("short-id", srv.DELETED_SESSIONS)


if __name__ == "__main__":
    unittest.main()
