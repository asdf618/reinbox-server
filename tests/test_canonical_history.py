import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import reinbox_server as server


class CanonicalHistoryTest(unittest.TestCase):
    SID = '10000000-0000-4000-8000-000000000001'
    B = '10000000-0000-4000-8000-000000000002'
    C = '10000000-0000-4000-8000-000000000003'
    TS = 1700000000000

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve()
        self.root = self.home / 'workspace'
        self.root.mkdir()
        self.addCleanup(patch.stopall)
        patch.object(server, 'CONFIG', {'root_dir': str(self.root),
            'db_path': str(self.home / 'test.db'), 'agents': [
                {'name': 'Runner', 'type': 'codex', 'home_dir': str(self.home), 'scope': 'workspace'}]}).start()
        patch.object(server, 'RUNNING_PROCESSES', {}).start()
        self.directory = self.home / 'sessions' / '2024' / '01' / '01'
        self.directory.mkdir(parents=True)
        server.init_db()

    def record(self, kind, payload, offset=0):
        return {'type': kind, 'timestamp': self.TS + offset, 'payload': payload}

    def completion(self, tid, text, assistant=False, offset=0):
        return self.record('history_mutation', {'version': 1, 'operation': 'append',
            'turn_id': tid, 'display_completions': [{'turn_id': tid,
                'started_at_ms': self.TS + offset, 'completed_at_ms': self.TS + offset,
                'item': {'type': 'AgentMessage' if assistant else 'UserMessage',
                         'id': ('a-' if assistant else 'u-') + tid,
                         'content': [{'text': text}], 'phase': 'final_answer'}}]}, offset)

    def write(self, physical, number, events, base=None):
        suffix = self.SID if physical == self.SID else self.SID + '_' + physical
        path = self.directory / f'rollout-2024-01-01T00-00-{number:02}-{suffix}.jsonl'
        head = self.record('session_meta', {'id': self.SID, 'cwd': str(self.root),
            'timestamp': '2023-11-14T22:13:20Z', 'thread_source': 'user',
            'history_format': 'canonical_v1', 'history_base': base})
        payload = ''.join(json.dumps(e) + '\n' for e in [head, *events]).encode()
        path.write_bytes(payload)
        inherited = base['end_ordinal_exclusive'] if base else 0
        return path, {'thread_id': physical, 'end_byte_offset': len(payload),
                      'end_ordinal_exclusive': inherited + len(events) + 1}

    def chain(self):
        a, ab = self.write(self.SID, 1, [self.completion('one', 'Repeat'),
            self.completion('one', 'Answer', True, 10)])
        with a.open('a') as f:
            f.write(json.dumps(self.completion('discard-a', 'Excluded', offset=20)) + '\n')
        b, bc = self.write(self.B, 2, [self.completion('two', 'Repeat', offset=30),
            self.completion('two', 'Answer', True, 40)], ab)
        with b.open('a') as f:
            f.write(json.dumps(self.completion('discard-b', 'Excluded', offset=50)) + '\n')
        c, _ = self.write(self.C, 3, [self.completion('three', 'Current', offset=60),
            self.completion('three', 'Working', True, 70)], bc)
        return a, b, c

    def parse(self, path):
        return server.parse_codex_rollout(str(path), server.codex_rollout_index(str(self.home)))

    def test_bounded_replay_and_repeated_text(self):
        a, b, c = self.chain()
        rec = self.parse(c)
        self.assertEqual([t['summary'] for t in rec['turns']],
                         ['Repeat', 'Answer', 'Repeat', 'Answer', 'Current', 'Working'])
        self.assertEqual(len({(t['turn_id'], t['sender']) for t in rec['turns']}), 6)

    def test_discovery_order_is_irrelevant(self):
        _, _, c = self.chain()
        entries = list(server.os.walk(str(self.home / 'sessions')))
        for listing in (entries, list(reversed(entries))):
            listing = [(d, dirs, list(reversed(files))) for d, dirs, files in listing]
            with patch.object(server.os, 'walk', return_value=iter(listing)):
                index = server.codex_rollout_index(str(self.home))
            self.assertEqual(index['heads'][self.SID]['path'], str(c))
        self.assertEqual(server.find_codex_rollout(self.SID), str(c))

    def test_thread_index_can_select_a_valid_tip(self):
        a, _ = self.write(self.SID, 1, [self.completion('one', 'One')])
        self.write(self.B, 2, [self.completion('two', 'Two')])
        with sqlite3.connect(self.home / 'state_5.sqlite') as conn:
            conn.execute('CREATE TABLE threads (id TEXT, rollout_path TEXT)')
            conn.execute('INSERT INTO threads VALUES (?, ?)', (self.SID, str(a)))
        self.assertEqual(server.find_codex_rollout(self.SID), str(a))

    def test_index_outside_store_is_ignored(self):
        a, _ = self.write(self.SID, 1, [self.completion('one', 'One')])
        with sqlite3.connect(self.home / 'state_5.sqlite') as conn:
            conn.execute('CREATE TABLE threads (id TEXT, rollout_path TEXT)')
            conn.execute('INSERT INTO threads VALUES (?, ?)', (self.SID, '/outside/session.jsonl'))
        self.assertEqual(server.find_codex_rollout(self.SID), str(a))

    def test_partial_tail_is_not_a_message(self):
        _, _, c = self.chain()
        with c.open('ab') as f:
            f.write(b'{"unfinished":')
        self.assertEqual(len(self.parse(c)['turns']), 6)

    def test_invalid_bounds_and_missing_ancestor(self):
        for base in ({'thread_id': self.B, 'end_byte_offset': 10, 'end_ordinal_exclusive': 1},
                     {'thread_id': self.SID, 'end_byte_offset': -1, 'end_ordinal_exclusive': 1}):
            p, _ = self.write(self.C, 3, [self.completion('three', 'Three')], base)
            self.assertIsNone(self.parse(p))

    def test_ordinal_mismatch(self):
        _, bound = self.write(self.SID, 1, [self.completion('one', 'One')])
        bound['end_ordinal_exclusive'] += 1
        p, _ = self.write(self.C, 3, [], bound)
        self.assertIsNone(self.parse(p))

    def test_cycle(self):
        self.write(self.SID, 1, [], {'thread_id': self.B, 'end_byte_offset': 0, 'end_ordinal_exclusive': 0})
        p, _ = self.write(self.B, 2, [], {'thread_id': self.SID, 'end_byte_offset': 0, 'end_ordinal_exclusive': 0})
        self.assertIsNone(self.parse(p))

    def test_unsupported_revision_retains_cached_session(self):
        p, _ = self.write(self.SID, 1, [self.completion('one', 'One')])
        server.reconcile_sessions(force=True)
        with p.open('a') as f:
            f.write(json.dumps(self.record('history_mutation', {'version': 1, 'operation': 'replace'})) + '\n')
        self.assertIsNone(self.parse(p))
        self.assertTrue(server.discover_transcripts()[self.SID]['unavailable'])
        server.reconcile_sessions(force=True)
        with server.get_db() as conn:
            self.assertIsNotNone(conn.execute('SELECT id FROM sessions WHERE id=?', (self.SID,)).fetchone())

    def test_projection_idempotence_metadata_and_local_input(self):
        _, _, c = self.chain()
        server.reconcile_sessions(force=True)
        with server.get_db() as conn:
            ids = [r[0] for r in conn.execute('SELECT id FROM messages ORDER BY id')]
            conn.execute('UPDATE sessions SET subject=?, subject_locked=1, is_read=1 WHERE id=?', ('Custom', self.SID))
            conn.execute("INSERT INTO messages (id,session_id,sender,timestamp,summary_output,expanded_thoughts) VALUES ('local',?,'me',?,'Pending','[]')", (self.SID,self.TS+100))
        self.assertEqual(server.reconcile_sessions(force=True), [])
        with server.get_db() as conn:
            self.assertEqual([r[0] for r in conn.execute("SELECT id FROM messages WHERE id!='local' ORDER BY id")], ids)
            row=conn.execute('SELECT * FROM sessions').fetchone()
            self.assertEqual((row['subject'],row['is_read'],row['last_message_by']),('Custom',1,'me'))
            self.assertIsNotNone(conn.execute("SELECT id FROM messages WHERE id='local'").fetchone())

    def test_rollover_removes_only_owned_tail(self):
        a, bound = self.write(self.SID, 1, [self.completion('one','One'),self.completion('one','Answer',True,10)])
        with a.open('a') as f:
            f.write(json.dumps(self.completion('discard','Discarded',offset=20))+'\n')
        server.reconcile_sessions(force=True)
        with server.get_db() as conn:
            original={r['summary_output']:r['id'] for r in conn.execute('SELECT * FROM messages')}
            conn.execute("INSERT INTO messages (id,session_id,sender,timestamp,summary_output,expanded_thoughts) VALUES ('local',?,'me',?,'Pending','[]')",(self.SID,self.TS+100))
        self.write(self.B,2,[self.completion('two','Two',offset=30)],bound)
        server.reconcile_sessions(force=True)
        with server.get_db() as conn:
            rows={r['summary_output']:r['id'] for r in conn.execute('SELECT * FROM messages')}
            self.assertNotIn('Discarded',rows)
            self.assertEqual(rows['One'],original['One'])
            self.assertIn('Pending',rows)

    def test_growth_updates_the_same_assistant(self):
        p,_=self.write(self.SID,1,[self.completion('one','One'),self.completion('one','Working',True,10)])
        server.reconcile_sessions(force=True)
        with server.get_db() as conn:
            mid=conn.execute("SELECT id FROM messages WHERE sender='claude'").fetchone()[0]
        update=self.completion('one','Finished',True,20)
        update['payload']['display_completions'][0]['item']['id']='final-one'
        with p.open('a') as f:f.write(json.dumps(update)+'\n')
        server.reconcile_sessions(force=True)
        with server.get_db() as conn:
            rows=conn.execute("SELECT id,summary_output FROM messages WHERE sender='claude'").fetchall()
            self.assertEqual([tuple(r) for r in rows],[(mid,'Finished')])

    def test_active_session_is_untouched(self):
        self.chain();server.reconcile_sessions(force=True)
        with server.get_db() as conn:conn.execute("UPDATE sessions SET status='active',is_read=1")
        with patch.object(server,'sync_canonical_projection') as sync:
            server.reconcile_sessions(force=True)
            sync.assert_not_called()

    def test_collapsed_derived_row_is_replaced_and_local_row_survives(self):
        p, _ = self.write(self.SID, 1, [self.completion('one', 'One'),
            self.record('event_msg', {'type': 'item_completed', 'turn_id': 'one',
                'item': {'type': 'CommandExecution', 'id': 'tool', 'command': 'pwd'}}, 5),
            self.completion('one', 'Answer', True, 10)])
        legacy = server.parse_codex_rollout(str(p), {})['turns'][0]
        with server.get_db() as conn:
            conn.execute("INSERT INTO sessions (id,claude_session_id,origin,status,agent,subject,subject_locked,is_read,last_turn_ts) VALUES (?,?,'external','completed','Runner','Custom',1,1,?)",
                         (self.SID,self.SID,self.TS+100))
            conn.execute("INSERT INTO messages (id,session_id,sender,timestamp,summary_output,expanded_thoughts) VALUES ('derived',?,?,?,?,?)",
                         (self.SID,legacy['sender'],legacy['timestamp'],legacy['summary'],json.dumps(legacy['steps'])))
            conn.execute("INSERT INTO messages (id,session_id,sender,timestamp,summary_output,expanded_thoughts) VALUES ('local',?,'me',?,'Pending','[]')",(self.SID,self.TS+100))
        server.reconcile_sessions(force=True)
        with server.get_db() as conn:
            messages = {r['id']:r['summary_output'] for r in conn.execute('SELECT * FROM messages')}
            self.assertNotIn('derived',messages)
            self.assertIn('One',messages.values())
            self.assertIn('Answer',messages.values())
            self.assertEqual(messages['local'],'Pending')
            self.assertEqual(conn.execute('SELECT is_read FROM sessions').fetchone()[0],1)

    def test_duplicate_completion_and_tool_representations(self):
        event = self.completion('one', 'Reply', True, 10)
        item = {'type': 'CommandExecution', 'id': 'tool', 'command': 'pwd', 'aggregated_output': '/project'}
        tool = self.record('event_msg', {'type': 'item_completed', 'turn_id': 'one', 'item': item}, 5)
        p, _ = self.write(self.SID, 1, [self.completion('one', 'One'), tool, tool, event, event])
        turns = self.parse(p)['turns']
        self.assertEqual(len(turns), 2)
        self.assertEqual([step['type'] for step in turns[1]['steps']], ['call', 'response', 'message'])

    def test_adopting_legacy_message_preserves_attachment(self):
        self.write(self.SID, 1, [self.completion('one', 'One'), self.completion('one', 'Answer', True, 10)])
        server.reconcile_sessions(force=True)
        with server.get_db() as conn:
            mid = conn.execute("SELECT id FROM messages WHERE sender='me'").fetchone()[0]
            conn.execute("UPDATE messages SET id='legacy', timestamp=? WHERE id=?", (self.TS - 20000, mid))
            conn.execute("INSERT INTO attachments (id,session_id,message_id,name) VALUES ('att',?,'legacy','image.png')", (self.SID,))
        server.reconcile_sessions(force=True)
        with server.get_db() as conn:
            self.assertEqual(conn.execute("SELECT message_id FROM attachments WHERE id='att'").fetchone()[0], mid)
            self.assertEqual(conn.execute("SELECT count(*) FROM messages WHERE sender='me'").fetchone()[0], 1)

    def test_incomplete_header_preserves_known_session(self):
        p, _ = self.write(self.SID, 1, [self.completion('one', 'One')])
        server.reconcile_sessions(force=True)
        p.write_bytes(b'{"type":"session_meta"')
        server.reconcile_sessions(force=True)
        with server.get_db() as conn:
            self.assertEqual(conn.execute('SELECT count(*) FROM sessions').fetchone()[0], 1)

    def test_reconcile_transaction_failure_rolls_back(self):
        self.chain()
        server.reconcile_sessions(force=True)
        with server.get_db() as conn:
            conn.execute('UPDATE sessions SET is_read=1')
            before = [tuple(r) for r in conn.execute('SELECT * FROM messages ORDER BY id')]
        original = server.sync_canonical_projection
        def fail(cur, existing, rec):
            original(cur, existing, rec)
            cur.execute('DELETE FROM messages')
            raise ValueError('test rollback')
        with patch.object(server, 'sync_canonical_projection', side_effect=fail):
            self.assertEqual(server.reconcile_sessions(force=True), [])
        with server.get_db() as conn:
            self.assertEqual([tuple(r) for r in conn.execute('SELECT * FROM messages ORDER BY id')], before)

    def test_legacy_item_format(self):
        p,_=self.write(self.SID,1,[])
        head=self.record('session_meta',{'id':self.SID,'cwd':str(self.root)})
        user=self.record('event_msg',{'type':'item_completed','item':{'type':'UserMessage','content':[{'text':'Legacy'}]}})
        reply=self.record('event_msg',{'type':'item_completed','item':{'type':'AgentMessage','content':[{'text':'Reply'}]}},10)
        for metadata in ({}, {'history_mode': 'paginated'},
                         {'history_mode': 'paginated', 'history_format': None}):
            with self.subTest(metadata=metadata):
                head['payload'].update(metadata)
                p.write_text(''.join(json.dumps(e)+'\n' for e in (head,user,reply)))
                self.assertEqual([t['summary'] for t in self.parse(p)['turns']],['Legacy','Reply'])
                self.assertFalse(server.discover_transcripts()[self.SID].get('unavailable'))

    def test_unknown_history_format_retains_cached_session(self):
        p, _ = self.write(self.SID, 1, [self.completion('one', 'One')])
        server.reconcile_sessions(force=True)
        records = [json.loads(line) for line in p.read_text().splitlines()]
        for metadata in ({'history_mode': 'paginated', 'history_format': 'canonical_v2'},
                         {'history_mode': 'paginated', 'history_format': None,
                          'history_base': {'thread_id': self.B}}):
            with self.subTest(metadata=metadata):
                records[0]['payload'].update(metadata)
                p.write_text(''.join(json.dumps(e)+'\n' for e in records))
                self.assertTrue(server.discover_transcripts()[self.SID]['unavailable'])
                server.reconcile_sessions(force=True)
                with server.get_db() as conn:
                    self.assertEqual(conn.execute('SELECT COUNT(*) FROM sessions').fetchone()[0], 1)
                    self.assertEqual(conn.execute('SELECT COUNT(*) FROM messages').fetchone()[0], 1)


if __name__ == '__main__':
    unittest.main()
