"""Cheap public IPC grammar controls; no wallet/native/proof/namespace execution."""
from pathlib import Path
import importlib.util
import json
import selectors
import struct
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
path = Path(__file__).resolve().with_name('run.py')
spec = importlib.util.spec_from_file_location('wallet_runner_controls', path)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class PublicFrameOwner:
    def __init__(self):
        self.proofs = []
        self.backup = None
        self.rpc_called = False

    def rpc(self, actor, value):
        self.rpc_called = True
        raise AssertionError('unit control must not invoke a controller')


class FrameControls(unittest.TestCase):
    def setUp(self):
        self.owner = PublicFrameOwner()
        self.actor = runner.Actor(self.owner, False)

    def tearDown(self):
        self.actor.selector.close()
        self.actor.stdout[:] = b'\0' * len(self.actor.stdout)
        if self.owner.backup is not None:
            self.owner.backup[:] = b'\0' * len(self.owner.backup)

    def inject(self, kind, data):
        self.actor.stdout.extend(struct.pack('<BI', kind, len(data)) + data)
        self.actor.parse_frames()

    def test_fragmented_backup_moves_only_into_ram_owner(self):
        # Deliberately public test bytes, not a key/backup fixture.
        data = b'PUBLIC_TEST_BYTES'
        wire = struct.pack('<BI', 4, len(data)) + data
        for value in wire[:-1]:
            self.actor.stdout.append(value)
            self.actor.parse_frames()
            self.assertIsNone(self.owner.backup)
        self.actor.stdout.append(wire[-1])
        self.actor.parse_frames()
        self.assertEqual(self.owner.backup, data)
        self.assertEqual(self.actor.stdout, bytearray())
        self.assertFalse(self.owner.rpc_called)

    def test_second_backup_fails_without_replacing_first(self):
        self.inject(4, b'PUBLIC_FIRST')
        with self.assertRaisesRegex(ValueError, '^single_private_backup$'):
            self.inject(4, b'PUBLIC_SECOND')
        self.assertEqual(self.owner.backup, b'PUBLIC_FIRST')
        self.assertEqual(self.actor.stdout, bytearray())

    def test_restore_cannot_emit_original_backup(self):
        self.actor.restore = True
        with self.assertRaisesRegex(ValueError, '^single_private_backup$'):
            self.inject(4, b'PUBLIC_TEST')
        self.assertIsNone(self.owner.backup)

    def test_oversized_private_frame_rejected_at_header(self):
        self.actor.stdout.extend(struct.pack('<BI', 4, runner.PRIVATE_CAP + 1))
        with self.assertRaisesRegex(ValueError, '^wallet_frame_cap$'):
            self.actor.parse_frames()
        self.assertIsNone(self.owner.backup)

    def test_membership_rpc_rejected_before_controller(self):
        with self.assertRaisesRegex(ValueError, '^fixed_rpc_grammar$'):
            self.inject(1, b'{"op":"membership","index":"PUBLIC_TEST"}')
        self.assertFalse(self.owner.rpc_called)
        self.assertEqual(self.actor.stdout, bytearray())

    def test_unknown_terminal_field_not_persisted(self):
        value = {'format':'CP04-ISOLATED-WALLET-DONE01', 'restore':False, 'counts':{},
                 'process_self':{}, 'private_material_persisted_or_hashed':False, 'unrecognized':'PUBLIC_TEST'}
        with self.assertRaisesRegex(ValueError, '^fixed_terminal_metrics$'):
            self.inject(5, json.dumps(value).encode())
        self.assertIsNone(self.actor.done)
        self.assertEqual(self.actor.stdout, bytearray())

    def test_duplicate_json_rejected(self):
        with self.assertRaisesRegex(ValueError, '^duplicate_json$'):
            runner.decode(b'{"op":"scan","op":"context"}')


class PermissionRaceControls(unittest.TestCase):
    def identity(self, state='R', start=100):
        return {'state':state,'starttime_ticks':start,'cpu_ticks':{
            'self_user':0,'self_system':0,'reaped_child_user':0,'reaped_child_system':0}}

    def test_only_same_bound_zombie_or_dead_is_confirmed(self):
        for state in ('Z','X'):
            with patch.object(runner,'proc_identity',return_value=self.identity(state)):
                self.assertTrue(runner.permission_exit_evidence(123,100)['confirmed_exit'])
        for state,expected,start in [('R',100,100),('Z',100,101),('Z',None,100)]:
            with patch.object(runner,'proc_identity',return_value=self.identity(state,start)):
                self.assertFalse(runner.permission_exit_evidence(123,expected)['confirmed_exit'])

    def test_missing_stat_alone_is_not_confirmed(self):
        with patch.object(runner,'proc_identity',side_effect=FileNotFoundError()), \
             patch.object(runner.Path,'stat',return_value=object()):
            self.assertFalse(runner.permission_exit_evidence(123,100)['confirmed_exit'])
        with patch.object(runner,'proc_identity',side_effect=FileNotFoundError()), \
             patch.object(runner.Path,'stat',side_effect=FileNotFoundError()):
            self.assertTrue(runner.permission_exit_evidence(123,100)['confirmed_exit'])

    def test_inaccessible_liveness_stays_failure(self):
        with patch.object(runner,'proc_identity',side_effect=PermissionError(13,'PUBLIC_TEST')):
            evidence=runner.permission_exit_evidence(123,100)
            self.assertFalse(evidence['confirmed_exit'])
            self.assertEqual(evidence['classification'],'unreadable')

    def test_sampler_skips_only_confirmed_same_identity_exit(self):
        actor=runner.Actor(PublicFrameOwner(),False);actor.node_pid=123
        try:
            with patch.object(runner,'proc_identity',side_effect=[self.identity(),self.identity('Z')]), \
                 patch.object(runner,'proc_status',side_effect=PermissionError(13,'DO_NOT_RECORD_THIS')):
                self.assertEqual(actor.sample(force=True),[])
            self.assertEqual(actor.permission_exit_count,1)
            self.assertEqual(actor.permission_exit_races[0]['operation'],'status')
            self.assertEqual(actor.permission_exit_races[0]['errno'],13)
            self.assertNotIn('DO_NOT_RECORD_THIS',repr(actor.permission_exit_races))
        finally:actor.selector.close()

    def test_sampler_live_permission_is_fatal_and_metadata_only(self):
        actor=runner.Actor(PublicFrameOwner(),False);actor.node_pid=123
        try:
            with patch.object(runner,'proc_identity',return_value=self.identity()), \
                 patch.object(runner,'proc_status',side_effect=PermissionError(13,'DO_NOT_RECORD_THIS')):
                with self.assertRaises(PermissionError):actor.sample(force=True)
            evidence=actor.public_result['proc_observation_failure']
            self.assertEqual(evidence['classification'],'live')
            self.assertEqual(evidence['operation'],'status')
            self.assertEqual(evidence['error_type'],'PermissionError')
            self.assertEqual(evidence['errno'],13)
            self.assertEqual(actor.permission_exit_count,0)
            self.assertNotIn('DO_NOT_RECORD_THIS',repr(actor.public_result))
        finally:actor.selector.close()


if __name__ == '__main__':
    unittest.main()
