"""Public closure grammar/copy controls only; no native replay or proof execution."""
from pathlib import Path
import hashlib
import importlib.util
import json
import tempfile
import unittest
import sys
sys.dont_write_bytecode=True
spec=importlib.util.spec_from_file_location('public_replay_controls',Path(__file__).with_name('public_replay.py'))
replay=importlib.util.module_from_spec(spec);spec.loader.exec_module(replay)


class PublicClosureControls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name).resolve()
        self.file=self.root/'public.bin';self.file.write_bytes(b'PUBLIC_TEST_BYTES')
        self.entry={'path':'public.bin','sha256':hashlib.sha256(self.file.read_bytes()).hexdigest(),'bytes':self.file.stat().st_size}

    def tearDown(self):self.temp.cleanup()

    def test_exact_labels_and_arities(self):
        self.assertEqual(len(replay.LABELS),264)
        self.assertEqual(len(set(replay.LABELS)),264)
        self.assertEqual(sum(replay.label_arity(x)==0 for x in replay.LABELS),2)
        self.assertEqual(sum(replay.label_arity(x)==1 for x in replay.LABELS),5)
        self.assertEqual(sum(replay.label_arity(x)==2 for x in replay.LABELS),257)

    def test_normalized_relative_paths_only(self):
        for name in ('../public.bin','/public.bin','x/../public.bin','./public.bin','x//public.bin','x\\public.bin'):
            with self.assertRaises(ValueError):replay.artifact(self.root,{**self.entry,'path':name},100)

    def test_symlink_is_not_an_artifact(self):
        (self.root/'linked').symlink_to(self.file)
        with self.assertRaises(ValueError):replay.artifact(self.root,{**self.entry,'path':'linked'},100)
        (self.root/'dir').symlink_to(self.root,target_is_directory=True)
        with self.assertRaises(ValueError):replay.artifact(self.root,{**self.entry,'path':'dir/public.bin'},100)

    def test_size_cap_precedes_copy(self):
        with self.assertRaises(ValueError):replay.artifact(self.root,self.entry,2)
        with self.assertRaises(ValueError):replay.artifact(self.root,{**self.entry,'bytes':True},100)

    def test_exact_hash_copy_and_exclusive_destination(self):
        out=self.root/'copied'
        replay.copy_public(replay.artifact(self.root,self.entry,100),out,self.entry)
        self.assertEqual(out.read_bytes(),self.file.read_bytes())
        with self.assertRaises(FileExistsError):replay.copy_public(self.file,out,self.entry)

    def test_bad_digest_preserves_failed_copy(self):
        out=self.root/'failed-copy'
        with self.assertRaisesRegex(ValueError,'copied_public_digest'):
            replay.copy_public(self.file,out,{**self.entry,'sha256':'0'*64})
        self.assertTrue(out.exists())

    def test_json_approval_binds_actual_read_bytes(self):
        path=self.root/'manifest.json';raw=b'{"public":1}';path.write_bytes(raw)
        self.assertEqual(replay.read_json(path,100,hashlib.sha256(raw).hexdigest()),{'public':1})
        with self.assertRaisesRegex(ValueError,'actual_public_json_approval'):replay.read_json(path,100,'0'*64)
        path.write_bytes(b'{"public":1,"public":2}')
        with self.assertRaisesRegex(ValueError,'duplicate_public_json'):replay.read_json(path,100)

    def test_reference_is_exact14_and_digest_only(self):
        value={name:{'rows':0,'sha256':'0'*64} for name in replay.TABLES}
        replay.validate_reference(value)
        with self.assertRaises(ValueError):replay.validate_reference({**value,'extra':{'rows':0,'sha256':'0'*64}})
        value['meta']['rows']=True
        with self.assertRaises(ValueError):replay.validate_reference(value)


if __name__=='__main__':unittest.main()
