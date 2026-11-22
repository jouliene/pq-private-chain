"""Calibrate the rules identity on two isolated, clean registered deployments."""
import argparse
import json
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from node_deployment import deployment_id
from stage import install


def check(source):
    with TemporaryDirectory() as tmp:
        first=install(source,Path(tmp)/"one")
        second=install(source,Path(tmp)/"two")
        expected=deployment_id(first)
        assert deployment_id(second)==expected
        path=second/"experiments/advancing-payments/ingress.py"
        original=path.read_bytes()
        path.write_bytes(original+b"\nInvalid syntax in the calibration copy only.\n")
        changed=deployment_id(second)
        assert changed!=expected
        path.write_bytes(original)
        os.chmod(path,0o640)
        os.utime(path,ns=(1234567890,1234567890))
        assert deployment_id(second)==expected
        cache=path.parent/"__pycache__"
        cache.mkdir()
        (cache/"ingress.cpython-312.pyc").write_bytes(b"generated cache stand-in")
        assert deployment_id(second)==expected
        (second/"unexpected-empty-dir").mkdir()
        assert deployment_id(second)!=expected
        (second/"link").symlink_to(first/"runtime/native")
        try:
            deployment_id(second)
        except ValueError as exc:
            assert "link or special file" in str(exc)
        else:
            raise AssertionError("deployment symlink accepted")
        return dict(clean_rules_sha256=expected,changed_ingress_sha256=changed,restoration=True,
                    files=sum(p.is_file() for p in first.rglob("*")),metadata_independent=True,
                    ignored_generated_cache=True,symlink_rejected=True)


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("registered_source",type=Path)
    print(json.dumps(check(parser.parse_args().registered_source),sort_keys=True))
