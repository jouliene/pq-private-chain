"""Reproduce a fresh 3-permutation proof with two independently frozen roots."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from kernel_checks import fixture

ROLE = Path(__file__).resolve().with_name("role.py")


def main():
    a,wa = fixture(0,2)
    b,wb = fixture(39,1)
    statement = b"SGP1\2\0"+a+b
    public = {"parents":3,"paths":2,"depths":[2,1],"flatten":3}
    with tempfile.TemporaryDirectory() as work:
        directory = Path(work)
        st,proof = directory/"expected",directory/"proof"
        st.write_bytes(statement)
        def role(action,*,data=b"",negative=False):
            p = subprocess.run([sys.executable,str(ROLE),action,str(st),str(proof),"--flatten","3"],
                               input=data,capture_output=True,cwd=directory)
            if negative:
                if p.returncode!=1 or b"rejected" not in p.stderr:
                    raise RuntimeError("missing public proof rejection")
                return p.stderr.decode().strip()
            if p.returncode:
                raise RuntimeError(p.stderr.decode())
            return json.loads(p.stdout)
        public["prover"] = role("prove",data=wa+wb)
        public["verifier"] = role("verify")
        public["packet_sha256"] = hashlib.sha256(proof.read_bytes()).hexdigest()
        for j,offset in enumerate((8,74)):
            corrupt = bytearray(statement)
            corrupt[offset]^=1
            st.write_bytes(corrupt)
            public[f"root_{j}_mutation"] = role("verify",negative=True)
    print(json.dumps(public,indent=2))


if __name__ == "__main__":
    main()
