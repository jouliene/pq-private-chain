"""Trusted local enrollment of the two intended role endpoints, outside coordinator control."""
from contextlib import ExitStack
import os
from pathlib import Path
import socket
import subprocess
import sys


def run_paired(public, coordinator, *, allow_maker_conflict=False):
    """Only owners inherit the two ends of the authenticated, one-record enrollment link."""
    here = Path(__file__).resolve().parent
    wallets = []
    try:
        with ExitStack() as stack:
            enrollment = socket.socketpair(type=socket.SOCK_SEQPACKET)
            for sock in enrollment:
                stack.callback(sock.close)
            driver_pipes = []
            for slot in range(2):
                read_request, write_request = os.pipe()
                read_reply, write_reply = os.pipe()
                driver_pipes.extend((stack.enter_context(os.fdopen(read_reply,"rb")),
                                     stack.enter_context(os.fdopen(write_request,"wb"))))
                enroll_fd = enrollment[slot].fileno()
                with os.fdopen(read_request,"rb") as owner_in, os.fdopen(write_reply,"wb") as owner_out:
                    wallet_args = ["--fixture-conflict"] if allow_maker_conflict and slot==0 else []
                    wallets.append(subprocess.Popen(
                        [sys.executable,"-B",here/"swap_owner.py",str(slot),public,str(enroll_fd),*wallet_args],
                        stdin=owner_in,stdout=owner_out,pass_fds=(enroll_fd,)))
            for sock in enrollment:
                sock.close()
            fds = [stream.fileno() for stream in driver_pipes]
            driver = subprocess.Popen([*coordinator,"--wallet-fds",*map(str,fds)],pass_fds=fds)
            for stream in driver_pipes:
                stream.close()
            if driver.wait():
                raise subprocess.CalledProcessError(driver.returncode,coordinator)
    finally:
        for wallet in wallets:
            wallet.wait()
    if any(wallet.returncode for wallet in wallets):
        raise RuntimeError("wallet process failed")
