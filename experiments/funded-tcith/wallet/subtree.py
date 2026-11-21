"""Sample a local owner process tree without reading its arguments, descriptors or memory contents."""
from pathlib import Path
import threading
import time

POLL_S = 0.05


def memory(pid):
    proc = Path('/proc') / str(pid)
    # The rollup contains aggregate kernel accounting for the process. PSS allocates each
    # shared page proportionally. Some Linux security configurations restrict the rollup.
    try:
        lines = (proc/'smaps_rollup').read_text().splitlines()
    except PermissionError:
        lines = (proc/'status').read_text().splitlines()
    values = {s.split()[0]: int(s.split()[1]) for s in lines if s.startswith(('Pss:', 'Rss:', 'VmRSS:'))}
    return values.get('Rss:', values.get('VmRSS:', 0)), values.get('Pss:')


def sample(root):
    queue = [root]
    seen = set()
    total_rss = total_pss = no_pss = 0
    while queue:
        pid = queue.pop()
        if pid in seen:
            continue
        seen.add(pid)
        proc = Path('/proc')/str(pid)
        try:
            for task in (proc/'task').iterdir():
                try:
                    queue.extend(map(int, (task/'children').read_text().split()))
                except (FileNotFoundError, ProcessLookupError):
                    pass
            rss, pss = memory(pid)
            total_rss += rss
            if pss is not None:
                total_pss += pss
            elif rss:
                no_pss += 1
        except (FileNotFoundError, ProcessLookupError):
            continue
    return total_rss, None if no_pss else total_pss


class OwnerMeter:
    def __init__(self, pid, launch_ns):
        self.pid = pid
        self.launch_ns = launch_ns
        self.samples = []
        self.done = threading.Event()
        self.error = None
        self.thread = threading.Thread(target=self.collect, daemon=True)
        self.thread.start()

    def collect(self):
        try:
            while not self.done.is_set():
                before = time.monotonic_ns()
                rss, pss = sample(self.pid)
                after = time.monotonic_ns()
                self.samples.append(((before+after)//2,rss,pss))
                self.done.wait(max(0., POLL_S-(after-before)/1e9))
        except Exception as exc:
            self.error = exc

    def close(self):
        self.done.set()
        self.thread.join()

    def result(self, stamps, end_ns):
        self.close()
        if self.error:
            raise RuntimeError('owner process accounting failed') from self.error
        times = [self.launch_ns, *stamps.values(), end_ns]
        if times != sorted(times) or not self.samples:
            raise ValueError('owner resource clock or sampler failed')

        def interval(start, end):
            rows = [row for row in self.samples if start <= row[0] < end]
            pss = [row[2] for row in rows if row[2] is not None]
            clock = [start, *(row[0] for row in rows), end]
            return dict(wall_s=round((end-start)/1e9, 6), samples=len(rows),
                        longest_gap_s=round(max(b-a for a,b in zip(clock,clock[1:]))/1e9, 4),
                        peak_sum_RSS_KiB=max((r[1] for r in rows), default=None),
                        peak_sum_PSS_KiB=max(pss) if rows and len(pss)==len(rows) else None)

        result = dict(sample_interval_s=POLL_S, full_owner=interval(self.launch_ns,end_ns),
                      prepare=interval(self.launch_ns,stamps['waiting']),
                      protocol_wait=interval(stamps['waiting'],stamps['authorization']),
                      verify_and_authorize=interval(stamps['authorization'],stamps['teardown']),
                      teardown=interval(stamps['teardown'],end_ns))
        if 'candidate_frontend' in stamps:
            result['candidate_frontend_and_prover'] = interval(stamps['candidate_frontend'],stamps['candidate_done'])
            result['candidate_frontend'] = interval(stamps['candidate_frontend'],stamps['candidate_prove'])
            result['candidate_prover'] = interval(stamps['candidate_prove'],stamps['candidate_done'])
        return result
