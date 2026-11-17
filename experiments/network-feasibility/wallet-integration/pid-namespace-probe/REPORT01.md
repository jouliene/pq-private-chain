# Public nested PID discriminator — allocation29

**Result: numeric PID collision produces the exact frozen forbidden-root failure
without demonstrating controller access.** One public attempt completed in
0.094497884s, with three explicit subprocess launches and one harmless Python
thread, plus bubblewrap's inherent namespace/reaper processes. No wallet,
original Controller, private config, key generation, proof, build or repair ran.
The raw safe metadata is [RESULT01.json](RESULT01.json); reproducible public source
is [probe.py](probe.py). Do not overwrite this result with another attempt.

The launch preserved the independent reviewer's actual outer argv from the clean
clone's `.work/gate5-supervision/small01-command.json`, replacing only the public
stdin program. The outer PID namespace held a public supervisor and harmless
controller, reproducing controller PID3. The controller used the unchanged
`isolation.command` and fixed seccomp filter for an inner Python diagnostic, with
no mounted project trees. A harmless inner thread intentionally occupied TID3.
This tests the proposed collision rather than depending on scheduler luck.

| Identity | PID/TID | TGID | starttime ticks | PID namespace | mount namespace |
|---|---:|---:|---:|---|---|
| Public controller | 3 | process | 86032965 | pid:[4026532891] | mnt:[4026532890] |
| Inner PID1 | 1 | 1 | 86032967 | pid:[4026532897] | mnt:[4026532894] |
| Inner Python | 2 | 2 | 86032968 | pid:[4026532897] | mnt:[4026532894] |
| Inner thread, also `/proc/3` candidate | 3 | 2 | 86032970 | pid:[4026532897] | mnt:[4026532894] |

The inner `/proc/3/root` existed and resolved to the same root inode as inner
PID1/self. Its PID namespace, mount namespace, starttime and TGID identify an
inner Python thread, distinct from the outer controller. Calling the actual
frozen `inspect()` function rejected it with exactly:

```text
ValueError: host process root inaccessible
```

Every preceding check was also recorded separately:

* Both actual failed-attempt forbidden paths returned ENOENT. The public sentinel
  was successfully opened read-only by the outer controller before launch, so
  its inner absence was not simply a nonexistent sentinel control.
* Three inherited descriptors were checked against the sentinel's actual
  device/inode; none matched. The transient `/proc/self/fd` enumeration descriptor
  returned the explicitly permitted EBADF. An inheritable sentinel FD held in the
  controller was excluded by the actual close-fds/pass-filter-only launch.
* AF_INET, AF_INET6 and AF_UNIX socket creation each returned EPERM.
* The diagnostic reported seccomp mode2. Inner PID1/self/thread share a PID
  namespace different from the controller's. Outer, controller and inner command
  exits were all0, with empty stderr. The frozen probe's rejection is a recorded
  observation, not a PASS of the old boundary assertion.

Inspected frozen source SHA256:

* `isolation.py`: `f5c3bef9b6ff6123d2f2d5cb7b2b2357eccb700e85f5fdf15ca3e316d70aff28`
* `isolation_probe.py`: `a2b0507309cfed1620708dbd4cb1aae7ceeb54b906cb618e311d77ed39dfcc52`

## Correction implications

It is justified to replace the cross-namespace numeric-existence assertion with a
reviewed namespace/identity-aware assertion. Capture the controller's PID namespace
before launch; require the child's actual PID namespace and its PID1 namespace to
exclude it. If the same numeric `/proc` path exists, classify its identity in that
namespace rather than treating existence as outer-root access. Any unreadable or
ambiguous identity must remain fail-closed under the separately reviewed policy.
Keep external process/namespace/mount/executable observation and the existing
path, FD and socket controls. Do not simply delete the boundary or label the
colliding path nonexistent. A field should describe namespace exclusion rather
than claim that every matching numeric root path was absent.

The historical reviewer-small01 failure sanitized the failing clause. This
controlled experiment therefore does not prove which original thread occupied3
or recover that missing trace. It does establish the concrete defect in the exact
assertion under the exact outer shape and preserved isolation implementation.
It does not show a capability leak or prove general absence of leaks. Root and
the author/reviewer own the narrow repair and any separately allocated genuine
rerun. No accepted source or security setting was changed here.
