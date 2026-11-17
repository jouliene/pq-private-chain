# Optional remote reproduction prerequisites

Read-only inspection on 2026-11-17, completed at approximately 11:51 UTC. This
report authorizes no provisioning or execution campaign. The local full wallet
campaign remains independent; the optional server is not a local completion gate.

## Decision

The remote host cannot run the unchanged reproduction commands directly today.
It has Ubuntu26.04 and OpenSSL3.5.5, whereas discovery requires native
OpenSSL3.0.13, Node24.22.1 with embedded OpenSSL3.5.9, and Rust1.99.1. Rust and Node
are absent. Existing unprivileged bubblewrap **did** execute a harmless namespace
capability check successfully. A user-owned Ubuntu24.04/Noble-compatible root
filesystem under that existing tool is therefore the smallest identified
unchanged-source candidate. No such prepared root filesystem, complete nested
wallet isolation, or approved remote installation was established by this task.

Do not replace the host OpenSSL or change services/security settings. A local
OpenSSL library passed as `--libcrypto` alone does not solve the mismatch.

## Actual safe remote observations

The existing `goadmin` shell alias was used with BatchMode, password and keyboard
interactive authentication disabled, StrictHostKeyChecking enabled, and host-key
updates disabled. Only public capability metadata was returned. Endpoint,
account, credential paths and directory names are intentionally omitted.

| Observation | Actual result |
|---|---|
| OS / architecture / kernel | Ubuntu26.04 / x86_64 / 7.0.0-43-generic |
| Python / its OpenSSL | 3.14.4 / 3.5.5 |
| `/usr/bin/openssl version` | OpenSSL3.5.5, 27Jan2026; library3.5.5 |
| C compiler / Git | Ubuntu GCC15.2.0-16ubuntu1 / Git2.53.0 |
| Present tools | bwrap0.11.1, unshare, chroot, lxc, curl, tar, xz, make, pkg-config |
| Absent tools | rustup/cargo/rustc, node, rg, docker, podman, nerdctl, apptainer, singularity, systemd-nspawn, proot |
| Docker socket | `/var/run/docker.sock` absent; no container daemon was queried or started |
| Namespace settings | unprivileged_userns_clone=1; max_user_namespaces=662997; apparmor_restrict_unprivileged_userns=1 |
| Home write access | `os.access(..., W_OK)` true; no file created |
| `/mnt/data` | total3936802029568B; available2752250372096B (about2.50TiB); mount root not writable |
| Existing data subdirectories | 12 immediate entries; 2 directories owned by the login UID and writable according to `os.access`; contents not inspected, names not recorded |

Root separately inspected two4TB NVMe devices and approximately293GB free on the
system root. Those are Root observations, not an additional device enumeration by
this task. Free space is neither a project allocation nor a demonstrated write.

The one ephemeral capability command was:

```sh
/usr/bin/bwrap --die-with-parent --new-session \
  --unshare-user --unshare-pid --unshare-net --unshare-ipc --unshare-uts \
  --cap-drop ALL --ro-bind / / --proc /proc --dev /dev -- /usr/bin/true
```

Actual exit0, zero stdout/stderr bytes, Python monotonic elapsed0.004317935s.
This proves the displayed namespace operation worked despite the AppArmor
setting. It does not prove the wallet runner's tighter filesystem/seccomp policy,
nested namespaces, same-UID `/proc` observation, rootfs loader compatibility, or
resource-accounting behavior. `lxc` presence establishes no usable LXD service,
rootless container image, authorization, or existing guest.

## Unchanged source constraints

* `scripts/prepare_runtime.py:24` checks the exact Node/OpenSSL/platform tuple;
  hashes the actual ELF before/after, records live mappings and `ldd` closure.
* Lines30–34 resolve a selected `libcrypto.so.3`, but independently execute the
  **fixed `/usr/bin/openssl`**. That CLI must link the selected library and report
  OpenSSL3.0.13. The loader cache, OpenSSL configuration, CLI and native files are
  pinned. The host's3.5.5 CLI fails this gate.
* Installation requires the reviewed candidate digest and rechecks every runtime
  pin. Only disposable installation paths/native pin tables change; the fixed
  embedded worker and proof programs remain unchanged. An old local installation
  digest cannot authorize this server.
* `scripts/build.py:69–95` requires an explicit rustup Cargo proxy and selects
  cargo/rustc1.99.1. Its fresh isolated Cargo home uses the checked-in vendor,
  offline/locked compilation, one job, and a fresh target. Compiler depfiles,
  features and actual ELF linkage are subsequently checked.
* The existing compile-time `LIBRARY_PATH` selects a link search directory; it
  does not authorize a different runtime library. Actual `ldd` paths must match
  the approved closure and ledger must link the selected crypto. No `LD_*`
  override, cache modification, provider bypass or version-check change is part
  of the proposed route.
* The wallet isolation launcher has a fixed `/usr/bin/bwrap` and separately binds
  `/usr`, approved files/trees, `/proc` and `/dev`, with seccomp and private user,
  PID, network, IPC and UTS namespaces. A rootfs must supply these prerequisites,
  and its nested actual policy must be checked independently before private work.

Inspected source SHA256 pins (not remote binary attestation):

| File | SHA256 |
|---|---|
| `scripts/prepare_runtime.py` | `5c542123763f435c0b5d9f3fd12742fe45efef9361666d3eb2c2a5eb30d0f4e5` |
| `scripts/build.py` | `f1be626bccba99de72b2aa1bedd077e6ec8e05f8c0b8b36521267570c8fb9fa1` |
| `BUILD.md` | `b03ea95e5fe161b7d9eb741b749d49539ef2fb7deeb5c511db1bd801db7fff9c` |
| `.github/workflows/smoke.yml` | `63d909de9a8a3175a92be467176ae952b17e78162a6a4cb87076117ad54de4e0` |
| `experiments/network-feasibility/wallet-integration/isolation.py` | `f5c3bef9b6ff6123d2f2d5cb7b2b2357eccb700e85f5fdf15ca3e316d70aff28` |

## Smallest bounded next prerequisite

Root can separately authorize staging into one confirmed existing owned writable
directory, with explicit disk budget and immutable artifact manifest. Prepare a
user-owned rootfs with matching OpenSSL CLI/library/configuration/development
files, C/GNU tools, Python, rg and bubblewrap; stage exact rustup/Rust1.99.1 and
the official Node24.22.1 tarball there. Do not overwrite the host `/usr` or loader
configuration. All subsequent preparation, discovery, build and execution must
use that same filesystem view and stable visible workspace paths.

The repository CI already names Ubuntu24.04. The official Ubuntu package pages
currently list Noble `openssl` and `libssl-dev`3.0.13-0ubuntu3.16, supporting that
candidate release family; this is **not** an approved rootfs/package digest or
attestation that its CLI/linkage will pass. Inspect the fetched artifacts and
actual binaries rather than selecting an unpinned moving image tag. See
[Ubuntu OpenSSL](https://packages.ubuntu.com/noble/openssl) and
[Ubuntu development package](https://packages.ubuntu.com/noble/libssl-dev).
Bubblewrap supports constructing the root filesystem through mount namespaces;
it is not a dependency/image provisioner. See its
[upstream documentation](https://github.com/containers/bubblewrap/blob/main/README.md).

Use the existing official Node archive checksum in `BUILD.md`:
`6c172a9ab6718f7b801fb5a7bd486af2ee5e32758086a04b84fcce2aa77095e6`
(32026916B). The Rust channel manifest is
`https://static.rust-lang.org/dist/channel-rust-1.99.1.toml`.
These retained source pins are not claims that remote retrieval occurred.

Before allocating proving: (1) verify provisioned rootfs/package/toolchain hashes,
versions and normal loader closure; (2) run a bounded harmless nested wallet
isolation/proc-policy pilot without relaxing any checks; (3) execute existing
runtime discovery and explicitly approve its new digest; (4) allocate one fresh
offline build plus tiny public controls and inspect actual source/ELF/runtime
closure. Only then consider a separately allocated remote proof campaign. No
rootfs download, installation, build, crypto test, private input, service change,
permission change, sudo command or persistent remote output occurred here.
