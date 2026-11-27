# Linux/arm64 validation

Run from the repository root:

```bash
bash banner-proton/prefix-preparation/container/run-tests.sh
```

This is the primary local validation environment for prefix-preparation changes.
macOS host tests are supplementary. Docker must be running; the first build fetches
an official Ubuntu base and Python packages. Later test runs need no network
inside their containers. This builds a test image, not Proton.

The target distribution/architecture follow DroidDeck commit
`cdff94e72c45da50af43bbceff28effaf0179caf`:

- [Runtime description](https://github.com/Droid-Deck/DroidDeck/blob/cdff94e72c45da50af43bbceff28effaf0179caf/tools/ubuntu/README.md): Ubuntu 26.04 LTS / arm64, run under patched proot on Android.
- [Base definition](https://github.com/Droid-Deck/DroidDeck/blob/cdff94e72c45da50af43bbceff28effaf0179caf/tools/ubuntu/base.env): Ubuntu Base 26.04.1 / arm64.
- [Runtime packages](https://github.com/Droid-Deck/DroidDeck/blob/cdff94e72c45da50af43bbceff28effaf0179caf/tools/ubuntu/packages-runtime.txt): includes `python3`.
- [Guest UID selection](https://github.com/Droid-Deck/DroidDeck/blob/cdff94e72c45da50af43bbceff28effaf0179caf/app/src/main/java/com/droiddeck/launcher/runtime/LinuxRuntime.java): normal sessions use the Android app UID; fake-root sessions are separate.

The Dockerfile pins the official Ubuntu 26.04 base by registry digest, explicitly
builds for `linux/arm64`, and installs the distribution's Python. The harness
requires Python 3.14, checks the OS/architecture, and prints the actual Python,
glibc, kernel and selected package versions. Apt package versions are not frozen;
record the printed image ID and package versions for each validation. The image
tag is a local test handle; the content-addressed image ID identifies the run.

The build context is an explicit allowlist of Python/shell sources and existing
regression tests, assembled in a temporary directory. It includes the `proton`
source because the observer tests extract a method via AST and test it with mocks.
It does not include binaries, archives, game files, profiles, `.env` files, host
settings or an entire repository checkout. The temporary context is removed after
execution. No host directory is bind-mounted into a test container.

Each run tests as UID:GID `0:0` and `10000:10000` (a synthetic nonroot identity,
not a recorded device UID). Source/root filesystems are read-only. Fixtures use a
Linux tmpfs, with execute permission checks enabled, `nosuid` and `nodev`. The
preflight rejects `noexec`, verifies a generated mode-0755 file with `os.access`
without executing it, and checks that source storage is read-only.

Containers run with no network, all capabilities dropped, no new privileges,
128-process/512-MiB/two-CPU limits and 128-MiB temporary storage. They are removed
on exit; the dedicated test image remains locally for reuse. The script does not
prune images/volumes, restart Docker, or operate on unrelated containers.

For each UID the harness runs the same test files (the list is in `run-in-container.sh`)
without replacing assertions. Each file prints its own count when it runs. 1.0.1 removed the
suites of the removed code (preflight, measured dependency plans, the dedicated registration
probe and its recovery, and the old command-line modes).

The script stops at the first failing suite and preserves the raw console error.
A zero script exit means both UID runs finished; it is not a device preparation
result. Failures must be classified from the responsible code and environment,
not dismissed as platform differences.

This matches the distribution family, architecture and Python package stream,
not an exact installed DroidDeck rootfs. The Docker Desktop Linux kernel, native
UIDs, tmpfs and ordinary Linux syscalls differ from Android/proot and device
storage. GUI, graphics/audio drivers, Wine, actual installer behavior,
authentication, Steam binding and game operation are outside these tests.

The launch suite only plans launches (no child process). The trial, game-prefix and
dependency-installation suites execute a disposable Python substitute with fixed arguments,
selected environment and synthetic prefix files. They test process handling and rejection
paths, including timeout without termination. They do not run Wine or an installer, verify the
real payload, or establish runtime equivalence.

Payload tests generate tiny archives and installed trees in temporary storage.
Real NAS archives and runtime binaries are excluded from the Docker build context.

The process suite includes a harmless native Linux Python child. It checks that a
prefix-related environment is observed while the child waits on stdin and clears
after normal exit. No signals or Wine processes are used. This does not establish
Android/proot process visibility. macOS supplemental runs skip this native test.

Runtime tests use synthetic helper sources and ELF headers. Native Linux tests
also check a disposable Unix socket, the container OS definition and the auditor
proc/umask fields. They do not connect to GUI/audio servers. The self-contained
audit command is executed against the test container root and keeps its blockers.
