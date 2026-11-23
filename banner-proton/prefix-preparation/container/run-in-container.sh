#!/bin/bash
# Read-only source; all test fixtures live in the container's Linux tmpfs.
set -euo pipefail
cd /tmp
/usr/bin/python3 -I -B - <<'PY'
import json
import os
import platform
import sys
import tempfile
from pathlib import Path

release = {}
for line in Path('/etc/os-release').read_text().splitlines():
    if '=' in line:
        key, value = line.split('=', 1)
        if key in ('ID', 'VERSION_ID', 'VERSION_CODENAME'):
            release[key] = value.strip('"')
assert release['ID'] == 'ubuntu' and release['VERSION_ID'] == '26.04', release
assert platform.machine() == 'aarch64', platform.machine()
assert sys.version_info[:2] == (3, 14), sys.version
mounts = [line.split() for line in Path('/proc/mounts').read_text().splitlines()]
tmp_mount = next(item for item in mounts if item[1] == '/tmp')
assert tmp_mount[2] == 'tmpfs' and 'noexec' not in tmp_mount[3].split(','), tmp_mount
assert os.statvfs('/input').f_flag & os.ST_RDONLY, 'test sources must be read-only'
with tempfile.TemporaryDirectory(dir='/tmp') as folder:
    probe = Path(folder) / 'mode-probe'
    probe.write_text('#!/bin/sh\nexit 0\n')
    probe.chmod(0o755)
    assert os.access(probe, os.X_OK), 'test filesystem must allow execute permission checks'
print(json.dumps({'test_filesystem': tmp_mount[2], 'tmp_mount_flags': tmp_mount[3], 'source_read_only': True,
                  'os_release': release, 'architecture': platform.machine(),
                  'python': platform.python_version(), 'glibc': platform.libc_ver(),
                  'kernel': platform.release(), 'uid': os.getuid(), 'gid': os.getgid()}, sort_keys=True), flush=True)
PY
dpkg-query -W -f='${Package}=${Version}\n' python3 python3.14 libc6
stat -f -c 'TEST_FILESYSTEM=%T' /tmp
for test in \
    /input/prefix-preparation/test_prepare_game.py \
    /input/prefix-preparation/test_preparation_store.py \
    /input/prefix-preparation/test_preparation_slot_manifest.py \
    /input/prefix-preparation/test_preparation_installer_log.py \
    /input/prefix-preparation/test_preparation_vc_record.py \
    /input/prefix-preparation/test_preparation_dependencies.py \
    /input/prefix-preparation/test_preparation_binding.py \
    /input/prefix-preparation/test_preparation_execution.py \
    /input/prefix-preparation/test_preparation_processes.py \
    /input/prefix-preparation/test_preparation_payload.py \
    /input/prefix-preparation/test_preparation_customization.py \
    /input/prefix-preparation/test_preparation_runtime.py \
    /input/prefix-preparation/test_preparation_runtime_context.py \
    /input/prefix-preparation/test_preparation_installation.py \
    /input/prefix-preparation/test_preparation_tool_writer.py \
    /input/prefix-preparation/test_preparation_preflight.py \
    /input/prefix-preparation/test_preparation_static_placement.py \
    /input/prefix-preparation/test_preparation_trial.py \
    /input/prefix-preparation/test_preparation_dependency_install.py \
    /input/prefix-preparation/test_preparation_game_prefix.py \
    /input/prefix-preparation/test_preparation_prefix_dll.py \
    /input/prefix-preparation/test_preparation_one_pass.py \
    /input/prefix-preparation/test_preparation_status.py \
    /input/prefix-preparation/test_preparation_proton_update.py \
    /input/prefix-preparation/test_preparation_batch.py \
    /input/prefix-preparation/test_preparation_folder_reads.py \
    /input/prefix-preparation/test_preparation_probe_recovery.py \
    /input/prefix-preparation/test_preparation_probe.py \
    /input/prefix-preparation/test_preparation_selection.py \
    /input/banner-proton/test-softdenchi-install.py \
    /input/banner-proton/test-softdenchi-setup.py \
    /input/banner-proton/test-softdenchi-observer.py; do
    printf '\nRunning %s\n' "$test"
    /usr/bin/python3 -I -B "$test"
done
