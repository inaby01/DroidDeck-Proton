#!/bin/bash
# Build only the test harness; do not rebuild Proton or modify any device.
set -euo pipefail
script_path=${BASH_SOURCE[0]}
script_parent=.
if [[ $script_path == */* ]]; then
    script_parent=${script_path%/*}
fi
script_dir=$(CDPATH='' cd -- "$script_parent" && pwd -P)
preparation_dir=${script_dir%/*}
banner_dir=${preparation_dir%/*}
repo_dir=${banner_dir%/*}
image=droiddeck-prefix-tests:ubuntu26.04-arm64

# Build from a private allowlisted snapshot, without host bind mounts or repository secrets.
context=$(mktemp -d "${TMPDIR:-/tmp}/droiddeck-prefix-tests.XXXXXXXX")
trap 'rm -rf -- "$context"' EXIT
mkdir -p "$context/input/prefix-preparation/container" "$context/input/banner-proton"
cp "$script_dir/Dockerfile" "$script_dir/.dockerignore" "$context/"
cp "$script_dir/run-in-container.sh" "$context/input/prefix-preparation/container/"
for file in prepare-game.sh prepare_game.py preparation_common.py preparation_assets.py preparation_store.py preparation_vdf.py preparation_binding.py preparation_execution.py preparation_payload.py preparation_target.py preparation_processes.py preparation_customization.py preparation_runtime.py preparation_runtime_context.py preparation_installation.py preparation_tool_writer.py preparation_publication.py preparation_preflight.py preparation_selection.py preparation_probe.py preparation_probe_recovery.py preparation_static_placement.py test_preparation_static_placement.py test_preparation_probe.py test_preparation_probe_recovery.py test_preparation_selection.py test_preparation_preflight.py test_preparation_tool_writer.py test_preparation_installation.py test_preparation_runtime_context.py test_preparation_customization.py test_preparation_runtime.py test_preparation_processes.py test_preparation_payload.py test_preparation_execution.py test_preparation_binding.py test_prepare_game.py test_preparation_store.py; do
    cp "$preparation_dir/$file" "$context/input/prefix-preparation/"
done
for file in test-softdenchi-install.py test-softdenchi-setup.py test-softdenchi-observer.py install-softdenchi.py setup-softdenchi.py; do
    cp "$banner_dir/$file" "$context/input/banner-proton/"
done
cp "$repo_dir/softdenchi_observer.py" "$repo_dir/proton" "$context/input/"
docker build --platform linux/arm64 --tag "$image" "$context"
docker image inspect --format 'TEST_IMAGE={{.Id}} PLATFORM={{.Os}}/{{.Architecture}}' "$image"
for test_user in 0:0 10000:10000; do
    printf '\nTesting as uid:gid %s\n' "$test_user"
    docker run --rm --platform linux/arm64 --user "$test_user" \
        --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
        --pids-limit 128 --memory 512m --cpus 2 \
        --tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=128m \
        "$image" \
        /bin/bash /input/prefix-preparation/container/run-in-container.sh
done
