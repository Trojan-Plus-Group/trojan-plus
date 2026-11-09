#!/usr/bin/env bash
# Usage: run_in_container.sh <image> <logdir> [harness args...]
set -euo pipefail
if (( $# < 2 )); then
    echo "Usage: $0 <image> <logdir> [harness args...]" >&2
    exit 2
fi
image=$1
logdir=$2
shift 2
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
mkdir -p -- "$logdir"
logdir=$(cd -- "$logdir" && pwd -P)
case "$logdir/" in
    "$repo/"*) echo 'Log directory must be outside repository' >&2; exit 2 ;;
esac
read -r -a runtime <<< "${CONTAINER:-podman}"
command -v "${runtime[0]}" >/dev/null || { echo "Missing container command: ${runtime[0]}" >&2; exit 1; }
exec "${runtime[@]}" run --rm --privileged \
    -v "$repo:/src:ro" -v "$logdir:/logs" "$image" bash -c '
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
for tool in ip tc sysctl python3 stat cmake nproc cp; do
    command -v "$tool" >/dev/null || { echo "Missing prerequisite in image: $tool" >&2; exit 1; }
done
cp -a /src /work
cd /work
rm -rf build
{ cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DENABLE_QUIC=ON && cmake --build build -j"$(nproc)"; } > /logs/build.log 2>&1 || {
    cat /logs/build.log >&2
    exit 1
}
exec python3 /src/tests/netem/harness.py --output-dir /logs "$@"
' netem "$@"
