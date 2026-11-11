#!/usr/bin/env bash
# Usage: perf_in_container.sh IMAGE EXTERNAL_LOG_DIR [harness args...]
# Opt-in diagnostic runner. Existing run_in_container.sh behavior is unchanged.
set -euo pipefail
if (( $# < 2 )); then
    echo 'Usage: perf_in_container.sh IMAGE EXTERNAL_LOG_DIR [harness args...]' >&2
    exit 2
fi
image=$1
logdir=$2
shift 2
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
mkdir -p -- "$logdir"
logdir=$(cd -- "$logdir" && pwd -P)
case "$logdir/" in "$repo/"*) echo 'Log directory must be outside repository' >&2; exit 2 ;; esac
read -r -a runtime <<< "${CONTAINER:-podman}"
exec "${runtime[@]}" run --rm --privileged --pid=host \
    -e "CMAKE_EXTRA_CXX_FLAGS=${CMAKE_EXTRA_CXX_FLAGS:--g -fno-omit-frame-pointer}" \
    -e "PERF_REUSE_BINARY=${PERF_REUSE_BINARY:-}" \
    -v "$repo:/src:ro" -v /:/host:ro -v "$logdir:/logs" \
    -v "$logdir:/host$logdir:rw" "$image" bash -c '
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
host_logs=$1
shift
cp -a /src /work
cd /work
rm -rf build
mkdir build
if [[ -n "$PERF_REUSE_BINARY" ]]; then
    cp "/host$PERF_REUSE_BINARY" build/trojan
    echo "Reusing profiling binary: $PERF_REUSE_BINARY" > /logs/build.log
    readelf -S build/trojan | grep -E "debug_info|symtab" >> /logs/build.log
else
{
    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DENABLE_QUIC=ON \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON "-DCMAKE_CXX_FLAGS=${CMAKE_EXTRA_CXX_FLAGS}"
    cmake --build build -j"$(nproc)"
    cat build/CMakeFiles/trojan.dir/flags.make
    cat build/CMakeFiles/trojan.dir/link.txt
    readelf -h build/trojan
    readelf -S build/trojan | grep -E "debug_info|symtab"
} > /logs/build.log 2>&1
cp build/compile_commands.json /logs/compile_commands.json
fi
cp build/trojan /logs/trojan.symbols
if [[ "${1:-}" == --perf-matrix ]]; then
    shift
    python3 /src/tests/netem/harness.py --output-dir /logs/unprofiled --perf-host-output "$host_logs/unprofiled" "$@"
    for kind in record stat trace; do
        for role in server client; do
            python3 /src/tests/netem/harness.py --output-dir "/logs/$kind-$role" \
                --perf-host-output "$host_logs/$kind-$role" --perf-role "$role" --perf-kind "$kind" "$@"
        done
    done
else
    python3 /src/tests/netem/harness.py --output-dir /logs --perf-host-output "$host_logs" "$@"
fi
# Resolve container executable/system DSOs while container filesystem still exists.
# An explicit retained symbol tree works across chroot and after endpoint exit.
mkdir -p /logs/symfs/work/build /logs/symfs/proc
cp build/trojan /logs/symfs/work/build/trojan
# Resolve platform DSO paths rather than assuming an architecture or libc layout.
ldd build/trojan > /logs/ldd.txt
while IFS= read -r library; do
    cp --parents "$library" /logs/symfs/
done < <(awk '\''{ for (i = 1; i <= NF; ++i) if ($i ~ /^\//) print $i }'\'' /logs/ldd.txt)
cp /proc/kallsyms /logs/symfs/proc/kallsyms
symfs="$host_logs/symfs"
while IFS= read -r -d "" data; do
    host_data="$host_logs/${data#/logs/}"
    directory=${data%/*}
    if [[ "$data" == */syscalls-*/* || " $* " == *" --perf-kind syscalls "* ]]; then
        chroot /host /usr/bin/perf script -i "$host_data" > "$directory/perf-script.txt" 2> "$directory/perf-script.stderr.txt"
    else
        chroot /host /usr/bin/perf report --stdio --no-children --call-graph none --percent-limit 0 \
            --symfs "$symfs" --kallsyms "$symfs/proc/kallsyms" -i "$host_data" > "$directory/perf-report-self.txt" 2> "$directory/perf-report.stderr.txt"
        chroot /host /usr/bin/perf report --stdio --children --percent-limit 0 \
            --symfs "$symfs" --kallsyms "$symfs/proc/kallsyms" -i "$host_data" > "$directory/perf-report-callgraph.txt" 2> "$directory/perf-callgraph.stderr.txt"
        chroot /host /usr/bin/perf script -i "$host_data" --symfs "$symfs" > "$directory/perf-script.txt" 2> "$directory/perf-script.stderr.txt"
    fi
done < <(find /logs -name perf.data -type f -print0)
' perf "$logdir" "$@"
