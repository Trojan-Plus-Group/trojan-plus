#!/bin/sh
set -eu
mode=${1:-}
protocol=${2:-}
config=${3:-}
target_ip=${4:-}
size=${5:-1048576}
watchdog=${6:-180}
requests=${7:-1}
concurrency=${8:-1}

case "$mode" in nat|client_tun) ;; *) exit 64;; esac
case "$protocol" in tcp|quic) ;; *) exit 64;; esac
case "$target_ip" in *[!0-9.]*|*.*.*.*.*|"") exit 64;; esac
case "$size" in *[!0-9]*|"") exit 64;; esac
case "$watchdog" in *[!0-9]*|"") exit 64;; esac
case "$requests" in *[!0-9]*|"") exit 64;; esac
case "$concurrency" in *[!0-9]*|"") exit 64;; esac

trojan_pid=
watchdog_pid=
cleanup() {
    status=$?
    set +e
    if [ "$status" -ne 0 ]; then
        cat /tmp/trojan.log >&2 2>/dev/null
        iptables -t nat -L OUTPUT -nvx >&2 2>/dev/null
        ip -s link show dev tun0 >&2 2>/dev/null || true
        ip route show >&2 2>/dev/null || true
    fi
    test -z "$trojan_pid" || kill "$trojan_pid" 2>/dev/null
    test -z "$watchdog_pid" || kill "$watchdog_pid" 2>/dev/null
    test -z "$trojan_pid" || wait "$trojan_pid" 2>/dev/null
    iptables -t nat -D OUTPUT -d "$target_ip/32" -p tcp --dport 443 -j REDIRECT --to-ports 12345 2>/dev/null
    ip route del "$target_ip/32" dev tun0 2>/dev/null
    exit "$status"
}
trap cleanup EXIT INT TERM

if [ "$mode" = nat ]; then
    iptables -t nat -A OUTPUT -d "$target_ip/32" -p tcp --dport 443 -j REDIRECT --to-ports 12345
fi

/runtime/trojan -c "$config" -l /tmp/trojan.log &
trojan_pid=$!
(sleep "$watchdog"; kill -TERM "$trojan_pid" 2>/dev/null) &
watchdog_pid=$!

ready=false
for n in $(seq 1 60); do
    if ! kill -0 "$trojan_pid" 2>/dev/null; then
        wait "$trojan_pid" || true
        cat /tmp/trojan.log >&2 2>/dev/null
        exit 70
    fi
    if [ "$mode" = nat ]; then
        if ss -H -ltn sport = :12345 | grep -q .; then
            ready=true
            break
        fi
    elif ip link show tun0 >/dev/null 2>&1; then
        ip link set tun0 up
        ip route replace "$target_ip/32" dev tun0
        ready=true
        break
    fi
    sleep 1
done

if [ "$ready" != true ]; then
    cat /tmp/trojan.log >&2 2>/dev/null
    exit 71
fi

# target resolve: --resolve "speed.cloudflare.com:443:$target_ip"
python3 - <<EOF "$target_ip" "$size" "$requests" "$concurrency" "$mode" "$protocol"
import concurrent.futures
import json
import os
import statistics
import subprocess
import sys
import time

target_ip = sys.argv[1]
size = int(sys.argv[2])
requests = int(sys.argv[3])
concurrency = int(sys.argv[4])
mode = sys.argv[5]
protocol = sys.argv[6]

curl_write_out = '{"http_code":%{http_code},"size_download":%{size_download},"speed_download":%{speed_download},"time_total":%{time_total},"time_connect":%{time_connect}}'

def run_one(req_id):
    out_path = f"/tmp/payload_{req_id}.bin"
    cmd = [
        "curl", "--fail", "--silent", "--show-error",
        "--max-time", "170",
        "--resolve", f"speed.cloudflare.com:443:{target_ip}",
        "--output", out_path,
        "--write-out", curl_write_out,
        f"https://speed.cloudflare.com/__down?bytes={size}"
    ]
    start_t = time.monotonic()
    res = subprocess.run(cmd, capture_output=True, text=True)
    elapsed = time.monotonic() - start_t
    actual_sz = 0
    try:
        actual_sz = os.path.getsize(out_path)
        os.remove(out_path)
    except OSError:
        pass

    parsed = None
    if res.stdout.strip():
        try:
            parsed = json.loads(res.stdout.strip())
        except Exception:
            pass

    http_code = parsed.get("http_code", 0) if parsed else 0
    size_download = parsed.get("size_download", 0) if parsed else 0
    speed_download = parsed.get("speed_download", 0.0) if parsed else 0.0
    time_total = parsed.get("time_total", elapsed) if parsed else elapsed
    time_connect = parsed.get("time_connect", 0.0) if parsed else 0.0
    success = (res.returncode == 0 and actual_sz == size and http_code == 200 and size_download == size)
    
    return {
        "req_id": req_id,
        "exit_code": res.returncode,
        "actual_size": actual_sz,
        "size_download": size_download,
        "http_code": http_code,
        "speed_download": speed_download,
        "speed_mbps": (speed_download * 8.0) / 1e6,
        "time_total": time_total,
        "time_connect": time_connect,
        "success": success,
        "stderr": res.stderr.strip() if not success else ""
    }

start_all = time.monotonic()
samples = []
with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
    futures = [executor.submit(run_one, i) for i in range(1, requests + 1)]
    for f in concurrent.futures.as_completed(futures):
        samples.append(f.result())
total_duration = time.monotonic() - start_all

samples.sort(key=lambda s: s["req_id"])
successes = [s for s in samples if s["success"]]
success_count = len(successes)
failed_count = len(samples) - success_count

speeds = [s["speed_mbps"] for s in successes] or [0.0]
durations = [s["time_total"] for s in successes] or [0.0]
connects = [s["time_connect"] for s in successes] or [0.0]

result = {
    "mode": mode,
    "protocol": protocol,
    "target_ip": target_ip,
    "size": size,
    "expected_size": size,
    "actual_size": size if success_count == len(samples) else (successes[0]["actual_size"] if successes else 0),
    "http_code": 200 if success_count == len(samples) else (samples[0]["http_code"] if samples else 0),
    "size_download": size if success_count == len(samples) else (successes[0]["size_download"] if successes else 0),
    "total_requests": requests,
    "concurrency": concurrency,
    "success_count": success_count,
    "failed_count": failed_count,
    "total_duration_sec": round(total_duration, 3),
    "speed_mbps_median": round(statistics.median(speeds), 2),
    "speed_mbps_min": round(min(speeds), 2),
    "speed_mbps_max": round(max(speeds), 2),
    "time_total_median": round(statistics.median(durations), 3),
    "time_connect_median": round(statistics.median(connects), 3),
    "all_success": (success_count == requests and requests > 0),
    "failures": [s for s in samples if not s["success"]][:10]
}

if requests <= 5:
    result["samples"] = samples

print(json.dumps(result, separators=(",", ":")))
if not result["all_success"]:
    sys.exit(1)
EOF

