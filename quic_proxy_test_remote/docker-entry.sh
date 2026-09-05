#!/bin/sh
set -eu
mode=${1:-}
protocol=${2:-}
config=${3:-}
target_ip=${4:-}
size=${5:-}
watchdog=${6:-}
case "$mode" in nat|client_tun) ;; *) exit 64;; esac
case "$protocol" in tcp|quic) ;; *) exit 64;; esac
case "$target_ip" in *[!0-9.]*|*.*.*.*.*|"") exit 64;; esac
case "$size:$watchdog" in 1048576:180) ;; *) exit 64;; esac
trojan_pid=
watchdog_pid=
cleanup() {
    status=$?
    set +e
    if [ "$status" -ne 0 ]; then
        cat /tmp/trojan.log >&2 2>/dev/null
        iptables -t nat -L OUTPUT -nvx >&2 2>/dev/null
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
output=/tmp/payload.bin
metrics=$(curl --fail --silent --show-error --max-time 170 --resolve "speed.cloudflare.com:443:$target_ip" --output "$output" --write-out '{"http_code":%{http_code},"size_download":%{size_download}}' "https://speed.cloudflare.com/__down?bytes=$size")
actual_size=$(wc -c < "$output" | tr -d ' ')
printf '%s' "$metrics" | python3 -c 'import json,sys; data=json.load(sys.stdin); data["actual_size"]=int(sys.argv[1]); data["mode"]=sys.argv[2]; print(json.dumps(data, separators=(",", ":")))' "$actual_size" "$mode"
printf '\n'
test "$actual_size" = "$size"
