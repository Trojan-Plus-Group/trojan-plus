#!/usr/bin/env python3

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import re
import secrets
import shlex
import statistics
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
RESULT_DIRS = ("metadata", "baseline", "direct", "tcp-tls", "quic", "logs", "captures")
RUN_ID_RE = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]{7,40}-r\d+$")
HOST = "172.236.226.35"
SSH_USER = "root"
SSH_PORT = 9922
IPERF_PORT = 5201
RETRY_DELAYS = (3, 10)
ITEM_TIMEOUT = 180


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def posix(path):
    return str(path).replace("\\", "/")


def run(command, cwd=None):
    return subprocess.run(command, cwd=cwd, check=True, text=True, capture_output=True).stdout.strip()


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def render(template_name, output, values):
    content = (ROOT / template_name).read_text()
    for key, value in values.items():
        content = content.replace("${" + key + "}", value)
    if "${" in content:
        raise ValueError(f"unresolved placeholder in {template_name}")
    json.loads(content)
    output.write_text(content)
    output.chmod(0o600)


def prepare(args):
    if not RUN_ID_RE.fullmatch(args.run_id):
        raise ValueError("run-id must match YYYYMMDDTHHMMSSZ-<commit>-r<number>")
    repo = pathlib.Path(args.local_repo).resolve()
    runtime = ROOT / "runtime" / args.run_id
    results = ROOT / "results" / args.run_id
    if runtime.exists() or results.exists():
        raise FileExistsError(f"run already exists: {args.run_id}")
    runtime.mkdir(parents=True, mode=0o700)
    results.mkdir(parents=True)
    for name in RESULT_DIRS:
        (results / name).mkdir()
    password = secrets.token_urlsafe(32)
    password_path = runtime / "password"
    password_path.write_text(password + "\n")
    password_path.chmod(0o600)
    key_path = runtime / "server.key"
    cert_path = runtime / "server.crt"
    run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key_path), "-out", str(cert_path), "-days", "7", "-subj", f"/CN={HOST}", "-addext", f"subjectAltName=IP:{HOST}"])
    key_path.chmod(0o600)
    cert_path.chmod(0o644)
    server = runtime / "server.json"
    client_quic = runtime / "client-quic.json"
    client_tcp = runtime / "client-tcp.json"
    render("server.json.template", server, {"PASSWORD": password, "CERT_PATH": args.remote_runtime + "/server.crt", "KEY_PATH": args.remote_runtime + "/server.key"})
    client_values = {"PASSWORD": password, "CERT_PATH": posix(cert_path), "REMOTE_ADDR": HOST}
    render("client-quic.json.template", client_quic, client_values)
    render("client-tcp.json.template", client_tcp, client_values)
    commit = run(["git", "rev-parse", "HEAD"], repo)
    status = run(["git", "status", "--short", "--branch"], repo)
    manifest = {
        "run_id": args.run_id,
        "created_utc": utc_now(),
        "baseline_commit": commit,
        "local": {"repo": posix(repo), "status": status},
        "remote": {"host": HOST, "ssh_port": SSH_PORT, "user": SSH_USER, "repo": args.remote_repo, "runtime": args.remote_runtime},
        "build": {"type": "Release", "cmake_args": ["-DCMAKE_BUILD_TYPE=Release", "-DENABLE_QUIC=ON"]},
        "config_sha256": {"server": sha256(server), "client_quic": sha256(client_quic), "client_tcp": sha256(client_tcp)},
        "commands_file": "metadata/commands.jsonl",
    }
    (results / "metadata" / "manifest.json").write_text(json.dumps(manifest, indent=4) + "\n")
    print(args.run_id)
    print(posix(runtime))
    print(posix(results))


def ssh(remote_command):
    return ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-p", str(SSH_PORT), f"{SSH_USER}@{HOST}", remote_command]


def execute_attempt(command, output_prefix, timeout, commands_file, item, attempt):
    started = utc_now()
    start = time.monotonic()
    try:
        completed = subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)
        stdout = completed.stdout
        stderr = completed.stderr
        exit_code = completed.returncode
        timed_out = False
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout or ""
        stderr = error.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")
        exit_code = None
        timed_out = True
    ended = utc_now()
    output_prefix.parent.mkdir(parents=True, exist_ok=True)
    output_prefix.with_suffix(".stdout").write_text(stdout)
    output_prefix.with_suffix(".stderr").write_text(stderr)
    record = {"item": item, "attempt": attempt, "command": command, "started_utc": started, "ended_utc": ended, "duration_seconds": time.monotonic() - start, "exit_code": exit_code, "timed_out": timed_out, "stdout": posix(output_prefix.with_suffix('.stdout').relative_to(commands_file.parent.parent)), "stderr": posix(output_prefix.with_suffix('.stderr').relative_to(commands_file.parent.parent))}
    output_prefix.with_suffix(".json").write_text(json.dumps(record, indent=4) + "\n")
    with commands_file.open("a") as target:
        target.write(json.dumps(record) + "\n")
    return record, stdout


def run_item(command, directory, name, commands_file, validator=lambda record, output: record["exit_code"] == 0, attempt_timeout=50):
    deadline = time.monotonic() + ITEM_TIMEOUT
    attempts = []
    for index in range(3):
        if index:
            delay = RETRY_DELAYS[index - 1]
            if time.monotonic() + delay >= deadline:
                break
            time.sleep(delay)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        record, output = execute_attempt(command, directory / f"{name}-attempt{index + 1}", min(attempt_timeout, remaining), commands_file, name, index + 1)
        record["valid"] = validator(record, output)
        attempts.append(record)
        if record["valid"]:
            break
    return {"name": name, "valid": bool(attempts and attempts[-1]["valid"]), "attempts": attempts}


def valid_iperf(record, output):
    if record["exit_code"] != 0:
        return False
    try:
        data = json.loads(output)
        return not data.get("error") and "end" in data
    except json.JSONDecodeError:
        return False


def start_server(results, commands_file):
    remote_log = f"/tmp/iperf3-{results.name}.log"
    remote = f"if ss -lntup | grep -q ':{IPERF_PORT} '; then exit 73; fi; nohup iperf3 -s -p {IPERF_PORT} >{shlex.quote(remote_log)} 2>&1 </dev/null & pid=$!; sleep 1; test -r /proc/$pid/cmdline || exit 74; tr '\\0' ' ' </proc/$pid/cmdline; printf '\\n%s\\n' \"$pid\""
    item = run_item(ssh(remote), results / "baseline" / "server", "iperf3-server-start", commands_file, attempt_timeout=15)
    if not item["valid"]:
        raise RuntimeError("remote iperf3 server failed to start")
    stdout_path = results / item["attempts"][-1]["stdout"]
    lines = stdout_path.read_text().splitlines()
    pid = int(lines[-1])
    cmdline = " ".join(lines[:-1])
    if "iperf3 -s" not in cmdline or f"-p {IPERF_PORT}" not in cmdline:
        raise RuntimeError("remote iperf3 cmdline mismatch")
    (results / "metadata" / "iperf3-server.json").write_text(json.dumps({"pid": pid, "cmdline": cmdline, "remote_log": remote_log}, indent=4) + "\n")
    return pid, remote_log


def stop_server(pid, remote_log, results, commands_file):
    expected = f"iperf3 -s -p {IPERF_PORT}"
    remote = f"pid={pid}; test -r /proc/$pid/cmdline || exit 0; cmd=$(tr '\\0' ' ' </proc/$pid/cmdline); case \"$cmd\" in *{shlex.quote(expected)}*) kill \"$pid\"; for n in 1 2 3 4 5; do test ! -e /proc/$pid && break; sleep 1; done; test ! -e /proc/$pid;; *) printf '%s\\n' \"$cmd\" >&2; exit 75;; esac; rm -f {shlex.quote(remote_log)}"
    return run_item(ssh(remote), results / "baseline" / "server", "iperf3-server-stop", commands_file, attempt_timeout=15)


def snapshot(results, commands_file, phase):
    command = "printf '%s\\n' '=== UTC ==='; date -u +%Y-%m-%dT%H:%M:%SZ; printf '%s\\n' '=== SNMP ==='; cat /proc/net/snmp; printf '%s\\n' '=== SOFTNET ==='; cat /proc/net/softnet_stat; printf '%s\\n' '=== LINK ==='; ip -s link"
    return run_item(ssh(command), results / "baseline" / "system", f"remote-{phase}", commands_file, attempt_timeout=30)


def percentile(values, fraction):
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def iperf_metrics(output, protocol):
    data = json.loads(output)
    end = data["end"]
    if protocol == "tcp":
        section = end.get("sum_received") or end.get("sum_sent")
        sent = end.get("sum_sent", {})
        return {"bits_per_second": section.get("bits_per_second"), "retransmits": sent.get("retransmits"), "max_snd_cwnd": sent.get("max_snd_cwnd"), "cpu_utilization_percent": end.get("cpu_utilization_percent")}
    section = end.get("sum") or end.get("sum_received") or end.get("sum_sent")
    return {"bits_per_second": section.get("bits_per_second"), "lost_percent": section.get("lost_percent"), "jitter_ms": section.get("jitter_ms"), "out_of_order": section.get("out_of_order"), "cpu_utilization_percent": end.get("cpu_utilization_percent")}


def summarize(items, results):
    groups = {}
    invalid = []
    for item in items:
        if not item["valid"]:
            invalid.append(item["name"])
            continue
        attempt = item["attempts"][-1]
        output = (results / attempt["stdout"]).read_text()
        metrics = iperf_metrics(output, item["protocol"])
        item["metrics"] = metrics
        if not item["warmup"]:
            groups.setdefault(item["case"], []).append(metrics)
    summary_groups = {}
    for name, samples in groups.items():
        rates = [sample["bits_per_second"] for sample in samples if sample.get("bits_per_second") is not None]
        summary_groups[name] = {"valid_samples": len(samples), "p10_bits_per_second": percentile(rates, 0.1), "median_bits_per_second": statistics.median(rates) if rates else None, "p90_bits_per_second": percentile(rates, 0.9), "samples": samples}
    summary = {"generated_utc": utc_now(), "valid_sample_count": sum(len(value) for value in groups.values()), "invalid_sample_count": len(invalid), "invalid_samples": invalid, "groups": summary_groups}
    (results / "baseline" / "summary.json").write_text(json.dumps(summary, indent=4) + "\n")
    lines = [f"valid samples: {summary['valid_sample_count']}", f"invalid samples: {summary['invalid_sample_count']}"]
    for name, group in sorted(summary_groups.items()):
        lines.append(f"{name}: valid={group['valid_samples']} p10={group['p10_bits_per_second']} median={group['median_bits_per_second']} p90={group['p90_bits_per_second']}")
    if invalid:
        lines.append("invalid: " + ", ".join(invalid))
    (results / "baseline" / "summary.txt").write_text("\n".join(lines) + "\n")
    return summary


def baseline(args):
    if args.warmup < 0 or args.runs < 1:
        raise ValueError("warmup must be >= 0 and runs must be >= 1")
    results = ROOT / "results" / args.run_id
    if not (results / "metadata" / "manifest.json").is_file():
        raise FileNotFoundError(f"prepared run not found: {args.run_id}")
    commands_file = results / "metadata" / "commands.jsonl"
    items = []
    server = None
    remote_log = None
    try:
        items.append(run_item(["ping", "-c", "30", HOST], results / "baseline" / "path", "ping", commands_file, attempt_timeout=50))
        items.append(run_item(["traceroute", HOST], results / "baseline" / "path", "traceroute", commands_file, attempt_timeout=50))
        items.append(run_item(ssh("date -u +%Y-%m-%dT%H:%M:%SZ; timedatectl show -p NTPSynchronized --value 2>/dev/null || true"), results / "baseline" / "system", "remote-time", commands_file, attempt_timeout=15))
        items.append(snapshot(results, commands_file, "before"))
        server, remote_log = start_server(results, commands_file)
        for warmup, count in ((True, args.warmup), (False, args.runs)):
            label = "warmup" if warmup else "run"
            for number in range(1, count + 1):
                for streams in (1, 4, 8):
                    for reverse in (False, True):
                        case = f"tcp-p{streams}-{'reverse' if reverse else 'forward'}"
                        name = f"{case}-{label}{number}"
                        command = ["iperf3", "-c", HOST, "-p", str(IPERF_PORT), "-n", "15000000", "-O", "2", "-P", str(streams), "--get-server-output", "--json"]
                        if reverse:
                            command.append("-R")
                        item = run_item(command, results / "baseline" / "tcp" / case, name, commands_file, valid_iperf, 140)
                        item.update({"case": case, "protocol": "tcp", "warmup": warmup})
                        items.append(item)
                for bitrate, duration in ((10, 20), (25, 12), (50, 8)):
                    for reverse in (False, True):
                        case = f"udp-{bitrate}m-{'reverse' if reverse else 'forward'}"
                        name = f"{case}-{label}{number}"
                        command = ["iperf3", "-c", HOST, "-p", str(IPERF_PORT), "-u", "-b", f"{bitrate}M", "-t", str(duration), "-O", "2", "--get-server-output", "--json"]
                        if reverse:
                            command.append("-R")
                        item = run_item(command, results / "baseline" / "udp" / case, name, commands_file, valid_iperf, 35)
                        item.update({"case": case, "protocol": "udp", "warmup": warmup})
                        items.append(item)
    finally:
        items.append(snapshot(results, commands_file, "after"))
        if server is not None:
            items.append(stop_server(server, remote_log, results, commands_file))
    summary = summarize([item for item in items if "protocol" in item], results)
    print(posix(results / "baseline" / "summary.json"))
    if summary["invalid_sample_count"]:
        print(f"invalid samples: {summary['invalid_sample_count']}", file=sys.stderr)


def parse_args():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    command = subparsers.add_parser("prepare")
    command.add_argument("--run-id", required=True)
    command.add_argument("--local-repo", default=str(ROOT.parent))
    command.add_argument("--remote-repo", default="/root/trojan-plus")
    command.add_argument("--remote-runtime", default="/root/trojan-plus/quic_proxy_test_remote/runtime")
    command = subparsers.add_parser("baseline")
    command.add_argument("--run-id", required=True)
    command.add_argument("--warmup", default=1, type=int)
    command.add_argument("--runs", default=1, type=int)
    return parser.parse_args()


def main():
    args = parse_args()
    if args.command == "prepare":
        prepare(args)
    elif args.command == "baseline":
        baseline(args)


if __name__ == "__main__":
    try:
        main()
    except (FileExistsError, FileNotFoundError, RuntimeError, ValueError, subprocess.CalledProcessError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
