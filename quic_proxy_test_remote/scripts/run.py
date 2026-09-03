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
REPO_ROOT = ROOT.parent
TROJAN_BINARY = REPO_ROOT / "build" / "trojan"
RESULT_DIRS = ("metadata", "baseline", "direct", "tcp-tls", "quic", "logs", "captures")
RUN_ID_RE = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]{7,40}-r\d+$")
HOST = "172.236.226.35"
SSH_USER = "root"
SSH_PORT = 9922
IPERF_PORT = 5201
TROJAN_REMOTE_PORT = 3443
TROJAN_LOCAL_PORT_TCP = 9081
TROJAN_LOCAL_PORT_QUIC = 9080
BYTESOURCE_PORT = 8001
R2_DEFAULT_SIZES = (1 << 20, 5 << 20, 10 << 20, 15 << 20)
R2_MAX_SAMPLE_BYTES = 15 << 20
ITEM_TIMEOUT = 170
RETRY_DELAYS = (3, 10)
DEFAULT_ATTEMPT_TIMEOUT = 140


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


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def bytesource_payload(n):
    if n < 0:
        raise ValueError("payload size must be non-negative")
    return bytes(((i * 31 + 7) & 0xFF) for i in range(n))


def bytesource_sha256(n):
    return sha256_bytes(bytesource_payload(n))


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=4) + "\n")
    return path


def load_json(path):
    return json.loads(path.read_text())


def local_lsof(port, timeout=5):
    try:
        completed = subprocess.run(["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN"], text=True, capture_output=True, timeout=timeout, check=False)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False
    if completed.returncode != 0:
        return False
    needle = f":{port} (LISTEN)"
    return needle in completed.stdout


def wait_local_port(port, process=None, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            return False
        if local_lsof(port):
            return process is None or process.poll() is None
        time.sleep(0.5)
    return False


def parse_int(value):
    text = value.strip()
    if not text:
        raise ValueError("empty integer")
    return int(text)


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


def execute_attempt(command, output_prefix, timeout, commands_file, item, attempt, input_data=None):
    started = utc_now()
    start = time.monotonic()
    try:
        completed = subprocess.run(command, text=True, input=input_data, capture_output=True, timeout=timeout, check=False)
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


def scp(local_path, remote_path):
    return ["scp", "-P", str(SSH_PORT), str(local_path), f"{SSH_USER}@{HOST}:{remote_path}"]


def remote_mktemp(prefix, mode="700"):
    quoted_prefix = shlex.quote(prefix)
    quoted_mode = shlex.quote(mode)
    return f"umask 077 && dir=$(mktemp -d -p /tmp {quoted_prefix}.XXXXXX) && chmod {quoted_mode} \"$dir\" && printf '%s\\n' \"$dir\""


def ensure_remote_dir(remote_dir, results, commands_file, name):
    output_prefix = results / "metadata" / "trojan" / f"{name}-mktemp"
    record, output = execute_attempt(ssh(remote_mktemp(name)), output_prefix, 30, commands_file, f"{name}-mktemp", 1)
    if record["exit_code"] != 0 or not output.strip():
        raise RuntimeError(f"failed to create remote temp dir: {name}")
    return output.strip().splitlines()[-1]


def scp_files(local_paths, remote_dir, results, commands_file, name):
    target_dir = remote_dir if not str(remote_dir).endswith("/") else remote_dir
    for local_path in local_paths:
        command = scp(local_path, f"{target_dir}/{pathlib.Path(local_path).name}")
        item_name = f"{name}-{pathlib.Path(local_path).name}"
        output_prefix = results / "metadata" / "trojan" / item_name
        record, _ = execute_attempt(command, output_prefix, 30, commands_file, item_name, 1)
        if record["exit_code"] != 0:
            raise RuntimeError(f"scp failed for {local_path}")
    return target_dir


def trojan_deploy(args):
    results = ROOT / "results" / args.run_id
    runtime = ROOT / "runtime" / args.run_id
    if not (results / "metadata" / "manifest.json").is_file():
        raise FileNotFoundError(f"prepared run not found: {args.run_id}")
    commands_file = results / "metadata" / "commands.jsonl"
    sources = [runtime / "server.json", runtime / "server.crt", runtime / "server.key"]
    for path in sources:
        if not path.is_file():
            raise FileNotFoundError(f"missing prepared file: {path}")
    remote_dir = ensure_remote_dir("/tmp/trojan-r2", results, commands_file, "trojan-deploy")
    scp_files(sources, remote_dir, results, commands_file, "trojan-deploy")
    server = load_json(runtime / "server.json")
    server["ssl"]["cert"] = f"{remote_dir}/server.crt"
    server["ssl"]["key"] = f"{remote_dir}/server.key"
    server_text = json.dumps(server, indent=4) + "\n"
    json.loads(server_text)
    command = ssh(f"cat > {shlex.quote(remote_dir + '/server.json')} && chmod 600 {shlex.quote(remote_dir + '/server.json')}")
    record, _ = execute_attempt(command, results / "metadata" / "trojan" / "trojan-deploy-server-json", 30, commands_file, "trojan-deploy-server-json", 1, server_text)
    if record["exit_code"] != 0:
        raise RuntimeError("failed to write deployed server.json")
    record_payload = {"run_id": args.run_id, "remote_dir": remote_dir, "files": [path.name for path in sources], "transferred_utc": utc_now()}
    write_json(results / "metadata" / "trojan-deploy.json", record_payload)
    print(posix(results / "metadata" / "trojan-deploy.json"))
    print(remote_dir)


def start_remote_named(name, remote_dir, command_tail, results, commands_file, marker):
    remote_log = f"{remote_dir}/{name}.log"
    quoted_log = shlex.quote(remote_log)
    remote = (
        f"cd {shlex.quote(remote_dir)}; "
        f"nohup {command_tail} >{quoted_log} 2>&1 </dev/null & "
        f"pid=$!; sleep 1; test -r /proc/$pid/cmdline || exit 74; "
        f"tr '\\0' ' ' </proc/$pid/cmdline; printf '\\n%s\\n' \"$pid\""
    )
    item = run_item(ssh(remote), results / "logs" / name, f"{name}-start", commands_file, attempt_timeout=30)
    if not item["valid"]:
        raise RuntimeError(f"remote {name} failed to start")
    stdout_path = results / item["attempts"][-1]["stdout"]
    lines = stdout_path.read_text().splitlines()
    pid = int(lines[-1])
    cmdline = " ".join(lines[:-1])
    if marker not in cmdline:
        raise RuntimeError(f"remote {name} cmdline mismatch: {cmdline!r}")
    payload = {"name": name, "pid": pid, "cmdline": cmdline, "remote_dir": remote_dir, "remote_log": remote_log, "marker": marker, "started_utc": utc_now()}
    write_json(results / "metadata" / f"{name}.json", payload)
    return payload


def stop_remote_named(name, results, commands_file):
    metadata_path = results / "metadata" / f"{name}.json"
    if not metadata_path.is_file():
        return {"name": name, "skipped": True, "reason": "no metadata"}
    payload = load_json(metadata_path)
    pid = int(payload["pid"])
    marker = payload["marker"]
    quoted_marker = shlex.quote(marker)
    remote = (
        f"pid={pid}; test -r /proc/$pid/cmdline || exit 0; "
        f"cmd=$(tr '\\0' ' ' </proc/$pid/cmdline); "
        f"case \"$cmd\" in *{quoted_marker}*) kill \"$pid\"; "
        f"for n in 1 2 3 4 5; do test ! -e /proc/$pid && break; sleep 1; done; "
        f"test ! -e /proc/$pid;; "
        f"*) printf '%s\\n' \"$cmd\" >&2; exit 75;; esac"
    )
    item = run_item(ssh(remote), results / "logs" / name, f"{name}-stop", commands_file, attempt_timeout=20)
    return {"name": name, "stopped": item["valid"], "attempts": item["attempts"]}


def trojan_start(args):
    results = ROOT / "results" / args.run_id
    if not (results / "metadata" / "trojan-deploy.json").is_file():
        raise FileNotFoundError("trojan-deploy must run before trojan-start")
    commands_file = results / "metadata" / "commands.jsonl"
    deploy = load_json(results / "metadata" / "trojan-deploy.json")
    remote_dir = deploy["remote_dir"]
    manifest = load_json(results / "metadata" / "manifest.json")
    binary = f"{manifest['remote']['repo']}/build/trojan"
    marker = f"{binary} -c server.json"
    payload = start_remote_named("trojan-server", remote_dir, f"{shlex.quote(binary)} -c server.json -l trojan-server.log", results, commands_file, marker)
    payload["server_config"] = f"{remote_dir}/server.json"
    payload["listen_port"] = TROJAN_REMOTE_PORT
    write_json(results / "metadata" / "trojan-server.json", payload)
    print(posix(results / "metadata" / "trojan-server.json"))
    return payload


def trojan_stop(args):
    results = ROOT / "results" / args.run_id
    if not (results / "metadata" / "trojan-server.json").is_file():
        raise FileNotFoundError("trojan-server metadata missing")
    commands_file = results / "metadata" / "commands.jsonl"
    outcome = stop_remote_named("trojan-server", results, commands_file)
    write_json(results / "metadata" / "trojan-server-stop.json", outcome)
    print(posix(results / "metadata" / "trojan-server-stop.json"))


BYTESOURCE_SCRIPT = (
    "import sys, re\n"
    "from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer\n"
    "block = bytes(((i * 31 + 7) & 0xFF) for i in range(65536))\n"
    "class H(BaseHTTPRequestHandler):\n"
    "    def do_GET(self):\n"
    "        m = re.fullmatch(r'/(\\d+)', self.path)\n"
    "        if not m:\n"
    "            self.send_response(400); self.send_header('Content-Length', '0'); self.end_headers(); return\n"
    "        n = int(m.group(1))\n"
    "        self.send_response(200); self.send_header('Content-Length', str(n)); self.end_headers()\n"
    "        sent = 0\n"
    "        while sent < n:\n"
    "            chunk = block[:min(len(block), n - sent)]\n"
    "            self.wfile.write(chunk)\n"
    "            sent += len(chunk)\n"
    "    def log_message(self, *a, **k):\n"
    "        pass\n"
    "port = int(sys.argv[1]) if len(sys.argv) > 1 else 8001\n"
    "ThreadingHTTPServer(('127.0.0.1', port), H).serve_forever()\n"
)


def bytesource_start(args):
    results = ROOT / "results" / args.run_id
    if not (results / "metadata" / "trojan-deploy.json").is_file():
        raise FileNotFoundError("trojan-deploy must run before bytesource-start")
    commands_file = results / "metadata" / "commands.jsonl"
    deploy = load_json(results / "metadata" / "trojan-deploy.json")
    remote_dir = deploy["remote_dir"]
    script_name = "bytesource.py"
    script_remote = f"{remote_dir}/{script_name}"
    write_remote = f"cat > {shlex.quote(script_remote)} <<'__BYTESOURCE_EOF__'\n{BYTESOURCE_SCRIPT}__BYTESOURCE_EOF__"
    output_prefix = results / "logs" / "bytesource" / "bytesource-upload"
    record, _ = execute_attempt(ssh(write_remote), output_prefix, 30, commands_file, "bytesource-upload", 1)
    if record["exit_code"] != 0:
        raise RuntimeError("failed to upload bytesource script")
    marker = f"python3 {script_name} {BYTESOURCE_PORT}"
    payload = start_remote_named("bytesource", remote_dir, f"python3 {script_name} {BYTESOURCE_PORT}", results, commands_file, marker)
    payload["script"] = script_remote
    payload["port"] = BYTESOURCE_PORT
    payload["bind"] = "127.0.0.1"
    write_json(results / "metadata" / "bytesource.json", payload)
    print(posix(results / "metadata" / "bytesource.json"))
    return payload


def bytesource_stop(args):
    results = ROOT / "results" / args.run_id
    if not (results / "metadata" / "bytesource.json").is_file():
        raise FileNotFoundError("bytesource metadata missing")
    commands_file = results / "metadata" / "commands.jsonl"
    outcome = stop_remote_named("bytesource", results, commands_file)
    write_json(results / "metadata" / "bytesource-stop.json", outcome)
    print(posix(results / "metadata" / "bytesource-stop.json"))


def start_local_client(runtime, protocol, port, results, commands_file):
    config_path = runtime / f"client-{protocol}.json"
    if not config_path.is_file():
        raise FileNotFoundError(f"client config missing: {config_path}")
    if local_lsof(port):
        raise RuntimeError(f"local port already in use: {port}")
    log_path = results / "logs" / f"client-{protocol}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    process = subprocess.Popen([str(TROJAN_BINARY), "-c", str(config_path), "-l", str(log_path)], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    started_utc = utc_now()
    if not wait_local_port(port, process=process, timeout=30):
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
        raise RuntimeError(f"local trojan client {protocol} did not listen on {port}")
    record = {"protocol": protocol, "pid": process.pid, "port": port, "config": posix(config_path), "binary": posix(TROJAN_BINARY), "log": posix(log_path), "started_utc": started_utc, "process": process}
    write_json(results / "metadata" / f"client-{protocol}.json", {k: v for k, v in record.items() if k != "process"})
    return record


def stop_local_client(client, results, commands_file):
    process = client["process"]
    protocol = client["protocol"]
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
    write_json(results / "metadata" / f"client-{protocol}-stop.json", {"protocol": protocol, "pid": client["pid"], "port": client["port"], "stopped_utc": utc_now(), "exit_code": process.returncode})
    return {"protocol": protocol, "stopped": True, "exit_code": process.returncode}


def valid_trojan(record, output, output_path, expected_size):
    if record["exit_code"] != 0:
        return False
    if not output_path.is_file():
        return False
    if output_path.stat().st_size != expected_size:
        return False
    expected_sha = bytesource_sha256(expected_size)
    actual_sha = sha256(output_path) if output_path.stat().st_size else ""
    return actual_sha == expected_sha


def summarize_trojan(record, output, output_path, expected_size, run_number, protocol):
    port = TROJAN_LOCAL_PORT_TCP if protocol == "tcp" else TROJAN_LOCAL_PORT_QUIC
    url = f"http://127.0.0.1:{BYTESOURCE_PORT}/{expected_size}"
    actual_size = output_path.stat().st_size if output_path.exists() else 0
    actual_sha = sha256(output_path) if output_path.exists() and actual_size else ""
    expected_sha = bytesource_sha256(expected_size)
    valid = valid_trojan(record, output, output_path, expected_size)
    return {"run": run_number, "protocol": protocol, "bytes": expected_size, "port": port, "url": url, "exit_code": record["exit_code"], "duration_seconds": record["duration_seconds"], "started_utc": record["started_utc"], "ended_utc": record["ended_utc"], "actual_size": actual_size, "expected_size": expected_size, "actual_sha256": actual_sha, "expected_sha256": expected_sha, "valid": valid}


def trojan_test(args):
    results = ROOT / "results" / args.run_id
    runtime = ROOT / "runtime" / args.run_id
    if not (results / "metadata" / "manifest.json").is_file():
        raise FileNotFoundError(f"prepared run not found: {args.run_id}")
    commands_file = results / "metadata" / "commands.jsonl"
    size = int(args.bytes)
    if size < 1 or size > R2_MAX_SAMPLE_BYTES:
        raise ValueError(f"bytes must be in [1, {R2_MAX_SAMPLE_BYTES}]")
    protocol = args.protocol
    if protocol not in ("tcp", "quic"):
        raise ValueError("protocol must be 'tcp' or 'quic'")
    port = TROJAN_LOCAL_PORT_TCP if protocol == "tcp" else TROJAN_LOCAL_PORT_QUIC
    target_dir = results / "trojan-tests" / f"{protocol}"
    target_dir.mkdir(parents=True, exist_ok=True)
    output_path = target_dir / f"{size}-{args.run}.bin"
    log_prefix = target_dir / f"{size}-{args.run}"
    url = f"http://127.0.0.1:{BYTESOURCE_PORT}/{size}"
    command = ["curl", "-sS", "-o", str(output_path), "--socks5-hostname", f"127.0.0.1:{port}", url]
    record, output = execute_attempt(command, log_prefix, DEFAULT_ATTEMPT_TIMEOUT, commands_file, f"trojan-test-{protocol}-{size}", args.run)
    summary = summarize_trojan(record, output, output_path, size, args.run, protocol)
    write_json(target_dir / f"{size}-{args.run}.json", summary)
    print(posix(target_dir / f"{size}-{args.run}.json"))
    return summary


def r2(args):
    if args.runs < 1:
        raise ValueError("runs must be >= 1")
    results = ROOT / "results" / args.run_id
    runtime = ROOT / "runtime" / args.run_id
    if not (results / "metadata" / "manifest.json").is_file():
        raise FileNotFoundError(f"prepared run not found: {args.run_id}")
    if not (results / "metadata" / "trojan-deploy.json").is_file():
        raise FileNotFoundError("trojan-deploy must run before r2")
    commands_file = results / "metadata" / "commands.jsonl"
    bytesource_payload_meta = None
    trojan_server_meta = None
    tcp_client = None
    quic_client = None
    sizes = tuple(args.sizes or R2_DEFAULT_SIZES)
    if any(size < 1 or size > R2_MAX_SAMPLE_BYTES for size in sizes):
        raise ValueError(f"sizes must be in [1, {R2_MAX_SAMPLE_BYTES}]")
    summary = {"run_id": args.run_id, "started_utc": utc_now(), "runs": args.runs, "sizes": list(sizes), "samples": []}
    try:
        bytesource_start_args = argparse.Namespace(run_id=args.run_id)
        bytesource_payload_meta = bytesource_start(bytesource_start_args)
        trojan_start_args = argparse.Namespace(run_id=args.run_id)
        trojan_server_meta = trojan_start(trojan_start_args)
        tcp_client = start_local_client(runtime, "tcp", TROJAN_LOCAL_PORT_TCP, results, commands_file)
        quic_client = start_local_client(runtime, "quic", TROJAN_LOCAL_PORT_QUIC, results, commands_file)
        for run_number in range(1, args.runs + 1):
            for size in sizes:
                for protocol in ("tcp", "quic"):
                    test_args = argparse.Namespace(run_id=args.run_id, bytes=size, protocol=protocol, run=run_number)
                    sample = trojan_test(test_args)
                    summary["samples"].append(sample)
    finally:
        summary["ended_utc"] = utc_now()
        for client in (tcp_client, quic_client):
            if client is not None:
                try:
                    stop_local_client(client, results, commands_file)
                except Exception as error:
                    print(f"client stop failed: {error}", file=sys.stderr)
        if trojan_server_meta is not None:
            try:
                trojan_stop(argparse.Namespace(run_id=args.run_id))
            except Exception as error:
                print(f"trojan stop failed: {error}", file=sys.stderr)
        if bytesource_payload_meta is not None:
            try:
                bytesource_stop(argparse.Namespace(run_id=args.run_id))
            except Exception as error:
                print(f"bytesource stop failed: {error}", file=sys.stderr)
    summary["valid_sample_count"] = sum(1 for sample in summary["samples"] if sample["valid"])
    summary["invalid_sample_count"] = sum(1 for sample in summary["samples"] if not sample["valid"])
    write_json(results / "r2-summary.json", summary)
    print(posix(results / "r2-summary.json"))


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
    command = subparsers.add_parser("trojan-deploy")
    command.add_argument("--run-id", required=True)
    command = subparsers.add_parser("trojan-start")
    command.add_argument("--run-id", required=True)
    command = subparsers.add_parser("trojan-stop")
    command.add_argument("--run-id", required=True)
    command = subparsers.add_parser("bytesource-start")
    command.add_argument("--run-id", required=True)
    command = subparsers.add_parser("bytesource-stop")
    command.add_argument("--run-id", required=True)
    command = subparsers.add_parser("trojan-test")
    command.add_argument("--run-id", required=True)
    command.add_argument("--protocol", required=True, choices=("tcp", "quic"))
    command.add_argument("--bytes", required=True, type=int)
    command.add_argument("--run", default=1, type=int)
    command = subparsers.add_parser("r2")
    command.add_argument("--run-id", required=True)
    command.add_argument("--runs", default=1, type=int)
    command.add_argument("--sizes", nargs="+", type=int)
    return parser.parse_args()


def main():
    args = parse_args()
    if args.command == "prepare":
        prepare(args)
    elif args.command == "baseline":
        baseline(args)
    elif args.command == "trojan-deploy":
        trojan_deploy(args)
    elif args.command == "trojan-start":
        trojan_start(args)
    elif args.command == "trojan-stop":
        trojan_stop(args)
    elif args.command == "bytesource-start":
        bytesource_start(args)
    elif args.command == "bytesource-stop":
        bytesource_stop(args)
    elif args.command == "trojan-test":
        trojan_test(args)
    elif args.command == "r2":
        r2(args)


if __name__ == "__main__":
    try:
        main()
    except (FileExistsError, FileNotFoundError, RuntimeError, ValueError, subprocess.CalledProcessError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
