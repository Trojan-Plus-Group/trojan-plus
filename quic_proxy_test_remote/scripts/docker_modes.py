#!/usr/bin/env python3

import argparse
import importlib.util
import ipaddress
import json
import pathlib
import re
import socket
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
RUNNER_PATH = pathlib.Path(__file__).with_name("run.py")
HOST = "172.236.226.35"
SSH_PORT = 9922
SIZE = 1 << 20
WATCHDOG = 180
IMAGE = "trojan-plus-docker-modes"
CLOUDFLARE_HOST = "speed.cloudflare.com"
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


def load_runner():
    spec = importlib.util.spec_from_file_location("remote_runner", RUNNER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def command_output(command, timeout=30):
    return subprocess.run(command, text=True, capture_output=True, check=True, timeout=timeout).stdout.strip()


def ssh(command):
    return ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-p", str(SSH_PORT), f"root@{HOST}", command]


def validate_run_id(value):
    if not NAME_RE.fullmatch(value):
        raise ValueError("run-id must contain only letters, digits, dot, underscore, or hyphen")
    return value


def parse_cloudflare_ipv4(values):
    addresses = set()
    for value in values:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as error:
            raise ValueError("Cloudflare resolution returned invalid address") from error
        if address.version != 4 or not address.is_global:
            raise ValueError("Cloudflare resolution returned non-public IPv4")
        addresses.add(str(address))
    if len(addresses) != 1:
        raise ValueError("Cloudflare resolution must return exactly one IPv4")
    return addresses.pop()


def resolve_cloudflare_ipv4():
    return parse_cloudflare_ipv4((socket.gethostbyname(CLOUDFLARE_HOST),))


def docker_commands(mode, protocol, run_id, runtime, target_ip, size=SIZE, watchdog=WATCHDOG, requests=1, concurrency=1):
    validate_run_id(run_id)
    target_ip = parse_cloudflare_ipv4((target_ip,))
    if mode not in ("nat", "client_tun") or protocol not in ("tcp", "quic"):
        raise ValueError("invalid mode or protocol")
    name = f"trojan-{mode}-{protocol}-{run_id}"
    config = f"/runtime/{mode}-{protocol}.json"
    capabilities = ["--cap-add", "NET_ADMIN"]
    if mode == "nat":
        capabilities += ["--cap-add", "NET_RAW"]
    base = ["docker", "run", "--rm", "--name", name, "--cap-drop", "ALL", *capabilities, "--device", "/dev/net/tun", "-v", f"{runtime}:/runtime:ro", IMAGE]
    if size == SIZE and watchdog == WATCHDOG and requests == 1 and concurrency == 1:
        tail = [mode, protocol, config, target_ip, str(SIZE), str(WATCHDOG)]
    else:
        tail = [mode, protocol, config, target_ip, str(size), str(watchdog), str(requests), str(concurrency)]
    return {"name": name, "run": base + tail, "remove": ["docker", "rm", "-f", name]}


def render_configs(runtime, protocol, password, cert):
    common = json.loads((ROOT / f"client-{protocol}.json.template").read_text().replace("${PASSWORD}", password).replace("${CERT_PATH}", "/runtime/server.crt").replace("${REMOTE_ADDR}", HOST))
    common["local_addr"] = "0.0.0.0"
    common["local_port"] = 12345
    nat = json.loads(json.dumps(common))
    nat["run_type"] = "nat"
    nat["tcp"]["use_tproxy"] = False
    tun = json.loads(json.dumps(common))
    tun["run_type"] = "client_tun"
    tun["tun"] = {"tun_name": "tun0", "net_ip": "10.77.0.2", "net_mask": "255.255.255.0", "mtu": 1500, "redirect_local": False}
    tun["dns"] = {"enabled": False}
    tun["route"] = {"enabled": False}
    runtime.mkdir(parents=True, mode=0o700, exist_ok=True)
    (runtime / "server.crt").write_bytes(cert)
    for mode, config in (("nat", nat), ("client_tun", tun)):
        (runtime / f"{mode}-{protocol}.json").write_text(json.dumps(config, indent=4) + "\n")


def measure_iperf3_baseline():
    """Measures raw download throughput from remote server using iperf3."""
    remote_log = "/tmp/iperf3_docker_baseline.log"
    subprocess.run(ssh("pkill -9 -f 'iperf3 -s' || true"), capture_output=True, text=True, timeout=10)
    start_cmd = f"nohup iperf3 -s -p 5201 > {remote_log} 2>&1 < /dev/null & sleep 1; pgrep -f 'iperf3 -s -p 5201'"
    res = subprocess.run(ssh(start_cmd), capture_output=True, text=True, timeout=15)
    server_pid = res.stdout.strip()
    if not server_pid:
        return {"available": False, "error": "Failed to start remote iperf3 server"}
    try:
        client_res = subprocess.run(
            ["iperf3", "-c", HOST, "-p", "5201", "-R", "-t", "3", "-J"],
            capture_output=True, text=True, timeout=15
        )
        if client_res.returncode != 0:
            return {"available": False, "error": client_res.stderr.strip() or "iperf3 client failed"}
        data = json.loads(client_res.stdout)
        bps = data["end"]["sum_received"]["bits_per_second"]
        mbps = round(bps / 1e6, 2)
        return {"available": True, "mbps": mbps, "raw_bps": bps}
    except Exception as e:
        return {"available": False, "error": str(e)}
    finally:
        subprocess.run(ssh(f"kill -9 {server_pid} 2>/dev/null || pkill -9 -f 'iperf3 -s' || true; rm -f {remote_log}"),
                       capture_output=True, text=True, timeout=10)


def build_image():
    command_output(["docker", "build", "-t", IMAGE, "-f", str(ROOT / "Dockerfile.template"), str(ROOT)], 300)


def smoke(args):
    runner = load_runner()
    size = getattr(args, "size", SIZE)
    watchdog = getattr(args, "watchdog", WATCHDOG)
    requests = getattr(args, "requests", 1)
    concurrency = getattr(args, "concurrency", 1)
    with_iperf = getattr(args, "with_iperf", False)

    runtime = ROOT / "runtime" / f"docker-{args.run_id}"
    results = ROOT / "results" / f"docker-{args.run_id}-{args.mode}-{args.protocol}.json"
    if runtime.exists() or results.exists():
        raise FileExistsError("Docker smoke run already exists")
    deploy_args = argparse.Namespace(run_id=args.run_id, server_disable_tcp=args.protocol == "quic")
    server = container = remote_dir = None
    report = {
        "run_id": args.run_id,
        "mode": args.mode,
        "protocol": args.protocol,
        "watchdog_seconds": watchdog,
        "expected_size": size,
        "requests": requests,
        "concurrency": concurrency,
        "cleanup": {}
    }
    try:
        if with_iperf or requests > 1:
            print(f"[*] Measuring raw iperf3 download baseline against {HOST}:5201...")
            iperf_res = measure_iperf3_baseline()
            report["iperf_baseline"] = iperf_res
            if iperf_res.get("available"):
                print(f"[+] Raw network iperf3 reverse throughput: {iperf_res['mbps']} Mbps")

        target_ip = resolve_cloudflare_ipv4()
        report["cloudflare_ipv4"] = target_ip
        runner.prepare(argparse.Namespace(run_id=args.run_id, local_repo=str(ROOT.parent), remote_repo="/root/trojan-plus", remote_runtime="/root/trojan-plus/quic_proxy_test_remote/runtime"))
        runner.trojan_deploy(deploy_args)
        metadata = runner.load_json(ROOT / "results" / args.run_id / "metadata" / "trojan-deploy.json")
        remote_dir = metadata["remote_dir"]
        manifest = runner.load_json(ROOT / "results" / args.run_id / "metadata" / "manifest.json")
        runtime.mkdir(parents=True, mode=0o700, exist_ok=True)
        remote_binary = f"{manifest['remote']['repo']}/build/trojan"
        command_output(["scp", "-P", str(SSH_PORT), f"root@{HOST}:{remote_binary}", str(runtime / "trojan")], 60)
        (runtime / "trojan").chmod(0o700)
        render_configs(runtime, args.protocol, (ROOT / "runtime" / args.run_id / "password").read_text().strip(), (ROOT / "runtime" / args.run_id / "server.crt").read_bytes())
        build_image()
        server = runner.trojan_start(argparse.Namespace(run_id=args.run_id))
        commands = docker_commands(args.mode, args.protocol, args.run_id, runtime, target_ip, size, watchdog, requests, concurrency)
        container = commands["name"]
        completed = subprocess.run(commands["run"], text=True, capture_output=True, timeout=watchdog + 10, check=False)
        if not completed.stdout.strip():
            raise RuntimeError(f"Docker mode failed: {completed.stderr.strip()}")
        payload = json.loads(completed.stdout)
        report.update(payload)
        report["docker_stderr"] = completed.stderr
        report["exit_code"] = completed.returncode
        if "all_success" in payload:
            report["valid"] = completed.returncode == 0 and payload["all_success"]
        else:
            report["valid"] = completed.returncode == 0 and payload.get("http_code") == 200 and payload.get("size_download") == size and payload.get("actual_size") == size

        if report.get("iperf_baseline", {}).get("available"):
            iperf_mbps = report["iperf_baseline"]["mbps"]
            proxy_mbps = report.get("speed_mbps_median", 0.0)
            ratio = round(proxy_mbps / iperf_mbps, 3) if iperf_mbps > 0 else 0.0
            report["iperf_ratio"] = ratio
            if ratio < 0.2:
                warning_msg = f"Proxy throughput ({proxy_mbps} Mbps) deviates significantly from iperf3 raw link ({iperf_mbps} Mbps), ratio={ratio}"
                report["iperf_deviation_warning"] = warning_msg
                print(f"[!] WARNING: {warning_msg}", file=sys.stderr)
    finally:
        if container:
            subprocess.run(["docker", "rm", "-f", container], capture_output=True, text=True, check=False)
        if server:
            runner.trojan_stop(argparse.Namespace(run_id=args.run_id))
        if remote_dir:
            try:
                server_log = results.parent / f"docker-{args.run_id}-{args.mode}-{args.protocol}-server.log"
                command_output(["scp", "-P", str(SSH_PORT), f"root@{HOST}:{remote_dir}/trojan-server.log", str(server_log)], 15)
                report["server_log"] = str(server_log)
            except Exception:
                pass
            command_output(ssh(f"rm -rf -- {remote_dir}"))
        report["cleanup"]["docker"] = command_output(["docker", "ps", "-a", "--filter", f"name=trojan-{args.mode}-{args.protocol}-{args.run_id}", "--format", "{{.Names}}"])
        results.parent.mkdir(parents=True, exist_ok=True)
        results.write_text(json.dumps(report, indent=4) + "\n")
    print(results)
    if not report.get("valid"):
        if report.get("docker_stderr"):
            print("=== docker_stderr ===", file=sys.stderr)
            print(report["docker_stderr"], file=sys.stderr)
        raise RuntimeError("Docker smoke validation failed")


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", required=True, choices=("nat", "client_tun"))
    parser.add_argument("--protocol", required=True, choices=("tcp", "quic"))
    parser.add_argument("--run-id", required=True, type=validate_run_id)
    parser.add_argument("--size", type=int, default=SIZE)
    parser.add_argument("--watchdog", type=int, default=WATCHDOG)
    parser.add_argument("--requests", type=int, default=1)
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument("--with-iperf", action="store_true", help="Record raw iperf3 baseline before test")
    return parser.parse_args()


if __name__ == "__main__":
    try:
        smoke(parse_args())
    except (FileExistsError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)

