#!/usr/bin/env python3

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import re
import secrets
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
RESULT_DIRS = ("metadata", "baseline", "direct", "tcp-tls", "quic", "logs", "captures")
RUN_ID_RE = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]{7,40}-r\d+$")


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
    run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key_path), "-out", str(cert_path), "-days", "7",
        "-subj", f"/CN={args.host}", "-addext", f"subjectAltName=IP:{args.host}",
    ])
    key_path.chmod(0o600)
    cert_path.chmod(0o644)

    server = runtime / "server.json"
    client_quic = runtime / "client-quic.json"
    client_tcp = runtime / "client-tcp.json"
    render("server.json.template", server, {
        "PASSWORD": password,
        "CERT_PATH": args.remote_runtime + "/server.crt",
        "KEY_PATH": args.remote_runtime + "/server.key",
    })
    client_values = {
        "PASSWORD": password,
        "CERT_PATH": str(cert_path).replace("\\", "/"),
        "REMOTE_ADDR": args.host,
    }
    render("client-quic.json.template", client_quic, client_values)
    render("client-tcp.json.template", client_tcp, client_values)

    commit = run(["git", "rev-parse", "HEAD"], repo)
    status = run(["git", "status", "--short", "--branch"], repo)
    created = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    manifest = {
        "run_id": args.run_id,
        "created_utc": created,
        "baseline_commit": commit,
        "local": {"repo": str(repo).replace("\\", "/"), "status": status},
        "remote": {
            "host": args.host,
            "ssh_port": args.ssh_port,
            "user": args.ssh_user,
            "repo": args.remote_repo,
            "runtime": args.remote_runtime,
        },
        "build": {
            "type": "Release",
            "cmake_args": ["-DCMAKE_BUILD_TYPE=Release", "-DENABLE_QUIC=ON"],
        },
        "config_sha256": {
            "server": sha256(server),
            "client_quic": sha256(client_quic),
            "client_tcp": sha256(client_tcp),
        },
        "commands_file": "metadata/commands.jsonl",
    }
    manifest_path = results / "metadata" / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=4) + "\n")
    print(args.run_id)
    print(runtime)
    print(results)


def parse_args():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    command = subparsers.add_parser("prepare")
    command.add_argument("--run-id", required=True)
    command.add_argument("--host", default="172.236.226.35")
    command.add_argument("--ssh-user", default="root")
    command.add_argument("--ssh-port", default=9922, type=int)
    command.add_argument("--local-repo", default=str(ROOT.parent))
    command.add_argument("--remote-repo", default="/root/trojan-plus")
    command.add_argument("--remote-runtime", default="/root/trojan-plus/quic_proxy_test_remote/runtime")
    return parser.parse_args()


def main():
    args = parse_args()
    if args.command == "prepare":
        prepare(args)


if __name__ == "__main__":
    try:
        main()
    except (FileExistsError, ValueError, subprocess.CalledProcessError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
