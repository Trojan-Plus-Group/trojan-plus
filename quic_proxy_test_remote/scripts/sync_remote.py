#!/usr/bin/env python3
"""
Synchronize local branch to remote server using git bundle and build safely.

Remote Server Specs & Stability Constraints:
- Host: 172.236.226.35 (Port 9922)
- Hardware: 1 vCPU, 1G RAM (954 MB RAM, 2.5 GB swap)
- OOM Risk: Heavy tasks or parallel compilation will trigger Linux kernel OOM Killer,
  terminating system critical processes (e.g. systemd pid 83234) and crashing the system:
    [143642.613087] oom-kill:constraint=CONSTRAINT_NONE... task=systemd,pid=83234,uid=0
    [143642.616566] Out of memory: Killed process 83234 (systemd) total-vm:20336kB...
- Rules:
  1. Never run parallel builds (--parallel or -j > 1) on the remote host. Always use -j 1.
  2. Never push directly to remote origin. Always use git bundle via SCP/SSH fast-forward.
"""

import argparse
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
HOST = "172.236.226.35"
SSH_PORT = 9922
REMOTE_REPO = "/root/trojan-plus"


def run_cmd(cmd, cwd=None, check=True, timeout=120):
    return subprocess.run(
        cmd,
        cwd=cwd,
        check=check,
        text=True,
        capture_output=True,
        timeout=timeout
    )


def ssh_cmd(remote_script):
    return [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=10",
        "-p", str(SSH_PORT),
        f"root@{HOST}",
        remote_script,
    ]


def status_remote():
    print(f"[*] Querying remote host status (172.236.226.35:9922)...")
    remote_script = (
        f"echo '--- Git Commit ---' && "
        f"git -C {REMOTE_REPO} log -1 --format='%h (%ci) %s' && "
        f"echo '--- Memory Status ---' && "
        f"free -h && "
        f"echo '--- Trojan Binary ---' && "
        f"ls -lh {REMOTE_REPO}/build/trojan 2>/dev/null || echo 'trojan binary missing' && "
        f"{REMOTE_REPO}/build/trojan --version 2>/dev/null || true && "
        f"echo '--- Active Listeners (3443/5201/8001) ---' && "
        f"ss -tulpn | grep -E '3443|5201|8001' || echo 'None'"
    )
    res = run_cmd(ssh_cmd(remote_script), timeout=30)
    print(res.stdout.strip())


def sync_bundle(branch="fix_quic"):
    bundle_file = f"/tmp/{branch}.bundle"
    local_bundle = pathlib.Path(bundle_file)
    remote_bundle = f"/tmp/{branch}.bundle"

    print(f"[*] Step 1: Creating local git bundle for branch '{branch}'...")
    if local_bundle.exists():
        local_bundle.unlink()
    try:
        run_cmd(["git", "bundle", "create", str(local_bundle), branch], cwd=ROOT)

        print(f"[*] Step 2: Transferring bundle to root@{HOST}:{remote_bundle} via SCP...")
        run_cmd(["scp", "-P", str(SSH_PORT), str(local_bundle), f"root@{HOST}:{remote_bundle}"])

        print(f"[*] Step 3: Fast-forwarding {REMOTE_REPO} on remote...")
        remote_script = (
            f"git -C {REMOTE_REPO} fetch {remote_bundle} {branch} && "
            f"git -C {REMOTE_REPO} merge --ff-only FETCH_HEAD && "
            f"rm -f {remote_bundle}"
        )
        res = run_cmd(ssh_cmd(remote_script), timeout=60)
        if res.stdout.strip():
            print(res.stdout.strip())
        print("[+] Remote repository fast-forwarded successfully.")
    finally:
        local_bundle.unlink(missing_ok=True)
        # Ensure remote temp bundle is cleaned up even if fetch failed
        run_cmd(ssh_cmd(f"rm -f {remote_bundle}"), check=False, timeout=15)


def build_remote(jobs=1):
    if jobs != 1:
        print(
            f"[!] WARNING: Remote host is 1 CPU, 1G RAM. Build jobs (-j {jobs}) "
            "must be 1. Clamping jobs to 1.",
            file=sys.stderr
        )
        jobs = 1

    print(f"[*] Building on remote server (strict -j {jobs} for 1 CPU/1G RAM safety)...")
    build_cmd = (
        f"cd {REMOTE_REPO} && "
        f"cmake --build build -j {jobs} && "
        f"ls -lh build/trojan && "
        f"build/trojan --version && "
        f"free -h"
    )
    res = run_cmd(ssh_cmd(build_cmd), timeout=600)
    if res.stdout.strip():
        print(res.stdout.strip())
    print("[+] Remote trojan build and verification completed successfully.")


def main():
    parser = argparse.ArgumentParser(
        description="Sync code to remote 1CPU/1G RAM server via git bundle and build safely"
    )
    parser.add_argument("--branch", default="fix_quic", help="Branch to bundle and sync (default: fix_quic)")
    parser.add_argument("--build-only", action="store_true", help="Only build on remote without bundling")
    parser.add_argument("--sync-only", action="store_true", help="Only sync bundle without building")
    parser.add_argument("--status", action="store_true", help="Check remote host git, binary, and memory status")
    parser.add_argument(
        "--jobs",
        type=int,
        default=1,
        help="Max compilation jobs on remote (default: 1; clamped to 1 for 1 CPU/1G RAM host safety)"
    )
    args = parser.parse_args()

    if args.status:
        status_remote()
        return

    if not args.build_only:
        sync_bundle(args.branch)
    if not args.sync_only:
        build_remote(args.jobs)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as e:
        print(f"Error: Command '{' '.join(e.cmd)}' failed with exit code {e.returncode}:", file=sys.stderr)
        if e.stderr:
            print(e.stderr.strip(), file=sys.stderr)
        sys.exit(1)
    except subprocess.TimeoutExpired as e:
        print(f"Error: Command '{' '.join(e.cmd)}' timed out after {e.timeout}s", file=sys.stderr)
        sys.exit(1)
