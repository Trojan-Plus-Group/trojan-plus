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
  2. Never push directly to remote origin. Use git bundle via SCP/SSH and reset only the matching remote test branch.
"""

import argparse
import pathlib
import shlex
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


def ssh_cmd(remote_script, connect_timeout):
    return [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={connect_timeout}",
        "-p", str(SSH_PORT),
        f"root@{HOST}",
        remote_script,
    ]


def status_remote(connect_timeout, timeout):
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
    res = run_cmd(ssh_cmd(remote_script, connect_timeout), timeout=timeout)
    print(res.stdout.strip())


def remote_sync_command(branch, remote_bundle):
    quoted_branch = shlex.quote(branch)
    quoted_bundle = shlex.quote(remote_bundle)
    quoted_ref = shlex.quote(f"refs/heads/{branch}")
    quoted_repo = shlex.quote(REMOTE_REPO)
    return (
        f"git -C {quoted_repo} fetch {quoted_bundle} {quoted_branch} && "
        f"if git -C {quoted_repo} show-ref --verify --quiet {quoted_ref}; then "
        f"git -C {quoted_repo} switch {quoted_branch}; "
        f"else git -C {quoted_repo} switch -c {quoted_branch} FETCH_HEAD; fi && "
        f"git -C {quoted_repo} reset --hard FETCH_HEAD && "
        f"test \"$(git -C {quoted_repo} branch --show-current)\" = {quoted_branch} && "
        f"test \"$(git -C {quoted_repo} rev-parse HEAD)\" = \"$(git -C {quoted_repo} rev-parse FETCH_HEAD)\" && "
        f"rm -f {quoted_bundle}"
    )


def sync_bundle(branch, connect_timeout, bundle_timeout, transfer_timeout, sync_timeout, cleanup_timeout):
    bundle_file = f"/tmp/{branch}.bundle"
    local_bundle = pathlib.Path(bundle_file)
    remote_bundle = f"/tmp/{branch}.bundle"

    print(f"[*] Step 1: Creating local git bundle for branch '{branch}'...")
    if local_bundle.exists():
        local_bundle.unlink()
    try:
        branch_ref = f"refs/heads/{branch}"
        run_cmd(["git", "check-ref-format", "--branch", branch], cwd=ROOT, timeout=bundle_timeout)
        run_cmd(["git", "bundle", "create", str(local_bundle), branch_ref], cwd=ROOT, timeout=bundle_timeout)

        print(f"[*] Step 2: Transferring bundle to root@{HOST}:{remote_bundle} via SCP...")
        run_cmd(["scp", "-P", str(SSH_PORT), str(local_bundle), f"root@{HOST}:{remote_bundle}"], timeout=transfer_timeout)

        print(f"[*] Step 3: Switching and resetting {REMOTE_REPO} test branch '{branch}' to local bundle...")
        res = run_cmd(ssh_cmd(remote_sync_command(branch, remote_bundle), connect_timeout), timeout=sync_timeout)
        if res.stdout.strip():
            print(res.stdout.strip())
        print("[+] Remote branch and commit match local bundle successfully.")
    finally:
        local_bundle.unlink(missing_ok=True)
        run_cmd(ssh_cmd(f"rm -f {shlex.quote(remote_bundle)}", connect_timeout), check=False, timeout=cleanup_timeout)


def build_remote(jobs, connect_timeout, timeout):
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
    res = run_cmd(ssh_cmd(build_cmd, connect_timeout), timeout=timeout)
    if res.stdout.strip():
        print(res.stdout.strip())
    print("[+] Remote trojan build and verification completed successfully.")


def current_branch():
    branch = run_cmd(["git", "branch", "--show-current"], cwd=ROOT).stdout.strip()
    if not branch:
        raise RuntimeError("detached HEAD requires explicit --branch")
    return branch


def main():
    parser = argparse.ArgumentParser(
        description="Sync code to remote 1CPU/1G RAM server via git bundle and build safely"
    )
    parser.add_argument("--branch", help="Branch to bundle and sync (default: current local branch)")
    parser.add_argument("--build-only", action="store_true", help="Only build on remote without bundling")
    parser.add_argument("--sync-only", action="store_true", help="Only sync bundle without building")
    parser.add_argument("--status", action="store_true", help="Check remote host git, binary, and memory status")
    parser.add_argument("--connect-timeout", type=int, default=10, help="SSH connection timeout in seconds (default: 10)")
    parser.add_argument("--command-timeout", type=int, default=120, help="Default command timeout in seconds (default: 120)")
    parser.add_argument("--status-timeout", type=int, default=30, help="Status command timeout in seconds (default: 30)")
    parser.add_argument("--bundle-timeout", type=int, help="Bundle creation timeout in seconds (default: --command-timeout)")
    parser.add_argument("--transfer-timeout", type=int, help="Bundle transfer timeout in seconds (default: --command-timeout)")
    parser.add_argument("--sync-timeout", type=int, default=60, help="Remote sync timeout in seconds (default: 60)")
    parser.add_argument("--cleanup-timeout", type=int, default=15, help="Remote cleanup timeout in seconds (default: 15)")
    parser.add_argument("--build-timeout", type=int, default=600, help="Remote build timeout in seconds (default: 600)")
    parser.add_argument(
        "--jobs",
        type=int,
        default=1,
        help="Max compilation jobs on remote (default: 1; clamped to 1 for 1 CPU/1G RAM host safety)"
    )
    args = parser.parse_args()

    if args.status:
        status_remote(args.connect_timeout, args.status_timeout)
        return

    if not args.build_only:
        sync_bundle(
            args.branch or current_branch(),
            args.connect_timeout,
            args.bundle_timeout or args.command_timeout,
            args.transfer_timeout or args.command_timeout,
            args.sync_timeout,
            args.cleanup_timeout,
        )
    if not args.sync_only:
        build_remote(args.jobs, args.connect_timeout, args.build_timeout)


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
