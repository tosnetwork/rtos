#!/usr/bin/env python3
"""Qualify an isolated LazyFS mount before using it for node recovery tests.

This checks loss of unsynced file data, not loss of directory metadata or a
physical device's power-failure behavior. No host installation is performed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import signal
import subprocess
import tempfile
import time


def is_mounted(path):
    # stat-based ismount() returns False for a disconnected FUSE mount.
    return any(line.split()[4] == str(path)
               for line in Path("/proc/self/mountinfo").read_text().splitlines())


def wait_until(check, process, seconds=20):
    deadline = time.monotonic() + seconds
    while not check():
        if process.poll() is not None:
            raise RuntimeError(f"LazyFS exited with {process.returncode}")
        if time.monotonic() >= deadline:
            raise TimeoutError("LazyFS readiness timeout")
        time.sleep(0.02)


def write(path, value, sync, truncate=True):
    with path.open("wb" if truncate else "r+b", buffering=0) as stream:
        assert stream.write(value) == len(value)
        if sync:
            os.fsync(stream.fileno())


def clear_cache(command, completion):
    reader = os.open(completion, os.O_RDONLY | os.O_NONBLOCK)
    try:
        writer = os.open(command, os.O_WRONLY | os.O_NONBLOCK)
        try:
            command_bytes = b"lazyfs::clear-cache\n"
            assert os.write(writer, command_bytes) == len(command_bytes)
        finally:
            os.close(writer)
        deadline = time.monotonic() + 20
        received = b""
        while b"finished::clear-cache" not in received:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("LazyFS did not acknowledge cache loss")
            if select.select([reader], [], [], min(remaining, 0.1))[0]:
                chunk = os.read(reader, 4096)
                if chunk:
                    received += chunk
                    if len(received) > 8192:
                        raise RuntimeError("Unexpected LazyFS completion output")
                else:
                    time.sleep(0.01)
        return received.decode()
    finally:
        os.close(reader)


def run(binary, output, node=None):
    output.mkdir(parents=True, exist_ok=False)
    root = Path(tempfile.mkdtemp(prefix="rtos-lazyfs-preflight-"))
    mount = root / "mount"
    backing = root / "backing"
    mount.mkdir()
    backing.mkdir()
    command = root / "commands.fifo"
    completion = root / "completed.fifo"
    config = root / "config.toml"
    config.write_text(
        f'[faults]\nfifo_path="{command}"\nfifo_path_completed="{completion}"\n'
        '[cache]\napply_eviction=false\n[cache.simple]\ncustom_size="64mb"\n'
        'blocks_per_page=1\n[filesystem]\nlog_all_operations=true\nlogfile=""\n'
    )
    shutil.copyfile(config, output / "config.toml")
    result = {"binary": str(binary), "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
              "scope": "unsynced file data loss only", "passed": False}
    process = None
    try:
        with (output / "lazyfs.log").open("wb") as log:
            process = subprocess.Popen(
                [str(binary), str(mount), "--config-path", str(config),
                 "-o", "modules=subdir", "-o", f"subdir={backing}", "-f"],
                stdout=log, stderr=subprocess.STDOUT,
            )
            wait_until(lambda: is_mounted(mount) and command.exists() and completion.exists(), process)
            directory = os.open(mount, os.O_RDONLY | os.O_DIRECTORY)
            try:
                try:
                    os.fsync(directory)
                    result["directory_fsync"] = "returned success (metadata-loss behavior unproven)"
                except OSError as error:
                    result["directory_fsync"] = {"errno": error.errno, "error": str(error)}
                    raise
            finally:
                os.close(directory)
            write(mount / "synced", b"durable-before-cut", True)
            write(mount / "overwrite", b"old durable data", True)
            write(mount / "overwrite", b"new volatile txt", False, truncate=False)
            write(mount / "unsynced", b"must-disappear-after-cut", False)
            assert (mount / "overwrite").read_bytes() == b"new volatile txt"
            assert (mount / "unsynced").read_bytes() == b"must-disappear-after-cut"
            result["before_clear"] = {name: (backing / name).read_bytes().hex()
                                      for name in ["synced", "overwrite", "unsynced"]}
            result["completion"] = clear_cache(command, completion)
            assert (mount / "synced").read_bytes() == b"durable-before-cut"
            assert (mount / "overwrite").read_bytes() == b"old durable data"
            assert (mount / "unsynced").read_bytes() == b""
            result["after_clear"] = {name: (mount / name).read_bytes().hex()
                                     for name in ["synced", "overwrite", "unsynced"]}
            if node is not None:
                fixture_dir = mount / "fixtures"
                fixture_dir.mkdir()
                environment = dict(os.environ)
                environment.update({
                    "RTOS_NODE_RECOVERY_FIXTURE_DIR": str(fixture_dir),
                    "RTOS_TEST_LAZYFS_COMMAND": str(command),
                    "RTOS_TEST_LAZYFS_COMPLETED": str(completion),
                    "RTOS_NODE_RECOVERY_BINARY": str(node.node_binary.resolve(strict=True)),
                    "RTOS_PUBLIC_FIXTURE_SIGNER": str(node.fixture_signer.resolve(strict=True)),
                    "RTOS_NODE_RECOVERY_EVIDENCE_DIR": str(output / "node"),
                })
                with (output / "node-test.log").open("wb") as log:
                    case = "actual_node_sparse_packages_interrupted_metadata" if node.no_cache_loss else "actual_node_sparse_packages_cache_loss"
                    result["node_cache_loss_enabled"] = not node.no_cache_loss
                    executed = subprocess.Popen(
                        [str(node.node_test_binary.resolve(strict=True)),
                         "archive_import::tests::node_process_recovery::" + case,
                         "--exact", "--ignored", "--nocapture", "--test-threads=1"],
                        env=environment, stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
                    )
                    try:
                        executed.wait(timeout=240)
                    finally:
                        remaining = []
                        for entry in Path("/proc").iterdir():
                            if not entry.name.isdecimal():
                                continue
                            pid = int(entry.name)
                            try:
                                if os.getsid(pid) == executed.pid:
                                    os.kill(pid, signal.SIGKILL)
                                    remaining.append(pid)
                            except ProcessLookupError:
                                pass
                        executed.wait(timeout=5)
                        result["terminated_remaining_test_processes"] = remaining
                if remaining:
                    raise RuntimeError("Node test left owned processes running")
                result["node_test_exit"] = executed.returncode
                if executed.returncode != 0:
                    raise RuntimeError(f"Actual node cache-loss test failed: {executed.returncode}")
                transcript = (output / "node-test.log").read_text()
                required_evidence = ["1 passed; 0 failed", "Actual node retried real truncation",
                                     "Actual node recovery interrupted at forward-after-row-sync"]
                if not node.no_cache_loss:
                    required_evidence.append("LazyFS discarded unsynced file data")
                elif "LazyFS discarded unsynced file data" in transcript:
                    raise RuntimeError("No-loss control unexpectedly discarded cache")
                for required in required_evidence:
                    if required not in transcript:
                        raise RuntimeError(f"Missing actual-node evidence: {required}")
            result["passed"] = True
    except Exception as error:
        result["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        cleanup_errors = []
        # Stop the owned cache process explicitly; upstream leaves its FIFO
        # thread joinable on graceful unmount and aborts during destruction.
        if process is not None:
            if process.poll() is None:
                process.kill()
                result["cleanup_sent_sigkill"] = True
            else:
                cleanup_errors.append("LazyFS exited before owned teardown")
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
                cleanup_errors.append("LazyFS required SIGKILL during cleanup")
            result["process_exit"] = process.returncode
            if process.returncode != -signal.SIGKILL:
                cleanup_errors.append("Unexpected LazyFS teardown exit status")
        if is_mounted(mount):
            try:
                subprocess.run(["fusermount3", "-u", str(mount)], check=True,
                               capture_output=True, timeout=10)
            except Exception as error:
                cleanup_errors.append(str(error))
        if not is_mounted(mount):
            try:
                shutil.rmtree(root)
            except OSError as error:
                cleanup_errors.append(f"Fixture cleanup failed; preserved {root}: {error}")
        else:
            cleanup_errors.append(f"Mount still present; preserved {root}")
        result["cleanup_errors"] = cleanup_errors
        if cleanup_errors:
            result["passed"] = False
        (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    if not result["passed"]:
        raise RuntimeError("LazyFS preflight or cleanup failed")
    print(f"LazyFS file-data-loss controls passed: {output / 'result.json'}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lazyfs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--no-cache-loss", action="store_true", help="run the same node cut without cache loss as a control")
    parser.add_argument("--node-test-binary", type=Path)
    parser.add_argument("--node-binary", type=Path)
    parser.add_argument("--fixture-signer", type=Path)
    args = parser.parse_args()
    node_args = [args.node_test_binary, args.node_binary, args.fixture_signer]
    if any(node_args) and not all(node_args):
        parser.error("all three node binary/signer arguments are required together")
    run(args.lazyfs.resolve(strict=True), args.output.resolve(), args if all(node_args) else None)
