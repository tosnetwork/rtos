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
    root = Path(tempfile.mkdtemp(prefix="rtos-lazyfs-preflight-owned-"))
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
                # Upstream mistakes any "-o" substring in a config argument
                # for an option. Keep the argument relative; the owned root
                # deliberately contains "-o" so every run covers this case.
                [str(binary), str(mount), "--config-path", config.name,
                 "-o", "modules=subdir", "-o", f"subdir={backing}", "-f"],
                stdout=log, stderr=subprocess.STDOUT, cwd=root,
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
                omitted_manifest = "validator-wal" if node.omit_validator_wal_sync else "lease-wal" if node.omit_lease_wal_sync else "root-wal" if node.omit_root_wal_sync else "cleaned-wal" if node.omit_cleaned_wal_sync else "committed-wal" if node.omit_committed_wal_sync else "ready-wal" if node.omit_ready_wal_sync else "stage" if node.omit_stage_sync else "selection" if node.omit_selection_sync else "ready" if node.omit_ready_sync else None
                fixture_dir = mount / "fixtures"
                fixture_dir.mkdir()
                environment = dict(os.environ)
                environment.update({
                    "RTOS_NODE_RECOVERY_FIXTURE_DIR": str(fixture_dir),
                    "RTOS_TEST_CACHE_LOSS_ENABLED": "0" if node.no_cache_loss else "1",
                    "RTOS_TEST_LAZYFS_COMMAND": str(command),
                    "RTOS_TEST_LAZYFS_COMPLETED": str(completion),
                    "RTOS_NODE_RECOVERY_BINARY": str(node.node_binary.resolve(strict=True)),
                    "RTOS_PUBLIC_FIXTURE_SIGNER": str(node.fixture_signer.resolve(strict=True)),
                    "RTOS_NODE_RECOVERY_EVIDENCE_DIR": str(output / "node"),
                })
                if omitted_manifest:
                    if environment.get("LD_PRELOAD"):
                        raise RuntimeError("Sync sensitivity requires an otherwise clean preload environment")
                    source = Path(__file__).with_name("omit_manifest_sync.c")
                    library = output / "omit-manifest-sync.so"
                    shutil.copyfile(source, output / source.name)
                    subprocess.run(["cc", "-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-Werror",
                                    str(source), "-o", str(library)], check=True, timeout=30,
                                   capture_output=True)
                    environment.update({
                        "LD_PRELOAD": str(library),
                        "RTOS_TEST_OMIT_MANIFEST_SYNC_ROOT": str(fixture_dir) + "/",
                        "RTOS_TEST_OMIT_MANIFEST_SYNC_FILE": (omitted_manifest if omitted_manifest in ["stage", "ready-wal", "committed-wal", "cleaned-wal", "root-wal", "lease-wal", "validator-wal"] else omitted_manifest + ".v1"),
                        "RTOS_TEST_OMIT_MANIFEST_SYNC_MARKER": str(output / "manifest-sync-omitted.log"),
                    })
                    if omitted_manifest in ["committed-wal", "cleaned-wal", "root-wal", "lease-wal", "validator-wal"]:
                        environment["RTOS_TEST_ROOT_WAL_ARM"] = str(output / "root-wal.arm")
                    result["sync_mutation"] = {"kind": f"omit {omitted_manifest} file sync only",
                                               "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                                               "library_sha256": hashlib.sha256(library.read_bytes()).hexdigest()}
                with (output / "node-test.log").open("wb") as log:
                    case = "actual_node_sparse_packages_interrupted_metadata" if node.no_cache_loss else "actual_node_sparse_packages_cache_loss"
                    if node.cut in ["ready", "selection"]:
                        case = f"actual_node_unfinished_{node.cut}_cache_loss"
                    if node.cut == "stages":
                        case = "actual_node_staged_packages_cache_loss"
                    if node.cut == "committed":
                        case = "actual_node_committed_cache_loss"
                    if node.cut == "cleaned":
                        case = "actual_node_cleaned_cache_loss"
                    if node.cut == "root-last":
                        case = "actual_node_root_last_cache_loss"
                    if node.cut == "lease":
                        case = "actual_node_lease_release_cache_loss"
                    if node.cut == "lease-acquire":
                        case = "actual_node_lease_acquire_cache_loss"
                    if node.cut == "lease-custody":
                        case = "actual_node_lease_custody_cache_loss"
                    if node.cut == "validator-floor":
                        case = "actual_node_validator_floor_cache_loss"
                    result["node_cut"] = node.cut
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
                transcript = (output / "node-test.log").read_text()
                expected_failure = bool(omitted_manifest) and omitted_manifest not in ["ready-wal", "committed-wal", "cleaned-wal", "root-wal"] and not node.no_cache_loss
                result["node_failure_expected"] = expected_failure
                if omitted_manifest:
                    marker = (output / "manifest-sync-omitted.log").read_text().splitlines()
                    prefix = tuple(name + " omitted: " + str(fixture_dir) + "/" for name in (["fsync", "fdatasync"] if omitted_manifest.endswith("-wal") else ["fsync"]))
                    suffix = ".log" if omitted_manifest.endswith("-wal") else ".pack" if omitted_manifest == "stage" else f"/{omitted_manifest}.v1"
                    if len(marker) != 1 or not marker[0].startswith(prefix) or not marker[0].endswith(suffix):
                        raise RuntimeError("Sync mutation did not hit exactly one scoped file")
                    result["sync_mutation"]["hits"] = marker
                required_evidence = ["Actual node recovery interrupted at " + (
                    f"producer-{node.cut}-cache-loss" if node.cut in ["ready", "selection"] else "forward-before-prepare-cache-loss" if node.cut == "stages" else "forward-committed-cache-loss" if node.cut == "committed" else "forward-cleaned-cache-loss" if node.cut == "cleaned" else "root-last-cache-loss" if node.cut == "root-last" else "forward-after-row-sync")]
                if node.cut in ["lease", "lease-acquire", "lease-custody"]:
                    operation = "custody" if node.cut == "lease-custody" else "acquire" if node.cut == "lease-acquire" else "release"
                    required_evidence = [f"Acknowledged lease {operation} writer killed without native close; cache-loss=" + ("false" if node.no_cache_loss else "true")]
                if node.cut == "validator-floor":
                    required_evidence = ["Acknowledged validator floor writer killed with physical pin and native owner alive; cache-loss=" + ("false" if node.no_cache_loss else "true")]
                if expected_failure and omitted_manifest == "validator-wal":
                    if executed.returncode != 101:
                        raise RuntimeError("Missing validator-floor sync omission failure")
                    required_evidence.extend(["0 passed; 1 failed",
                        "Actual node preserved protected history and progress after validator floor cut",
                        "Acknowledged validator cleanup floor lost after actual node restart"])
                    reports = list((output / "node").rglob("cache-loss.json"))
                    cold = list((output / "node").rglob("validator-floor-guarded-startup.json"))
                    if len(reports) != 1 or len(cold) != 1 or json.loads(cold[0].read_text())["actual"] is not None:
                        raise RuntimeError("Validator floor did not revert to absent")
                    report = json.loads(reports[0].read_text())
                    target = [f for f in report["validator_wal_files"] if marker[0].endswith("/" + f["path"])]
                    if len(target) != 1 or target[0]["sha256_before"] == target[0]["sha256_after"]:
                        raise RuntimeError("Validator floor omission did not lose target WAL bytes")
                    if report["ready_files"] or report["selection_files"]:
                        raise RuntimeError("Validator floor cut overlaps archive recovery")
                    result["changed_validator_wal"] = target[0]
                    result["sensitivity_detected"] = True
                elif expected_failure and omitted_manifest == "lease-wal":
                    if executed.returncode != 101:
                        raise RuntimeError("Lost lease mutation did not fail actual node recovery")
                    required_evidence.append("0 passed; 1 failed")
                    if node.cut == "lease-acquire":
                        required_evidence.extend(["Actual node started despite failed archive truncation", "Node services started."])
                    elif node.cut == "lease-custody":
                        required_evidence.extend(["Acknowledged custody record lost after actual node restart",
                            "Actual node lease protection preserved full history and progress after custody cut"])
                        cold_files = list((output / "node").rglob("lease-custody-cold.json"))
                        ack_files = list((output / "node").rglob("lease-mutation-ack.json"))
                        refused = list((output / "node").rglob("truncation-refused.log"))
                        if len(cold_files) != 1 or len(ack_files) != 1 or len(refused) != 1:
                            raise RuntimeError("Missing custody downgrade evidence")
                        cold = json.loads(cold_files[0].read_text())
                        acknowledged = json.loads(ack_files[0].read_text())["record"]
                        if cold["state"] != "Protecting" or acknowledged["state"] != "DurableCustody":
                            raise RuntimeError("Unexpected custody state transition")
                        cold["state"] = "DurableCustody"
                        if cold != acknowledged or "Archive truncation conflicts with repair custody" not in refused[0].read_text():
                            raise RuntimeError("Custody downgrade changed identity or lost startup protection")
                        result["custody_downgrade_detected"] = True
                    else:
                        required_evidence.extend(["Truncation retry", "Archive truncation conflicts with repair custody"])
                    reports = list((output / "node").rglob("cache-loss.json"))
                    if len(reports) != 1:
                        raise RuntimeError("Missing lease WAL cache-loss report")
                    report = json.loads(reports[0].read_text())
                    target = [f for f in report["wal_files"] if marker[0].endswith("/" + f["path"])]
                    if len(target) != 1 or target[0]["sha256_before"] == target[0]["sha256_after"]:
                        raise RuntimeError("Lease mutation sync omission did not lose target WAL bytes")
                    if report["ready_files"] or report["selection_files"]:
                        raise RuntimeError("Lease cut unexpectedly overlaps archive recovery")
                    result["changed_lease_wal"] = target[0]
                    result["sensitivity_detected"] = True
                elif expected_failure and omitted_manifest == "stage":
                    if executed.returncode != 101:
                        raise RuntimeError("Stage sync omission did not fail the actual restart")
                    required_evidence.extend(["0 passed; 1 failed", "Truncation retry",
                                              "Forward stage does not match final package"])
                    reports = list((output / "node").rglob("stages-cache-loss.json"))
                    manifests = list((output / "node").rglob("cache-loss.json"))
                    if len(reports) != 1 or len(manifests) != 1:
                        raise RuntimeError("Missing unique stage/manifest cache-loss reports")
                    stages = json.loads(reports[0].read_text())["stage_files"]
                    lost = [f for f in stages if marker[0].endswith("/" + f["path"])]
                    if len(lost) != 1 or lost[0]["bytes_before"] <= 28 or lost[0]["bytes_after"] != 0:
                        raise RuntimeError("Exact stage sync target did not lose its contents")
                    report = json.loads(manifests[0].read_text())
                    if len(report["ready_files"]) != 1 or len(report["selection_files"]) != 1 or len(stages) < 2:
                        raise RuntimeError("Missing non-target recovery files")
                    preserved = [f for f in stages if f != lost[0]] + report["ready_files"] + report["selection_files"]
                    if any(f["bytes_before"] != f["bytes_after"] or f["sha256_before"] != f["sha256_after"] for f in preserved):
                        raise RuntimeError("Non-target recovery file changed during cache loss")
                    result["lost_stage"] = lost[0]
                    result["preserved_files"] = preserved
                    result["sensitivity_detected"] = True
                elif expected_failure:
                    if executed.returncode != 101:
                        raise RuntimeError("Sync omission did not produce the expected Rust test failure")
                    required_evidence.extend(["0 passed; 1 failed", "Truncation retry",
                                              "Recovery sidecar type or length mismatch"])
                    reports = list((output / "node").rglob("cache-loss.json"))
                    if len(reports) != 1:
                        raise RuntimeError("Missing unique cache-loss report")
                    report = json.loads(reports[0].read_text())
                    lost = report[omitted_manifest + "_files"]
                    if len(lost) != 1 or lost[0]["bytes_before"] <= 28 or lost[0]["bytes_after"] != 0:
                        raise RuntimeError("Sync omission did not lose the selected manifest contents")
                    if not marker[0].endswith("/" + lost[0]["path"]):
                        raise RuntimeError("Lost manifest differs from the exact sync omission target")
                    other = "ready" if omitted_manifest == "selection" else "selection"
                    preserved = report[other + "_files"]
                    if len(preserved) != 1 or preserved[0]["bytes_before"] != preserved[0]["bytes_after"] or preserved[0]["sha256_before"] != preserved[0]["sha256_after"]:
                        raise RuntimeError("Non-target manifest changed during cache loss")
                    result["lost_" + omitted_manifest] = lost[0]
                    result["preserved_" + other] = preserved[0]
                    result["sensitivity_detected"] = True
                else:
                    if executed.returncode != 0:
                        raise RuntimeError(f"Actual node cache-loss test failed: {executed.returncode}")
                    required_evidence.extend(["1 passed; 0 failed", "Actual node retried real truncation"])
                    if node.cut == "validator-floor":
                        required_evidence.append("Validator cleanup floor bytes and truncation boundary preserved after two-boots")
                    if node.cut == "lease-custody":
                        required_evidence.append("Acknowledged DurableCustody record survived actual node restart")
                if omitted_manifest in ["ready-wal", "committed-wal", "cleaned-wal", "root-wal"] and not node.no_cache_loss:
                    required_evidence.append("Lost Ready WAL publication recovered through Building abort" if omitted_manifest == "ready-wal" else "Lost Cleaned WAL publication reopened Committed" if omitted_manifest == "cleaned-wal" else "Lost root deletion reopened Cleaned" if omitted_manifest == "root-wal" else "Lost Committed WAL publication replayed Ready")
                    reports = list((output / "node").rglob("cache-loss.json"))
                    if len(reports) != 1:
                        raise RuntimeError("Missing WAL cache-loss report")
                    report = json.loads(reports[0].read_text())
                    target = [f for f in report["wal_files"] if marker[0].endswith("/" + f["path"])]
                    if len(target) != 1 or target[0]["sha256_before"] == target[0]["sha256_after"]:
                        raise RuntimeError("Ready WAL sync omission did not lose target WAL bytes")
                    preserved = report["ready_files"] + report["selection_files"]
                    if len(preserved) != (0 if omitted_manifest == "root-wal" else 2) or any(f["bytes_before"] != f["bytes_after"] or f["sha256_before"] != f["sha256_after"] for f in preserved):
                        raise RuntimeError("WAL omission changed a durable manifest")
                    result["changed_wal"] = target[0]
                    result["preserved_manifests"] = preserved
                    result["building_fallback_verified" if omitted_manifest == "ready-wal" else "committed_reopen_verified" if omitted_manifest == "cleaned-wal" else "cleaned_reopen_verified" if omitted_manifest == "root-wal" else "ready_replay_verified"] = True
                if node.cut in ["ready", "selection"]:
                    required_evidence.append(f"Unfinished {node.cut.title()} cache-loss=" + ("false" if node.no_cache_loss else "true"))
                if node.cut in ["committed", "cleaned"]:
                    required_evidence.append(node.cut.title() + " cut cache-loss=" + ("false" if node.no_cache_loss else "true"))
                    if omitted_manifest in ["committed-wal", "cleaned-wal", "root-wal"]:
                        arms = list((output / "node").rglob(f"cut-forward-{node.cut}-cache-loss.log"))
                        if len(arms) != 1 or "Root WAL omission armed at verified production statement" not in arms[0].read_text():
                            raise RuntimeError("Committed WAL omission lacks verified production arm")
                if omitted_manifest == "cleaned-wal" and not node.no_cache_loss:
                    states = list((output / "node").rglob("cut-forward-verify-committed.log"))
                    if len(states) != 1 or "Persisted Committed root verified before replay" not in states[0].read_text():
                        raise RuntimeError("Missing actual persisted Committed state verification")
                if node.cut == "root-last":
                    required_evidence.append("Root-last cut cache-loss=" + ("false" if node.no_cache_loss else "true"))
                    if omitted_manifest == "root-wal":
                        arms = list((output / "node").rglob("cut-root-last-cache-loss.log"))
                        if len(arms) != 1 or "Root WAL omission armed at verified production statement" not in arms[0].read_text():
                            raise RuntimeError("Root deletion omission lacks verified production arm")
                        if not node.no_cache_loss:
                            states = list((output / "node").rglob("cut-root-verify-cleaned.log"))
                            if len(states) != 1 or "Persisted Cleaned root verified before cleanup" not in states[0].read_text():
                                raise RuntimeError("Missing actual persisted Cleaned state verification")
                if node.cut == "stages":
                    required_evidence.append("Published Ready staging cache-loss=" + ("false" if node.no_cache_loss else "true"))
                if node.cut == "selection":
                    required_evidence.append("Preparing abort removed Selection before Cleaned publication")
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
    mutation = parser.add_mutually_exclusive_group()
    mutation.add_argument("--omit-ready-sync", action="store_true", help="scoped Ready sync omission sensitivity control")
    mutation.add_argument("--omit-selection-sync", action="store_true", help="scoped Selection sync omission sensitivity control")
    mutation.add_argument("--omit-stage-sync", action="store_true", help="scoped replacement stage sync omission control")
    mutation.add_argument("--omit-ready-wal-sync", action="store_true", help="omit one main WAL sync after durable Ready")
    mutation.add_argument("--omit-committed-wal-sync", action="store_true", help="omit main WAL sync at verified Committed publication")
    mutation.add_argument("--omit-cleaned-wal-sync", action="store_true", help="omit main WAL sync at verified Cleaned publication")
    mutation.add_argument("--omit-root-wal-sync", action="store_true", help="omit main WAL sync at verified final root deletion")
    mutation.add_argument("--omit-lease-wal-sync", action="store_true", help="omit one scoped repair lease mutation WAL sync")
    mutation.add_argument("--omit-validator-wal-sync", action="store_true", help="omit one scoped validator floor WAL sync")
    parser.add_argument("--cut", choices=["rows", "ready", "selection", "stages", "committed", "cleaned", "root-last", "lease", "lease-acquire", "lease-custody", "validator-floor"], default="rows")
    parser.add_argument("--no-cache-loss", action="store_true", help="run the same node cut without cache loss as a control")
    parser.add_argument("--node-test-binary", type=Path)
    parser.add_argument("--node-binary", type=Path)
    parser.add_argument("--fixture-signer", type=Path)
    args = parser.parse_args()
    node_args = [args.node_test_binary, args.node_binary, args.fixture_signer]
    if any(node_args) and not all(node_args):
        parser.error("all three node binary/signer arguments are required together")
    if (args.omit_ready_sync or args.omit_selection_sync) and (not all(node_args) or args.cut != "rows"):
        parser.error("Manifest sync sensitivity requires all node arguments and --cut rows")
    if (args.omit_stage_sync or args.omit_ready_wal_sync) and (not all(node_args) or args.cut != "stages"):
        parser.error("Stage sync sensitivity requires all node arguments and --cut stages")
    if args.omit_committed_wal_sync and (not all(node_args) or args.cut != "committed"):
        parser.error("Committed WAL control requires all node arguments and --cut committed")
    if args.omit_cleaned_wal_sync and (not all(node_args) or args.cut != "cleaned"):
        parser.error("Cleaned WAL control requires all node arguments and --cut cleaned")
    if args.omit_root_wal_sync and (not all(node_args) or args.cut != "root-last"):
        parser.error("Root WAL control requires all node arguments and --cut root-last")
    if args.omit_lease_wal_sync and (not all(node_args) or args.cut not in ["lease", "lease-acquire", "lease-custody"]):
        parser.error("Lease WAL control requires all node arguments and a lease cut")
    if args.omit_validator_wal_sync and (not all(node_args) or args.cut != "validator-floor"):
        parser.error("Validator WAL control requires all node arguments and --cut validator-floor")
    run(args.lazyfs.resolve(strict=True), args.output.resolve(), args if all(node_args) else None)
