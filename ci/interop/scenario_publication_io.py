"""Bind live acceptance EIO to its original database and recovery budget."""

import base64
import json
import re
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory

from mixed_matrix import identity
from publication_io_fixture import selector_for
from publication_io_live_fixture import selected_source, verify_body_artifact
from scenario_matrix import require_fields
from scenario_packet import file_hash
from scenario_restart import check_restart_partition, restart_arguments


def publication_io_arguments(library, socket_library):
    return restart_arguments("partition-restart-member2", socket_library) + [
        "--publication-io-library",
        str(library),
    ]


def require_original_cleanup(original):
    if (
        original.exists()
        or (original.parent / "outputs-v1" / (original.stem + ".outputs")).exists()
    ):
        raise ValueError("Publication IO retains original intent or outputs")


def require_original_intent(original, copy, intent, selected, namespace, session):
    cert = json.loads(copy.read_text())
    if (
        original.parent != namespace / "finality-intents"
        or intent["path"] != selected["path"]
        or intent["sha256"] != selected["sha256"]
        or cert["slot"] != selected["slot"]
        or cert["candidate_hash"] != selected["candidate_hash"]
        or original.name != f"{cert['slot']}-{cert['candidate_hash']}.json"
        or cert["session_id"] != session
        or not cert["certificate"]
        or file_hash(copy) != intent["sha256"]
        or copy.stat().st_size != intent["bytes"]
    ):
        raise ValueError("Publication IO original intent identity/cleanup differs")
    require_original_cleanup(original)


def publication_io_artifacts(args, source):
    library = getattr(args, "publication_io_library", None)
    record = getattr(args, "publication_io_build_record", None)
    if library is None or record is None:
        raise ValueError("Publication IO requires a native library and build record")
    build = json.loads(record.read_text())
    native = source.parents[1] / "rtos/src/tests/publication_io_fault.c"
    if (
        Path(build["source"]).resolve() != native.resolve()
        or Path(build["library"]).resolve() != library.resolve()
    ):
        raise ValueError("Publication IO build record names different inputs")
    for path, meta in (
        (native, build["source_meta"]),
        (library, build["library_meta"]),
    ):
        if path.stat().st_size != meta["bytes"] or file_hash(path) != meta["sha256"]:
            raise ValueError("Publication IO native input differs from build receipt")
    return [native, library, record]


def check_publication_io_result(result):
    source = result.get("node_io_source")
    wrapper = result.get("publication_io_restart")
    if not isinstance(source, dict) or not isinstance(wrapper, dict):
        raise TypeError("Missing live publication IO receipts")
    partition, recovery = result.get("partition_restart"), result.get("recovery")
    check_restart_partition("partition-restart-member2", partition, recovery)
    require_fields(
        source,
        {
            "mode": "live-acceptance-body-sync-eio",
            "member": 2,
            "phase": "recovered",
            "interruption_returncode": -9,
            "original_intents_preserved": True,
            "pending_preserved_after_interruption": True,
            "pending_preserved_before_restart": True,
            "original_intents_resolved": True,
            "original_block_native_state_match": True,
            "node_io_original_source_recovered": True,
            "source_canonical_delivery_before_interruption": False,
            "node_io_failure_before_callback": True,
            "manual_database_repair": False,
        },
    )
    require_fields(
        wrapper,
        {
            "mode": "node_body_sync_eio_and_partition_restart",
            "member": 2,
            "phase": "recovered",
            "source_phase": "recovered",
            "partition_phase": "recovered",
        },
    )
    start = source.get("budget_started_at_unix")
    if type(start) not in (int, float) or not start > 0:
        raise ValueError("Missing original publication IO budget")
    for receipt in (source, wrapper, partition):
        limit, elapsed = (
            receipt.get("recovery_limit_seconds"),
            receipt.get("elapsed_seconds"),
        )
        if (
            type(limit) not in (int, float)
            or limit != 180
            or type(elapsed) not in (int, float)
            or not 24 <= elapsed <= 180
            or receipt.get("budget_started_at_unix") != start
        ):
            raise ValueError("Publication IO changed its original shared budget")
    if (
        not partition["elapsed_seconds"]
        <= source["elapsed_seconds"]
        <= wrapper["elapsed_seconds"]
    ):
        raise ValueError("Publication IO completion order differs")
    for key in ("old_pid", "new_pid", "new_start_ticks", "survivor_checkpoint"):
        if source.get(key) != partition.get(key):
            raise ValueError("Publication IO source and restart identity differ")
    block, final = source["original_block"], source["final_checkpoint"]
    if (
        final != recovery["last_checkpoint"]
        or block["workchain"] != -1
        or not recovery["before"]["seqno"] < block["seqno"] < final["seqno"]
    ):
        raise ValueError("Publication IO original block or later checkpoint differs")
    if not source.get("original_intents"):
        raise ValueError("Publication IO lacks its original Final intent")
    failed = source["node_observed_error"]
    require_fields(
        failed,
        {
            "typed_durability_failure": True,
            "publication_owner_marked_fatal": True,
            "accepted_callback_returned": False,
            "retained_draft_verified": False,
        },
    )
    target = source["node_io_target"]
    selector = target["selector"]
    expected = {
        "record_id": None,
        "node_receipt": None,
        "delivery_id": selector["delivery_id"],
        "stage": "LiveAcceptance",
    }
    if (
        failed["publication"] != expected
        or target["publication"] != expected
        or target["pid"] != source["old_pid"]
        or failed["pid"] != source["old_pid"]
        or selector["pid"] != source["old_pid"]
        or selector["session_id"] != source["session"]
        or "Input/output error (os error 5)" not in failed["error"]
    ):
        raise ValueError("Publication IO does not bind the live failed acceptance")
    for field in (
        "source_ack_fault",
        "source_ack_partition_restart",
        "source_retention_cut",
    ):
        if result.get(field) is not None:
            raise ValueError("Live publication IO must not require propagation custody")


def check_publication_io_evidence(runtime, result, checker):
    check_publication_io_result(result)
    source = result["node_io_source"]
    directory, io = runtime / "publication-io-source", runtime / "publication-io"
    database = (runtime / "rust-2/node_db").resolve()

    def owned(value):
        path = Path(value)
        if path.is_symlink() or not path.resolve().is_relative_to(database):
            raise ValueError("Publication IO evidence escapes the original database")
        return path

    def read(path):
        return json.loads(path.read_text())

    if (
        read(directory / "receipt.json") != source
        or read(io / "receipt.json") != result["publication_io_restart"]
        or read(io / "target.json") != source["node_io_target"]
        or read(io / "failed.json") != source["node_observed_error"]
    ):
        raise ValueError("Publication IO saved receipts differ")
    target, failed = source["node_io_target"], source["node_observed_error"]
    selector = read(io / "selector.json")
    if (
        selector != target["selector"]
        or file_hash(io / "selector.json") != target["selector_sha256"]
        or file_hash(io / "selector.json") != failed["selector_sha256"]
        or file_hash(io / "target.json") != failed["target_sha256"]
        or file_hash(io / "native-error.marker") != failed["native_marker_sha256"]
    ):
        raise ValueError("Publication IO raw native evidence hash differs")
    path = owned(target["path"])
    pattern = (
        f"publication sync-eio pid={source['old_pid']} tid={target['tid']} "
        f"syscall=(fsync|fdatasync) errno=5: {re.escape(str(path))}\\n"
    )
    if not re.fullmatch(pattern, (io / "native-error.marker").read_text()):
        raise ValueError("Publication IO native worker/syscall marker differs")
    if (
        verify_body_artifact(path, selector, target["artifact"])
        != source["body_artifact"]
    ):
        raise ValueError("Publication IO original body artifact differs")
    namespace = owned(source["namespace"])
    observed = read(io / "live-source.json")
    record, source_id = selected_source(
        observed, pid=source["old_pid"], session=source["session"], namespace=namespace
    )
    if selector_for(record, source_id, source["old_pid"]) != selector:
        raise ValueError("Publication IO selector differs from original live request")
    selected = observed["finality_intent"]
    if len(source["original_intents"]) != 1:
        raise ValueError("Publication IO requires its one selected Final intent")
    for index, intent in enumerate(source["original_intents"]):
        original = owned(intent["path"])
        copy = directory / f"original-{index}.json"
        require_original_intent(
            original, copy, intent, selected, namespace, source["session"]
        )
    witness = read(directory / "recovered-original-block/witness.json")
    checked = read(directory / "recovered-original-block/checked.json")
    block = source["original_block"]
    block_text = (
        f"({block['workchain']}:{int(block['shard']) % (1 << 64):016x}, "
        f"{block['seqno']}, rh {base64.b64decode(block['root_hash'], validate=True).hex()}, "
        f"fh {base64.b64decode(block['file_hash'], validate=True).hex()})"
    )
    if (
        selector["block_id"] != block_text
        or base64.b64decode(block["file_hash"], validate=True).hex()
        != selector["block_sha256"]
        or witness["mode"] != "state-copies"
        or identity(witness["block"]["id"]) != identity(block)
        or checked["mode"] != "state-copies"
        or checked["finality_checked"] is not False
        or identity(checked["block"]) != identity(block)
        or checked["sources"] != ["cpp-reference", "restarted-rust"]
        or not checked["state_root_hash"]
    ):
        raise ValueError("Publication IO original block/state witness differs")
    if [state["name"] for state in witness["states"]] != [
        "cpp-reference",
        "restarted-rust",
    ]:
        raise ValueError("Publication IO state sources differ")
    for state in witness["states"]:
        if identity(state["id"]) != identity(block):
            raise ValueError("Publication IO state block identity differs")
    # Independently parse the actual block and both full states, not just saved flags.
    with TemporaryDirectory(prefix="publication-io-recheck-", dir=runtime) as temp:
        output = Path(temp) / "checked.json"
        subprocess.run(
            [
                str(checker),
                str(directory / "recovered-original-block/witness.json"),
                str(output),
            ],
            check=True,
            capture_output=True,
            timeout=30,
        )
        if read(output) != checked:
            raise ValueError("Publication IO native state recheck differs")
