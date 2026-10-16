# Local C++ / Rust interop runners

The snapshot pins the executable's reported commit, copies the C++ programs,
checks their SHA-256 values, and exports the matching test sources. Supply a
clean C++ checkout at the requested revision and its existing build directory:

```sh
python3 ci/interop/cpp_snapshot.py \
  --cpp-source "$CPP_SOURCE" --cpp-build "$CPP_BUILD" \
  --revision "$CPP_REVISION" --output "$CPP_SNAPSHOT"
```

The snapshot's detached Git reference uses the input checkout's object store.
Keep that checkout available while running the existing C++ control runner.
Use the C++ test environment's Python (3.14 or later) with its dependencies:

```sh
"$CPP_PYTHON" ci/interop/cpp_control.py \
  --snapshot "$CPP_SNAPSHOT" --output "$CONTROL_OUTPUT" --base-port 55300
"$CPP_PYTHON" ci/interop/mixed_bootstrap.py \
  --snapshot "$CPP_SNAPSHOT" --rust-node "$RUST_NODE" \
  --output "$MIXED_OUTPUT" --base-port 55400
```

Each output directory must be new. The runners generate independent test
Genesis states and public deterministic PQ test identities through the existing
C++ harness. They do not load an existing validator identity or reset an
existing node. The bootstrap stage runs three C++ validators, reserves the
fourth identity without starting its C++ process, and starts Rust with signing
disabled. It records whether Rust logs processing MC4 from that network. Its result does
not prove Rust signed, validated a candidate, produced a block, or has the same
state root. Those are subsequent acceptance requirements; a bootstrap result
must not close the mixed-validator gate.

To exercise active signing, build both programs with the explicit isolated
signing feature and use the frozen `8f083dc` C++ snapshot:

```sh
cargo +1.91.1 build -p rtos --bin rtos --bin interop_validator_prepare \
  --features isolated-consensus-signing --locked
"$CPP_PYTHON" ci/interop/mixed_bootstrap.py \
  --snapshot "$CPP_SNAPSHOT" --rust-node "$RUST_NODE" \
  --validator-preparer "$VALIDATOR_PREPARER" \
  --output "$ACTIVE_OUTPUT" --base-port 55600 --timeout 180
```

This mode starts two C++ validators and Rust in a four-member committee. The
remaining C++ identities never start, so C++ alone cannot form a quorum. Fresh
public deterministic transport/PQ identities are bound to the generated
Genesis; offline preparation creates the matching MC and shard session journals
before Rust starts. Existing configurations/databases are refused. Independent
test shards use separate explicit journal owner directories. This isolated
provisioning is not an operator custody or committee-rotation implementation.
The native Param29 carrier version 5 is admitted with T0 wire format; it remains
distinct from the Param30 Simplex protocol version 2.

An active result requires both C++ nodes to agree at MC4 and Rust to log
processing at least MC4. This log is not an independent applied-state check. This measures required Rust participation in chain progress. It does
not close the full mixed-validator gate or prove every transaction/state profile
and every Rust leadership case.

The original bounded MC4 result demonstrated required Rust voting participation.
The preparer now includes enabled workchains whose first shard descriptor is
not yet in Genesis, and explicitly provisions current and immediate-successor
sessions of the initial set. It refuses a separate next validator set; this is
not live key rotation. The node advertises global-version support through 16,
matching the active fixture. The C++ baseline advertises a higher ceiling (19);
full later-version node qualification remains outstanding.

To require a Rust-created block with matching applied-state checkpoints:

```sh
"$CPP_PYTHON" ci/interop/mixed_bootstrap.py \
  --snapshot "$CPP_SNAPSHOT" --rust-node "$RUST_NODE" \
  --validator-preparer "$VALIDATOR_PREPARER" --block-checker "$BLOCK_CHECKER" \
  --require-leadership --min-height 4 --cpp-count 3 \
  --output "$LEADERSHIP_OUTPUT" --base-port 55600 --timeout 180
```

All three native RPCs must report the same produced masterchain block and
applied state. The independent BOC checker authenticates file/cell/header/state
update hashes and reads `BlockExtra.created_by` from the body. Acceptance also
requires the creator to equal Rust's authenticated validator ID and the
corresponding local collation success log. With `--cpp-count 3`, C++ alone has
quorum, so height progress is insufficient; leadership verification is mandatory.
With the default two C++ nodes, Rust is also necessary for quorum. Complete
transaction profiles, both mixed directions, workchain leadership and rotation
remain separate acceptance requirements. Preserve shutdown receipts: a forced
process stop is not an orderly-shutdown or recovery qualification.

`overlay-node-vector.cpp` uses the production C++ TL serializer to generate
the two wire fixtures in `adnl/src/overlay/testdata/`. The adjacent JSON pins
the reference revision. Run it against that revision's generated TL headers,
`tl-utils`, `tl_api`, and `tdutils` libraries when updating the fixtures; retain
the exact compiler command and library hashes with the run evidence.

## Compare existing local nodes

`local_compare.py` uses a public global network configuration and at least two
existing C++ observer RPC endpoints. It creates a fresh Rust directory and
enables its RPC server on an allocated loopback port. It starts and stops only
that Rust process. Node initialization remains the operator's responsibility.

Build the node and the independent BOC checker first:

```sh
cargo +1.91.1 build -p rtos --bin rtos --locked
cargo +1.91.1 build -p rtos_api --example interop_block_check --locked
python3 ci/interop/local_compare.py \
  --global-config /data/tos-global.json \
  --cpp-rpc http://127.0.0.1:8015/jsonRPC \
  --cpp-rpc http://127.0.0.1:8016/jsonRPC \
  --rust-node "$RUST_NODE" --block-checker "$BLOCK_CHECKER" \
  --output "$COMPARISON_OUTPUT"
```

Use `--prepare-only` to validate the reference chain and write configuration
without starting Rust. Every invocation needs a new output directory. A change
to the source global configuration invalidates a running comparison.

The actual run captures matching C++ block/state observations, requires Rust to
advance at least two blocks beyond the initial checkpoint, and finds a common
height. It obtains Rust's applied state root and full block through RPC. The
independent checker verifies the full BOC file hash, cell hash, block header,
canonical block ID labels and the state update's new root against both clients'
reported applied states. The C++ observers must still agree on the matched block
ID after Rust stops. Logs and `status.json` preserve terminal success or failure;
`sample.json` retains the exact public sample locally.

This establishes a block/state checkpoint comparison. It does not qualify
active Rust voting, candidate production, quorum behavior, transactions across
all profiles or the complete mixed-validator gate. The public synchronization
configuration contains fresh transport identities and no signing profile.

## Frozen four-member matrix

`mixed_matrix.py` starts all four validators and requires each one's own
masterchain block to be accepted with matching native applied-state checkpoints
at every endpoint. Rust creators additionally require the corresponding local
collation success log. Every owned Rust process must exit normally. The node,
preparer, checker, C++ snapshot and Genesis profile hashes remain pinned during
the run. Supply the exact Rust executable revision, independently of the runner
revision.

```sh
"$CPP_PYTHON" ci/interop/mixed_matrix.py \
  --snapshot "$CPP_SNAPSHOT" --rust-node "$RUST_NODE" \
  --validator-preparer "$VALIDATOR_PREPARER" --block-checker "$BLOCK_CHECKER" \
  --rust-revision "$RUST_REVISION" --cpp-count 1 \
  --output "$MATRIX_OUTPUT" --base-port 55700
```

Use `--cpp-count 1`, `2`, or `3` for the reverse, symmetric and forward
four-member topologies. Run them sequentially: these deliberately public test
identities must not be active in concurrent duplicate networks. The checked-in
`testnet-v16.json` fixes time, public wallet-seed derivation, initial-set lifetime,
version, equal membership, test economics, Simplex parameters and complete MC/WC
Genesis identities. The transport, validator-ID and PQ seeds use the fixed public
`n6-validator-{transport,id,seed}-{index}` SHA-256 derivations. Each deployment
regenerates Genesis with the frozen C++ programs and rejects a different full
identity before starting validators. `--prepare-genesis-only` performs generation
without running validator processes; it is not consensus acceptance.

The long initial-set lifetime is solely for reproducible isolated fixtures.
This profile does not qualify deployment fee schedules, version 17–19,
workchain leadership, elections or validator-set rotation. Do not use its public
identities or wallet for a shared deployment.
