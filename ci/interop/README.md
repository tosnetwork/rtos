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
disabled. It records whether Rust applies MC4 from that network. Its result does
not prove Rust signed, validated a candidate, produced a block, or has the same
state root. Those are subsequent acceptance requirements; a bootstrap result
must not close the mixed-validator gate.

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
