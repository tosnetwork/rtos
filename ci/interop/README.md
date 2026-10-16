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
