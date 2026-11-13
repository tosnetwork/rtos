# Shared conformance target

The target executes contexts from the TOS conformance suite and emits the effects of
RTOS. It never reads fixture expectations. The current target provides `vm`; other
harnesses return `harness_error` and must not be counted as passing.

The suite source and frozen vectors are pinned by `REFERENCE` to a TOS commit.
Each fixture retains its own reference-build provenance. Running frozen vectors
is distinct from regenerating them against a newer C++ baseline.

Build with the repository's pinned Rust toolchain:

```sh
cargo build -p rtos_vm --example conformance --locked
```

Given a clean TOS checkout at `REFERENCE`, run its runner directly:

```sh
python3 "$TOS_REFERENCE/test/conformance/runner/conformance.py" run \
  --target "$PWD/target/debug/examples/conformance" \
  "$TOS_REFERENCE/test/conformance/vectors/vm"
```

`conformance --info` advertises the supported harnesses. `conformance vm` accepts
one context JSON object per input line and writes one effects JSON object per
output line. A refused context emits `harness_error`. Stdout is reserved for this
protocol. Contexts are limited to 16 MiB; initial values are limited to depth 32
and 255 tuple or stack entries. Integer text is limited to 255 characters and
uses decimal digits with an optional leading minus, as in the reference parser. Final stack rendering has the reference's depth
512 and shared budget of 2^20 visited values.

The VM context initializes c3 according to the reference flags: without bit 0 it
is a continuation that exits with code 11; with bit 0 it executes the original
code, and bit 1 additionally pushes zero. The default c7 is an empty tuple.
These are harness inputs, not changes to the node's execution context.

Only a line reporting zero mismatches, refusals and skips proves agreement for
the vectors executed. Do not use a VM-only result to claim transaction, block,
replay, network or release qualification. Keep mismatching fixtures unchanged
and fix the target; expectations come from the recorded C++ reference.

The older inline PQ test families can be refreshed from these same frozen C++
effects, after checking the source context, with:

```sh
python3 ci/conformance/refresh_pq_effects.py "$TOS_REFERENCE"
```

This checks the exact clean reference commit, operand stack, version and gas
context before writing any family. It preserves all cases, including signature
override cases, and records the source fixture digests in each legacy data file.
It does not execute RTOS or generate expectations from RTOS output.
