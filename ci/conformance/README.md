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

## Transaction target

Build `cargo build -p rtos_executor --example txn_conformance --locked`, then run
`conformance.py run --target target/debug/examples/txn_conformance "$TOS_REFERENCE/test/conformance/vectors/txn"`.
This separate target advertises `txn` and executes each input with fresh executor
state. It accepts the configuration dictionary, complete ShardAccount, inbound
message or tick/tock, explicit time/LT/seed, libraries and serialized previous-block
tuple. Accepted effects include the transaction, Account and ShardAccount hashes;
external rejection includes its VM exit code; execution errors return `error`.

Serialized previous-block values are bounded to depth 512 and 2^20 visited values.
Continuation values in that optional input are currently refused explicitly.
A refused input remains a refusal in the runner and does not grant qualification.
The first baseline and any remaining differences are recorded in memo; adding the
entry point alone does not prove transaction, block or replay agreement.

The additional VM regression corpus in `vm/tests/data/conformance` records five
shared-signature gas boundaries filled by a clean C++ reference at `REFERENCE`.
Its contexts derive from `rtos-pq-mldsa44/eleven-paid-calls`: the eleventh key is
an empty cell and the gas limits straddle the first paid call. The fixture and
blob files are standard shared-runner inputs; they are also executed by the
VM example's native test. Run them alongside the main frozen VM corpus. Refill
only with the C++ `conformance.py regenerate --reference` command, preserving
its recorded provenance; never fill expectations from the Rust target.

The transaction corpus in `executor/src/tests/data/conformance/txn/fixtures` also
includes five `precompiled-external-admission` contexts checked against the frozen
C++ reference. Three preserve original gas-credit field-width errors after the
contract accepts; two exercise acceptance and rejection with a 2^62+1 fallback
budget. They cover the upstream `495113c8` external admission and credit-only
initialization fix. They do not qualify fallback budgets above signed i64 range;
those require additional reference investigation.

`config43-queue-wire` adds seven C++ transaction controls for the complete CP43
v3 queue-limit tail: default, zero, maximum and custom values, plus truncated,
trailing-bit and trailing-reference records. Invalid chain configuration returns
transaction `error`; malformed protocol inputs still refuse. The old 14
`size-limits.tsv` hashes remain unchanged: their v3 rows describe truncated
prefixes and are now explicitly checked as invalid. Queue limits round-trip in
BOC and JSON; collator/validator queue enforcement requires separate integration
and is not qualified by these transaction tests.

`compute-finalization` contains eight pinned C++ controls for null-code state
usage and the version14 activation boundary, plus precompiled OOG classification
and an ordinary-OOG control. `storage-option-finalization` contains19 C++ controls
for zero-valued account options, freezing/successors and the version13 distinction
between physical uninit storage and logical frozen transaction status. StateInit
message hashing keeps its original encoding; account options normalize when the
account is committed or frozen. These controls do not qualify the remaining
currency-width and other transaction differences.
