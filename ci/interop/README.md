# Local C++ / Rust interop runners

## Fixed scenario inventory and serial execution

`scenario_catalog.json` records named scenarios, assertion scope and native
control dependencies. Inspect with `python3 ci/interop/scenarios.py list`, or
expand a selection with `python3 ci/interop/scenarios.py plan necessary-low-weight-mixed`.
The planner orders controls before mixed cases and refuses unknown selections,
cycles, missing drivers and additions/removals in the fixture-source inventory.
This inventory does not prove every parameter combination is represented.

The `rotation_v1` adapter runs rotation, exact-weight, necessary-low-weight
control/mixed pairs and member2/member5 original-database restart. The `matrix_v1` adapter adds all five four-member compositions, three/six-member
healthy and threshold control/mixed cases, and six-member low-weight-majority
cases. The observer-budget control/mixed pair pauses two active successor
members while both retired observers remain responsive; it requires a bounded
stall, same-PID recovery, and native/Rust successor role evidence. It shares the
original240-second rotation deadline and requires all four authenticated signers
in both epochs. This does not inject invalid old-group votes. Eight packet cases cover partition,
loss, reorder and duplicate for retained2/joining5; each uses12 seconds of declared
impairment and the existing180-second recovery budget after rotation. Supply
`--socket-mark-library` and `--socket-mark-build-record` for packet selections.
The build JSON names `source`, `library`, and `source_meta`/`library_meta` objects
with `bytes` and `sha256`; both paths and content must match the current fixture
source and supplied library before any suite directory is created. The suite
hashes that C source, library and record along with its other inputs.

Three partitioned restart cases use the same native library provenance:
`partition-restart-member2`, `partition-restart-member5`, and
`below-quorum-restart`. They keep isolation through SIGKILL and original-database
restart, with12-second holds before survivor sampling and after restart within
the existing180-second recovery budget. The new process must remain isolated,
increase native drop counters, and recover its own vote and MC/WC creators with
matching full states after restoration. Below-quorum restart gives member2
weight30 and each other active member10: survivors have30 of60, below quorum40.
It requires4 seconds settling and12 seconds of responsive stalled finality,
then recovery without changing the original committee. A historical certificate
is not counted as new finality during the stall. Generic rotation dependencies
remain controls for rotation, not native controls for each injected restart.

Source ACK cases `source-ack-sync-eio` and `source-ack-write-enospc` target one
owned authenticated current-masterchain source store. Supply
`--source-ack-fault-library` and `--source-ack-fault-build-record`; the build record
uses the same source/library path, size and SHA256 checks described above.
The native syscall refusal must leave the original source pending across SIGKILL,
then recover its ACK after reopening the original database without injection.
Acceptance binds the retained source bytes, recovered ACK/reference, native error
marker, process identities and fresh vote/MC/WC participation, within the original
180-second recovery budget. These are syscall interposition tests, not physical
media failures. Combined cases `source-ack-partition-sync-eio` and
`source-ack-partition-write-enospc` additionally require both packet-library
arguments. They bind the ACK refusal and partition to the same original
180-second budget, process and checkpoints, and retain both native counter
samples. The source IO fault is removed before restart while packet isolation
continues through the restarted-process hold.

The `source-ack-intent-before-write`, `source-ack-intent-after-partial-write`
and `source-ack-intent-after-fsync` selections add an explicit intent cut to the
ACK sync-EIO and partition recovery scenario. They retain the empty file, exact
half-written prefix or complete synced record respectively, and require normal
replay to complete the original certificate after restart. The original record,
completed proof, stopped-process marker and disarmed injection are checked
against the same session, slot and candidate. Supply both ACK and packet library
arguments. All stages share the original180-second recovery budget.

Source retention cases `source-retention-before-write`,
`source-retention-after-partial-write` and `source-retention-after-fsync` stop
one owned source write before its commit rename. Supply
`--source-retention-cut-library` and `--source-retention-cut-build-record` with
verified native source/library provenance. The adapter checks the interrupted
prefix, original source identity, recovered ACK/reference and fresh participation
after reopening the original database. Only the existing three replay hints may
be reconstructed for writes that had not completed; the source body and certificate
remain exact. Recovery retains the original180-second budget.

Packet completion additionally requires native netem counters demonstrating
traffic effects (drops for partition/loss, traffic with zero drops for reorder),
a fresh surviving quorum, restored own vote and both chain creators, unchanged
process identity, and retained queue removal in a fresh namespace. The saved
statistics must match the semantic receipt. Native driver checks still verify
actual block/state/certificate content. The generic rotation control dependency
is not a native run of every individual packet impairment. Other entries
remain `unintegrated`; selecting any of them refuses the entire suite before
creating runtime directories. An omitted selection means the entire catalog,
so `run` currently requires an explicit supported selection.

```sh
"$CPP_PYTHON" ci/interop/scenarios.py run necessary-low-weight-mixed \
  --cpp-python "$CPP_PYTHON" --snapshot "$CPP_SNAPSHOT" \
  --profile-template "$EXPLICIT_BASELINE_PROFILE" \
  --rust-node "$RUST_NODE" --rust-revision "$RUST_REVISION" \
  --validator-preparer "$VALIDATOR_PREPARER" --block-checker "$BLOCK_CHECKER" \
  --output "$FRESH_SUITE_OUTPUT"
```

The template supplies schema, C++ revision, global version, consensus options
and AUTH network tag. The adapter rebuilds scenario weights and membership,
uses a fresh timestamp, freezes complete MC/WC Genesis identities before startup,
and gives each invocation a fresh user/network namespace. Scenarios run serially;
control failure prevents the dependent mixed run. The original rotation240s,
activation120s and recovery180s budgets are fixed for rotation. Matrices retain
their original180-second total deadline, including threshold pause/observation/
recovery. Four-member matrices with a C++ source enable WC creator history;
three/six-member and all-Rust matrices retain their supported direct sampling.
No arbitrary extra flags,
existing runtime-directory reuse or automatic retries are accepted.

`suite.json` retains source/binary/profile hashes and completed scenario result
hashes; each invocation retains its command, exit and log. Existing native driver
checks still authenticate certificates, bodies and states. The adapter additionally
requires successful exit and scenario-specific semantic receipts. It does not
accept externally supplied result files. `selected_scenarios_passed` applies only
to that selection; missing adapters and the separate replay, seven-day follower,
fuzz, review and release gates remain open. `plan` is always `not_executed`.

## Baseline and bootstrap

The active C++ reference is `881240331ee48a291b96d73f8b8b93bae005ace0`. The default version-16 profile pins its AUTH network tag and regenerated masterchain/workchain Genesis identities. Historical `8f083dc` profiles remain available only for explicit matching-snapshot replay; their results do not qualify the new reference. Updating this pin does not establish Rust compatibility with the new C++ baseline. The candidate `5af405dcb1f523be0ff3b812e9f6945275c4945b` is available through explicit `--cpp-revision` selection for active bootstrap tests; the default active pin and frozen profile remain unchanged. Candidate selection is a test input, not a qualification verdict.

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
disabled. It requires Rust to serve a native masterchain state at or beyond the
minimum height whose block identity and state root match all C++ observers,
with every observer pinned to the generated Genesis. A bounded history of C++
checkpoints permits a lagging Rust observer. This does not prove Rust signed,
validated every candidate, or produced a block; bootstrap does not close the
mixed-validator gate.

To exercise active signing, build both programs with the explicit isolated
signing feature and use the default active C++ snapshot, or select the candidate
explicitly with `--cpp-revision 5af405dcb1f523be0ff3b812e9f6945275c4945b`:

```sh
cargo +1.100.0 build -p rtos --bin rtos --bin interop_validator_prepare \
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

An active result requires both C++ nodes and the Rust native served state to
match the same block identity and state root at or beyond the minimum height.
This measures required Rust participation in chain progress. It does
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
cargo +1.100.0 build -p rtos --bin rtos --locked
cargo +1.100.0 build -p rtos_api --example interop_block_check --locked
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
four-member topologies; `0` and `4` run all-Rust and all-C++ validator controls.
The bootstrap DHT and Genesis generator remain C++ harness services in both
controls. An all-C++ run uses the offline Rust test-identity preparer to inspect its
committee, plus the offline BOC checker. The resulting unused journal is never
started as a Rust validator process. It downloads native block bytes through
the pinned C++ LiteServer/client, since the baseline has no `getBlock` JSON-RPC.
Run them sequentially: these deliberately public test
identities must not be active in concurrent duplicate networks. The checked-in
`testnet-v16.json` fixes time, public wallet-seed derivation, initial-set lifetime,
version, equal membership, test economics, Simplex parameters and complete MC/WC
Genesis identities. The transport, validator-ID and PQ seeds use the fixed public
`n6-validator-{transport,id,seed}-{index}` SHA-256 derivations. Each deployment
uses ML-DSA-44 consensus keys (algorithm ID 1), Ed25519 transport keys, the T0
wire profile, Param29 carrier 5 and Param30 Simplex protocol 2. The immutable
Genesis body pins the full public key descriptors as well as their identities.
Each deployment
regenerates Genesis with the frozen C++ programs and rejects a different full
identity before starting validators. `--prepare-genesis-only` performs generation
without running validator processes; it is not consensus acceptance.

The long initial-set lifetime is solely for reproducible isolated fixtures.
This profile does not qualify deployment fee schedules, version 17–19,
elections or validator-set rotation. Do not use its public
identities or wallet for a shared deployment.

Add `--verify-certificates` to require independent finality checks at every
sampled checkpoint. Rust validators expose their stored PQ proof through native
RPC. The C++ baseline's JSON-RPC does not export PQ signature sets, so its
existing `saveblkproofchain` command retains raw LiteServer responses instead.
The checker authenticates the supplied governing Genesis body against the
frozen root/file identity, derives the expected committee/session from its
configuration and the signed block header, and verifies the native ML-DSA-44
FinalCert and strict quorum. This is currently limited to the Genesis key-block
epoch; later governing epochs are refused. It checks the target certificate,
not every intermediate proof-link in an exported chain.

Requests use `reference` and `comparison` for two named native endpoints; the
older `rust` comparison field remains accepted for archived samples. Even in
single-language controls, the independent checker compares distinct endpoints,
and the runner requires matching applied states at all four endpoints.

Add `--verify-workchain --verify-certificates` to extend the same deployment
to workchain production and full-state comparison. The checker extracts shard
top block identities from the authenticated masterchain block body. For each
new workchain-0 anchor the runner obtains the full block and downloads full
states from all four validators through the pinned C++ LiteServer client,
including when the server is Rust. The checker verifies the block file/cell
hashes and header, its exact inclusion in the checked masterchain shard table,
and all four state cell roots and headers against the workchain block's state
update. State BOC serialization may differ; equality is required for cell roots.
Every member must create an anchored workchain block as well as a masterchain
block, and Rust creators need the matching local collation log. Each sample
retains native client logs and state bodies. This proves state availability and
masterchain inclusion in the initial frozen epoch, with the containing
masterchain FinalCert checked. It does not independently export a workchain
FinalCert, prove a workchain database applied cursor, or qualify set rotation.

For four-member matrices with at least one C++ process, add
`--workchain-creator-history --verify-workchain --verify-certificates` to recover
creators missed between sampled shard tops. The existing rotation collector
fetches full parent bodies and full states from all four endpoints; the checker
validates the ancestry back to the certified masterchain anchor. Rust creators
still require their local successful collation record. Historical evidence keeps
its original sample path and anchor, and uses the original run deadline and
64-link ancestry bound. This does not infer acceptance from candidate logs or
extend the timeout. All-Rust matrices currently require direct tip coverage.

## Predeclared successor rotation

`rotation_fixture.py` deploys six public fixture identities with initial members
`[0,1,2,3]` and successor members `[0,2,4,5]`. The pinned C++ Fift generator
places the declared successor in Genesis Param36 before creating the production
configuration account. The account's ordinary tock activates that set, moves the
previous set to Param32 and emits the real key-block transition. This exercises
committee replacement; it does not exercise an elector or stake application.

Supply a schema-1 profile with global ID 4, version 16, explicit Genesis time,
wallet seed label, activation delay, successor lifetime, the two member lists,
the Simplex options, the pinned C++ revision and nullable complete MC/WC Genesis
IDs. First run `--prepare-genesis-only` and then pass its `frozen-profile.json`
to the live invocation while the declared activation remains in the future.
Each output directory must be new. The original `testnet-v16.json` stays fixed.

On the latest candidate baseline, the fixture prepares signing ledgers for C++
successors declared in the frozen Genesis before any validator starts. It uses
the pinned key tool and only accepts never-started directories containing the
fixture keyring and seed. Existing state or ledgers are refused; the ceremony
receipt is retained. This is fresh fixture provisioning, not recovery of unknown
signing history.

Without Rust arguments all six processes use C++. Adding `--rust-node` and
`--validator-preparer` uses Rust members 2, 3 and 5: each active committee then
contains two C++ and two Rust members. Both epochs require all four members'
MC and WC production, six matching native applied-MC checkpoints, four complete
WC states, authenticated MC anchors and Rust creators' local collation logs.
Retired members continue observing. Every owned Rust process must exit normally.

The checker authenticates successor FinalCerts through the actual governing key
block's own certificate and complete resulting state, recursively anchored to
Genesis. Historical governing witnesses do not claim that RPC endpoints observed
that past block as their head. Both block/state bodies are independently checked;
a supplied validator list or configuration hash grants no authority.

The offline preparer requires `--include-genesis-successor` for these fixtures.
It binds only the Genesis-declared successor committees, profile, local identity,
shard/catchain coordinates and database, with expiry 600 seconds after activation.
The isolated build can then create a fresh exact session after its authenticated
key-block height becomes known. Existing or partial namespaces are refused.
The default build does not enable this fixture signing policy. This is separate
from production custody, operator key rotation and full election qualification.

Add `--interrupt-rust-member 2` (retained member) or `5` (joining member) to
continue that same network through an actual process interruption after both
creator epochs pass. The runner sends SIGKILL only to that owned Rust process,
reaps it, and requires the five survivors to agree on a newer certified MC block
whose generation time is after the interruption. It then starts the same binary
with the same configuration and database directory, without running the preparer
or repairing data. Fresh RPC observations from all six processes must agree;
the restarted member must create both a new certified MC block and a newly
anchored WC block, with matching post-restart collation logs and full WC states
from all four active members. Recovery observations and both process identities
are retained in `recovery/recovery.json`; the restarted process has a separate
`node-restart.log`. `--recovery-timeout` bounds this combined recovery phase
(default 180 seconds). The final normal shutdown limit remains 20 seconds per
Rust process. A process interruption does not simulate a power failure.

Native C++ proof capture must retain its exact-target `finality.complete`
receipt as well as all numbered responses. A zero client exit code alone is
insufficient: the pinned client can log a capture rejection and still exit zero.
The rotation runner stops collecting the initial phase once its required MC/WC
creators are certified, and stops downloading redundant WC states once that
phase has all four WC creators. Every counted creator still needs the same
independent certificate, body and state checks. Both runner sources are retained
with hashes in each new rotation output directory.

Recovery also requires the restarted member's own validator ID in a native
FinalCert for a block generated after restart. The runner fetches that member's
stored target and governing-key certificates and verifies both with the same
independent checker. The receipt records the voting block alongside MC/WC
leadership; observing other validators' signatures alone cannot satisfy it.

Nonuniform rotation and exact weighted quorum use the same pinned six-node
rotation fixture. Optional `initial_weights` and `successor_weights` objects map
physical member indices (JSON strings) to positive integer weights; omitted
objects retain the original weight 17. Both the native PQ descriptor and its
Fift registration use the explicit weight. Every observed authenticated current
committee must match the frozen weights exactly.

The predeclared `weighted_quorum_pause: [0, 2]` case requires successor members
4 and 5 to hold exactly the pinned C++ quorum, ceil(2W/3). One useful profile is
initial {0:30, 1:10, 2:11, 3:9}, successor {0:9, 2:11, 4:10, 5:30}:
W=60 and quorum=40, rather than the strict-greater comparator 41. After all four
members in each epoch have authenticated MC signatures and MC/WC creator
receipts, the fixture pauses only its own members 0 and 2 in a fresh namespace.
A fresh MC FinalCert must contain exactly members 4 and 5, with weight 40 under
the unchanged full four-member committee. It then resumes both original PIDs
and requires new authenticated votes, accepted MC/WC creators and matching full
six-node MC / four-active-node anchored WC states within the original 180-second
fault budget. All processes are resumed in the failure path; the normal Rust
exit limit remains 20 seconds. This scenario cannot combine with packet faults
or process-restart flags. Run a native all-C++ control before its mixed variant.

This is a nonuniform four-active-member rotation on six physical nodes. It does
not qualify three- or six-active-member threshold networks, arbitrary Byzantine
faults, actual elections, or a weighted WC certificate independent of its
verified MC anchor. Old-group observers remain outside successor certificate
membership. No production signing or quorum rule is changed.

To make low-weight participation necessary, the optional initial probe uses
`initial_probe_pause: [1]` with initial weights {0:29, 1:11, 2:10, 3:10}.
After all initial MC/WC creators have been observed it pauses its own member 1.
The remaining active members 0/2/3 have weight 49; any two have at most 39,
below the unchanged quorum 40. A fresh independently authenticated certificate
must contain exactly all three. It then resumes member 1's original PID and
requires its fresh vote/MC/WC creators plus matching full states. The original
all-four-signer gate is filled only from verified probe certificates. Both this
probe and its restoration must finish before the predeclared initial epoch
ends and within the original rotation deadline. The normal successor exact
40/60 pause remains mandatory afterward. This changes the availability input
of the experiment, not quorum assembly or signature verification.

For full active committee size checks, `mixed_matrix.py` accepts a frozen
profile with `validator_count` equal to 3 or 6 and the same `shard_validators`.
The default remains four. `--cpp-count` must fit that declared committee.
Prepare with `--prepare-genesis-only`, then use its `frozen-profile.json` for
the namespace run; both complete MC/WC Genesis identities are mandatory before
starting a non-default committee. Each declared identity must be observed as
an accepted MC creator and, with `--verify-workchain`, an anchored WC creator;
`--verify-certificates` also checks all authenticated current committee weights
against the generated 17-unit weights. Three members therefore require 34/51,
and six require 68/102 under the pinned C++ inclusive quorum rule. A healthy
full-committee result alone does not close threshold fault-budget acceptance.

A full active 3/6 profile may predeclare `threshold_fault` with
`pause_at_quorum`, `pause_below_quorum`, `settle_seconds: 4` and
`observe_seconds: 12`. The fixed three-member case pauses member2, then member1;
the six-member case pauses members1/5, then member3. Member0 remains the native
C++ proof anchor. Only the fixture's own validators in its fresh user/network
namespace receive SIGSTOP/SIGCONT. A fresh exact-threshold FinalCert must name
exactly the surviving members under the unchanged full committee. After the
additional pause, the declared four-second settling period precedes a complete
twelve-second responsive RPC observation with no finalized MC identity/state
advance; this is bounded observational evidence. All paused original PIDs then
resume and must appear in fresh authenticated votes and accepted MC/WC creator
evidence, with every active endpoint's MC/WC state checked. The entire sequence
shares the existing 180-second matrix deadline; it does not get a new recovery
deadline. A finally block resumes owned paused processes on failure. No DB or
production consensus change is made by the fixture.

The nonuniform full-six profile may declare `validator_weights` with members0–4
at6 each and member5 at30, and `threshold_fault.kind: low_weight_majority`.
Its fixed plan has `pause_at_quorum: []`, `pause_below_quorum: [5]`, and the
same4-second settling /12-second observation. Native PQ descriptors and Fift
registrations share these frozen weights. The full current total remains60
and the C++ quorum40; five low-weight members together have only30. The
fresh healthy baseline certificate must include member5 and pass the actual
weighted quorum; it is not called an exact40 certificate (the least reachable
sufficient sum here is42). Only member5 is paused and restored, and its fresh
authenticated vote, MC/WC creator evidence and every endpoint's complete states
are required after resume. CPP control precedes mixed3CPP3Rust, where member5
is Rust. Existing equal-weight plans retain their original exact-boundary gates.

A rotation profile may separately declare `observer_budget` with
`pause_at_quorum: []`, `pause_below_quorum: [0,2]`, `settle_seconds: 4` and
`observe_seconds: 12`. Both frozen committees use17-unit weights. The runner
requires all four authenticated MC signers and MC/WC creators in both epochs.
After rotation, current members are0/2/4/5 (68 total, quorum46); retired1/3
remain running observers. Pausing only0/2 leaves active4/5 at34/68 while both
observers still serve RPC and independently authenticated current-group proofs.
All four responsive endpoints must show no finalized MC identity/state advance
for the full declared window. Original0/2 then resume and must supply fresh
votes, accepted MC/WC creators, six matching applied MC states and complete WC
states on all four active members. The same original240-second rotation deadline
covers this sequence. Rust MC runtime roles are bound to the exact authenticated
certificate session; retired3 must be observer with no validator index, while
retained2/new5 are validators. CPP retired members require corresponding MC
observer startup logs. This legitimate availability/role observation does not
replace acceptance for invalid old-group votes submitted to a new group.
