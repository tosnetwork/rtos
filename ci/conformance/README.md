# Shared conformance target

The formal conformance reference is pinned by `REFERENCE` to clean TOS
`5af405dcb1f523be0ff3b812e9f6945275c4945b`. Use the maintained entry point to
build all 11 adapters and execute the shared vectors plus local regressions:

```sh
python3 ci/conformance/run.py --tos "$TOS_REFERENCE" \
  --out /datax/rtos-conformance/my-run --jobs 32 \
  --reference-binary "$CPP_REFERENCE"
```

The output directory must be new. `--target-dir` defaults to `CARGO_TARGET_DIR`
or this checkout's `target`. The optional C++ binary must identify itself as
clean and at the exact pin. Without it, the run checks Rust against frozen
fixtures, as the GitHub Conformance workflow does. That workflow reads the pin,
checks out the public TOS repository, installs the Rust toolchain from this
repository's toolchain file and retains the logs and JSON summary. It uses two
workers for hosted-runner resources; local builds and tests default to 32.

`--harness` selects an explicit subset; the summary marks whether all 11 ran.
`--extra-fixtures HARNESS=PATH` adds authored/fuzz regression fixtures. Empty,
duplicated or malformed fixture inputs fail. The runner delegates comparison
to the pinned TOS runner and schedules independent family invocations within
one worker budget. It fails on any mismatch, refusal, skip, zero comparison,
process error, or a change to source, inputs or tested binaries during the run.
The summary records commits, input/binary digests and every family command.
`--skip-build` explicitly uses existing binaries and records that limitation.

The suite contains 253910 cases across all 11 harnesses, including local
regressions. Initial-fill provenance is beside the fixtures; effects were generated only by
the clean pinned C++ CLI. Use the shared `regenerate` command on the fixture
and retain updated build/filler provenance when refreshing it.

The shared pin and active interop baseline both use TOS 5af405d. A fixture run
does not qualify the runtime scenarios; historical baselines require explicit selection.
Whole-history native state replay, runtime integration, resource qualification,
GitHub CI outcomes and independent/external reviews remain separate gates.

Reproduce the account-storage hint proof controls against a clean, pinned TOS
Ninja build:

```sh
python3 ci/conformance/storage_hint_reference.py \
  --cpp-build /tos/build/rtos-conformance-latest-5af405d \
  --out /datax/rtos-conformance/storage-hint-reference
```

The probe calls native `AccountStorageStat`, comparing successful partial-proof
updates with full native reconstruction. It checks that a zero-net-change hint
can retain pruned dictionary entries, while missing paths or changed reference
counts require real entries. The Rust unit tests retain the resulting hashes.
The output includes build commands, source/binary hashes and the native log.

Index original archive packages independently of reference replay output:

```sh
python3 ci/conformance/index_archives.py --root /datax/epoch/archive-packs \
  --sha256-list /datax/epoch/archive-packs.SHA256SUMS \
  --out /datax/rtos-conformance/archive-index --jobs 32
```

The SHA256 list defines the exact input set; extra files in the directory are not
included. Every listed package digest and entry boundary is checked. A new output
directory receives `index.sqlite` (packages and blocks keyed by workchain, shard,
sequence) and `summary.json`. Identical block identities are counted as duplicates;
conflicting identities fail. Per-chain first/last sequence, block count and internal
gap count are reported. `complete` means indexing finished, not that replay passed:
gaps and non-genesis starts remain visible, and BOC hashes, proof authenticity,
transaction execution and dependency order are checked in later stages. Failed
scans leave an incomplete index; callers must require `complete: true` before use.
Concurrency and result buffering are limited to `--jobs` packages per batch;
SQLite commits each batch. Original packages remain read-only.

If an original archive contains gaps, a complete continuous replay remains
unqualified. To verify an explicitly scoped genesis prefix while recovering the
missing data, use `select_archive_prefix.py --index /path/to/index.sqlite
--through=-1:8000000000000000:242333 --through=0:8000000000000000:243422
--out /path/to/new-prefix-index`. Every indexed chain needs an explicit inclusive
limit. A limit crossing a gap, beyond the source range, a missing/duplicate chain
or a nested selection fails. The original index stays read-only; the new index
records source hashes, exact limits, selected and not-selected block counts.
The planner carries that selection into its summary. A complete plan/replay of
this selected index does not qualify the omitted source range or missing blocks.

Build the optimized native replay example, then derive dependency order from original BOCs:

```sh
cargo build --release --locked -j32 -p rtos_executor --example stateful_block_replay
python3 ci/conformance/plan_archive_replay.py \
  --index /datax/rtos-conformance/archive-index/index.sqlite \
  --binary "$CARGO_TARGET_DIR/release/examples/stateful_block_replay" \
  --zerostate /datax/epoch/zerostate.boc --zerostate /datax/epoch/basestate0.boc \
  --out /datax/rtos-conformance/replay-plan --jobs 32
```

The planner requires a complete index with contiguous chains starting at one.
Native `--inspect` validates original block hashes and positions and reports
predecessor/master references. The planner checks those identities against the
index before emitting `inputs.jsonl`; it never asks C++ for execution order.
`--mc-limit N` emits an explicitly counted prefix after inspecting all headers;
otherwise every indexed block must be planned. Zero-state identities are checked
by the actual replay against the first block of each chain, not by the planner.
Only a plan with `summary.json` reporting `complete: true` is usable.

The plan includes standalone `{"release_master":"ROOT_HASH"}` records after the
last inspected consumer of a master context. Releasing a context does not remove
the current chain head. Unknown releases fail; an incorrect early release causes
later replay to fail on its missing dependency. Native stderr reports peak and
final retained master-context counts. The planner uses bounded batches of 1000
headers per worker and a reference-count map; it is an offline tool, not a node
runtime scheduler. Planned or inspected blocks are never reported as executed.

Compare the native output with a recorded canonical replay using
`check_archive_replay.py --reference-manifest /path/to/manifest.json
--effects /path/to/effects.jsonl --execution-log /path/to/replay.log
--out /path/to/new-check.json`. It verifies the reference artifact digest, checks
block identity/state roots and transaction counts in order, and requires a native
completion summary with no retained master contexts for a final pass. Bootstrap
file hashes must match the manifest's MC/WC zerostates. Native execution itself
checks each transaction/account root against its on-chain value; the canonical
block receipt contains aggregate transaction counts rather than individual effects.

Add `--require-shard-tops` to qualify the masterchain shard-top commitments.
The native replay emits descriptors from its reconstructed masterchain state;
the comparator checks their sequence/root/file identities against the digest-verified
canonical block inventory, using a temporary SQLite index with bounded cache.
The workchain zerostate is checked against the native bootstrap whose file hash
must match the manifest. Missing descriptors, missing referenced blocks, identity
mismatches and layouts other than the reference replay's single whole workchain 0
fail explicitly. The result records the flag and check count; older outputs without
these descriptors do not qualify under this flag. This does not authenticate signatures
or validate every validator rule. The SQLite identity index is removed on completion.

For a running process, `--allow-prefix` snapshots the current output byte length
and reports compared/equal/mismatched/refused/not-compared counts and partial lines.
This observation mode never returns a pass. Exit0 means a complete final comparison,
exit1 a mismatch/refusal or malformed input, and exit2 an incomplete/observation
result. The output path must be new. Reference receipts retain their own build
provenance: comparing an older canonical replay is not evidence that the latest
C++ binary reran the entire archive. Confirm process exit and seal final input,
binary and output hashes separately before declaring a full replay qualified.

For sequential state replay, build `rtos_executor --example stateful_block_replay`
with `cargo build --release --locked -j32`. Feed JSONL on stdin: initial
`{"zerostate":"/path/to/state.boc"}` records followed by
`{"block":"/path/to/original.boc","root_hash":"UPPERCASE_HEX","file_hash":"UPPERCASE_HEX"}`.
The hashes must come from the archive identity. Supply blocks in dependency
order; all zerostates must precede them. No intermediate state input is allowed.
To read a block directly from its original archive, replace `block` with
`"package":"/path/to/archive.pack","offset":171,"name":"block_(...)..."`.
`offset` is the byte position of the BOC payload and `name` is the exact archive
entry name. Root/file hashes remain required. The reader validates package magic,
entry tag, name/length, a 256 MiB entry limit, file bounds and the name's
workchain/shard/sequence against the decoded block. It refuses an input that
specifies both `block` and `package`. Package discovery and dependency ordering
remain the caller's responsibility; this is not a whole-archive scanner.
The tool checks archive identity, consecutive predecessor identity, native state
updates and transaction/account roots using the block boundary. It emits each
block's effects and exits nonzero at the first error, including empty replay.
Compare emitted roots and counts with the pinned reference replay separately.

The initial epoch-6 qualification covers MC 1–2000 and 2033 associated shard
blocks, with 4124 transactions, all matching the reference. Bootstrap states and
raw blocks were read from the recorded archive; C++ provided only selection/order
and comparison results, never intermediate Rust states. This is an offline
interval tool: it retains replayed master contexts until explicit release, refuses split/merge,
and does not verify block signatures or every validator rule. Shard-top identity
comparison requires the explicit comparator flag described above. Full archive indexing and native dependency planning are available; complete
execution, signature checks and mismatch continuation remain required
for whole-history qualification.


The target executes contexts from the TOS conformance suite and emits the effects of
RTOS. It never reads fixture expectations. Separate targets provide `vm`, `txn`,
`block`, `get_method` and `fee`; unsupported harnesses return `harness_error` and must not
be counted as passing.

The provisional `rtos_executor --example codec_conformance` target adds codec
adapters for BOCs, variable integers, configuration, validators, messages,
transactions, accounts, storage, currencies, addresses, block headers,
masterchain state extras and the generated unsplit shard state schema. It
also validates the generated and handwritten `ShardState` profiles. It
also validates the generated `Block` schema, its nested message and account
dictionaries, value flow and masterchain extra. MERKLE_UPDATE is special and
explicitly enables weak validation of its two state references; pruned cells
consume a visit and are accepted only within that weak subtree.
The full 5040-case codec run currently has 5040 equal, with zero refusals,
mismatches or skips. This covers the frozen codec vectors, not every possible
Block construction or production validation path. All 5040 frozen effects
were also checked against the clean pinned C++ build, without changing fixtures.
An additional300 C++ controls in `executor/src/tests/data/conformance/codec`
cover StateInit, MessageRelaxed, strict encoding, masterchain/shard state
structure, augmented dictionaries and typed-reference budgets.
They all match; run them alongside the original codec suite. The added47
controls pin sparse-mask hashes and Message body references. Generated Message
validates and charges the right-hand `^Any` body reference; its handwritten
validator retains the separate reference-shape-only rule. Untyped `^Cell`
fields, including StateInit code and IHR proofs, remain unvisited.
Native cell hash descriptors use the actual mask restricted to each hash level,
matching C++ for sparse masks. Bounded Merkle check/retention walks distinguish
visits at different Merkle depths, using a charged fixed32-byte bitmap per
representation hash. Both shared-reference orders now agree with ordinary apply;
the old fixture's traversal-order mutation rejection is no longer a valid
negative control after these corrections. Account storage
facts preserve the original slice and reference order, after native structural,
address and logical-time checks, without canonicalizing its encoding.
The ignored example test `export_constructed_state_codec_contexts` writes new
state-schema inputs to `RTOS_CODEC_CONTEXTS_OUT`. Fill effects only with the
clean pinned C++ CLI. These generated schema validators do not perform the
handwritten augmentation arithmetic; McStateExtra's handwritten validator
delegates to the generated validator in C++ as well.
ShardState's handwritten profile checks account depth/balance and queue minimum
emitted LT, including root-extra copies, after validating referenced children.
Post-order arithmetic tasks do not charge a second cell visit. Extra-currency
references survive encoding and failed additions reject rather than retaining a
stale sum. Currency trie merges preserve untouched subtrees and rebuild common
paths using the C++ combine strategy, including when both dictionaries are
nonempty. Generated checks retain their
independent structural rules. The 40
handwritten-state controls also pin signed sequence numbers, split-state profile
differences, explicit emitted LT zero and reference-budget boundaries.
Another138 review controls cover subtree-label preservation and ShardIdent's
distinct profiles: generated depth is at most60; handwritten depth uses all
six bits and checks the workchain sentinel and low-prefix alignment instead.
The codec writer's decimal context parser also preserves the C++ RefInt parser's
five balanced base-2^52 limb capacity and syntax, before applying the independent
VarUInteger byte bound. Parse refusal differs from a valid integer outside the
encoding range. Fifteen clean-C++ protocol records in
`executor/src/tests/data/codec-decimal-reference.jsonl` pin those boundaries,
including empty text and malformed syntax; the example test checks the actual
responses. Expected protocol refusals are not counted as passing shared fixtures.

The `rtos_api --example tl_conformance` target provides the TL wire harness.
It checks the root schema and object/function domain from build-generated native
schema metadata, then uses the T0 generated decoder and serializer. It reads no
fixture effects. The pinned174 original TL cases and154 added schema/domain/primitive
controls agree with clean CPP1181. Explicit target declarations retain the CPP
constructor IDs while referencing the existing native tonNode types. Changed
layouts have separate T0 types, including normalized raw message hashes; legacy
structs remain available through Legacy, and obsolete layouts are rejected by T0.
Native `TlString` owns raw bytes. T0 preserves malformed UTF-8; text consumers
validate UTF-8 explicitly before parsing numbers, JSON or configuration keys.
Legacy string decoding and encoding retain their UTF-8 contract. Numeric JSON
conversion propagates errors, including inside lists/tuples, rather than using
lossy text. Generic Object/Function reads retain the declared schema and kind;
primitive codecs such as Bool are fields, not members of the C++ Object class.
Generic object storage omits its constructor as C++ does; Function storage
retains it. The toslib wire adapter allows only raw.extMessageInfo. Slice-backed
reads check available padded payload before allocating or applying byte caps.
Typed Bool tags use the primitive raw-int reader before constructor-profile rules,
retaining invalid_value for every non-Bool tag, including forbidden legacy IDs.
Configuration names are validated before actor mutation, and a full overlay batch
is checked before any client-map update; malformed wire text cannot poison a
subsequent valid configuration save.
This is measured corpus agreement, not arbitrary TL input or whole-node qualification.
The focused wire-profile and native string tests pass. The broader API library's
previous a3eea42d run retained the sorted-size-list failure also seen at6fb1a144
(6passed/1failed/1ignored); this increment does not claim a clean full-library run.

The `rtos_api --example crypto_conformance` target calls existing native
Ed25519, ML-DSA-44, SLH-DSA-SHA2-128s, padded Falcon-512, LMS, SHA-256,
Poseidon2, quorum, session identity and PQBytes APIs. All9508 frozen crypto
contexts agree, with zero mismatches, refusals or skips.
All9508 frozen effects were independently checked against clean CPP1181.
Thirteen added clean-C++ controls cover full uint64 weights, raw algorithm
selection and validator dictionary size. The native validator decoder checks
the maximal dictionary index before dense membership reads; its bounded sibling
charges the fixed16-bit rightmost lookup before that check. Both reject hidden
entries beyond the declared total. Earlier budget tests now supply matching
maximal indices so allocation and repeated-path guards are still exercised.
The member controls cover raw algorithm
selection. For weights, the structural
TL long commits their original64 bits, while governing ValidatorSet construction
still rejects an overweight set. Raw PQ algorithm0 follows the reference
classical GroupMember profile with a zero classical key; it remains an invalid
PQ descriptor for governing-set admission. Positive algorithms keep the PQ
structural profile, independently of whether the suite is admitted. Native session encoding no longer mistakes
that structural field for an admission check. The admitted-suite key-ID helper
requires ML-DSA-44 and its exact key length before using the existing commitment;
the raw helper retains its diagnostic contract. The four frozen ML-DSA authority
domains are shared native constants, without granting key authorization.
A separate204-input probe gives189 equal effects and15 mutual protocol errors;
those errors are not passing shared fixtures. Adapters apply bounded byte edits
before native calls and reject edits naming an unread input. The config43 and validator-set adapters call native decoders; elector
authorization preimages use shared native serializers with explicit byte order.
Native expected-block signing shares raw coordinate binding with proof linkage
and explicit finality. Cell signature-carrier parsing optionally checks supplied
set metadata, signer membership, key commitments and claimed weight, without
verifying signatures or authenticating that set. Network carriers validate each
pair's algorithm and length before duplicate identities, and Lite candidate
parsing follows signature validation. Twenty-three additional C++ controls pin
these refusal orders, empty carriers, raw coordinates and maximal declared weight;
empty summary lists use the reference dash marker. Together the original9508 and
added36 controls yield9544 equal. A separate mismatched-set-hash probe is mutually
refused at the protocol boundary and is not a passing shared fixture. This is corpus agreement,
not arbitrary-input, network or production runtime qualification.

The provisional `adnl --example net_conformance` target connects native wire-key,
signing, verification, deterministic encryption/decryption, shared-secret,
ADNL-ID text, RaptorQ/Online/RoundRobin codecs and peer FEC-type operations.
At the 2026-11-14 overlay checkpoint, all1245 original network contexts agree.
Added101 clean-C++ controls give1346equal/0unsupported/0diff/0skip; the network
runner exits0. Unsupported operations are never passing cases. A separate
262-coordinate probe and78wire/identity probes retain their earlier key-checkpoint
scope, independently from the shared corpus.
Overlay records retain TOS's flags-bearing node/signature layout and validate
flags before the Ed25519 identity. Member certificate fields and signed expiry
with a three-second grace are preserved; signature verification alone does not
install or authorize a member. Broadcast certificates reuse native network key
profiles, including pub.unenc, on both direct and cached checks; they normalize
default flags to the v1 wire form. Existing peer signature bans remain in force.
Privacy rules retain direct-key precedence and report the maximum configured cap.
The live member expiry check also uses the signed grace comparison.
The explicit native channel API derives directional secrets and AES-key IDs, routes
before decrypting and validates the peer identity after packet construction. Channel
authentication does not require a packet signature. All16 original channel contexts
and640 additional C++ comparisons agree; four native channel tests cover equal-ID
roles, routing, digest/TL/source refusals and signature handling. This API is not yet
installed into the asynchronous node peer/channel lifecycle.
Network key agreement maps the unsigned Edwards-Y wire coordinate modulo the
field before the existing X25519 multiplication. It need not be a decompressed
Edwards verification point; zero shared results and the noninvertible coordinate
are refused. The coordinate conversion follows the existing public-integer
strategy with OpenSSL; private scalar copies use zeroizing storage. Ordinary
signing verification retains its own Ed25519 point checks. Wire private keys use
existing guarded/zeroizing containers and are neither Debug nor Clone.
The variable-key size estimate is separate from padded serialization length.
The typed wire readers retain refusal boundaries, including oversized declared
strings, and ADNL-ID text uses the native base32/CRC16 helper. Legacy key profiles
and the existing ADNL cipher construction are preserved; these primitive effects
never grant peer, packet or DHT admission. Full asynchronous network transport and validator runtime qualification remain
incomplete.

RaptorQ repair APIs use relative repair indices and preserve external ESI on the
wire. The explicit FEC decoder follows TOS/TON's arrival-order, inactivation and
Gaussian pivot policy, including inconsistent repair equations; its returned
encoder retains solved intermediate symbols. Ordinary generic RFC decoder APIs
remain separate. Online retains repeated indices and reference propagation order,
then regenerates RoundRobin symbols. A shared CPP/TON RoundRobin assertion on a
non-divisible full final symbol is recorded as a non-JSON boundary, not a pass.
Peer FEC types use bounded typed T0 decoding and validate signed fields, the
TOS-specific768-byte floor, size/count consistency and constructor in that order.
Type acceptance is separate from decoder capacity: zero-size peer data is valid,
while a type above56403source symbols cannot create a decoder. Local codec
configuration bounds remain independent. Peer-type validity alone does not admit an RLDP transfer. The explicit native
RLDP2 connection now admits raw receive packets and schedules outbound packets;
ADNL message/address/packet/local-datagram and preauth source/gate contexts now
use explicit native APIs; channel16 and overlay122 contexts remain unconnected.
RLDP2 FEC demand and checked reservation/solver-cost queries are connected to
native helpers; the FEC-demand helper is also used by the existing native sender.
The new reservation ledger implements solicited/unsolicited shares, per-identity
limits, checked headroom and owned shrink/drop release. Its ledger lifecycle is
tested against direct CPP calls and is now held by native Connection decoders,
finished part buffers and temporary solver attempts. Reservations precede decoder
creation; exact local requests select solicited credit on the authenticated peer
connection. Completion, error, timeout, replacement and connection drop release
their owners. Multipart assembly is charged only when the last part opens; a huge
claimed total does not eagerly allocate a transfer-sized buffer. Decoder recovery
can omit the regenerator and move decoded bytes into the transfer owner.
The native connection has bounded pending requests/transfers and a completed-ID
cache, ACK history/timers and strict TL framing. Callers drive it using one monotonic
clock epoch. An indexed four-ary timer heap preserves CPP timeout tie ordering. This is an explicit
connection API; existing asynchronous RldpNode integration and actual Rust allocator
peak/whole-process memory qualification remain open. Cost equality alone does not
prove actual Rust decoder/solver heap fits the CPP-derived reservation formula.
Outbound state uses native part/ACK/loss/RTT/bandwidth/BBR/pacer state with one fixed
clock sample per run, rather than deriving a packet count from fixture size. It
retains partial transfers, accepts typed raw confirm/complete packets, releases
in-flight counts and reports completion/timeout. Inbound/outbound deadlines share
one indexed heap; random transfer IDs are returned internally to bind their timers.
Connection runs return errors from local outbound encoding to the caller. Native
paired-connection tests exercise real ACK progression, delivery, completion echoes,
bidirectional same-ID ownership and mixed timer ordering. GSL-enabled reference
loss quantiles are matched by a native probability recurrence; no runtime GSL
library is added. Randomized BBR phase sequences, actual socket transport and
production runtime/heap bounds remain outside this checkpoint's qualification.

Native ADNL Packet retains received flags before typed-field validation. Public-key
identity, message/address construction and basic checks preserve the reference's
first-refusal order. Priority stays visible in receive metadata and is removed from
canonical signing bytes; signatures are verified over the canonical normalized
packet. Address lists normalize uint16 ports, partition QUIC entries, deduplicate
reverse addresses and use the reference size estimate/version sentinel. Local-ID
datagrams route the destination before decrypting, then validate the packet and
require an authenticated full source. Local unusable decryptor configuration is
separate from a peer refusal. These APIs do not install a peer or mutate Node state.
Preauth admission uses source IPv4/IPv6-/64 keys, source LRU/rate checks, shared
process/local budgets and owned tickets. Drop releases concurrent credits while
retaining rate debt. Native clocks and deterministic `_at` methods share the same
algorithm. Existing asynchronous AdnlNode receive routing is not yet switched.
Slice-backed T0 TL entry points retain input length; vector multiplicity is checked
against remaining bytes before elements, as in CPP TlFetchVector. Legacy vector
order stays unchanged. Network refusal translation retains bad-length separately
from truncation. Eight actual-CPP count controls and native typed/dynamic/prefix/
bundle regressions cover the guard. Broader physical-memory/production/Node
qualification and non-author review remain open.

The provisional `rtos_api --example consensus_conformance` target calls native
weight, validator-set, protocol-version, session, vote, explicit finality, structural
proof and key-block proof-link APIs. All268 original consensus contexts agree
with clean CPP1181. Run the whole consensus directory and added controls together. The raw numeric
`quorum_weight_reached` predicate matches C++ even for total0 or signed weight
above total. Node callers retain `has_quorum`'s nonempty and non-overcounted
membership guards, delegating only the numeric comparison to that predicate.
This distinction grants no signature or membership authority. A separate2138
input probe matches C++ effects or protocol-refusal status, including12 mutually
refused malformed contexts; protocol errors are not passing shared fixtures.
An additional24 C++ controls in `tl/rtos_api/tests/data/conformance/consensus`
cover explicit double/unsigned session options, future version predicates,
raw block coordinates, vote role/signature input and malformed candidates.
Node Param29 conversion delegates to the same native options encoding; explicit
session hashes and wire coordinates do not authenticate a governing config.
Native vote encoding shares its preimage serializer with production finality
while retaining raw wire coordinates at the structural boundary. Node finality
keeps its membership, admitted-block and canonical candidate checks.
Additional787 session/vote/version probes match C++, and the earlier2138 weight
and set probes still agree (12 mutual protocol errors remain separately reported).
This corpus agreement does not qualify a running consensus network or
production proof acceptance.
The native proof envelope keeps signatures opaque until header and state-update
checks finish. Its shard unpacker uses the C++ unpack profile (depth at most60),
which differs from the handwritten validator profile above. Structural header
reading validates inline fields and reference shape while leaving previous-block
references opaque; the existing full reader still traverses those references.
Key-block contexts derive validator subsets and both session identities through
native APIs. Supplied key blocks are test anchors, not authenticated chain state.
Another25 clean-C++ controls cover pruned roots, previous references, shard
alignment, trailing data, reserved fields and versioned governing options.
Together the original268 and added311 contexts yield579 equal, zero mismatches,
refusals or skips. Param29 options expose the full uint64
height-coefficient product while committing its low32 wire bits; the block-hash
flag follows the version2 boundary. A separate raw probe pins a product above
uint32; it is outside the shared fixture schema and is not counted in579.
Twelve further C++ controls pin review findings at the structural boundary:
BlockInfo captures the software field as104 bits without checking its nested
constructor, while its full reader keeps that check. Key-block config extraction
requires the auxiliary cell to end exactly. Optional legacy Param28/29 use the
C++ factory defaults when absent or not unpackable; strict production accessors
retain their own contract. The decoded-options session helper grants no governing
authority. Structural contexts report the header and Param19 IDs independently;
production finality still rejects a missing or mismatched governing Param19.
Two additional C++ controls keep pruned Param28/29 unavailable: they refuse as
proof_malformed and must never fall back to default configuration.
Fifteen more C++ controls pin pruned dictionary paths, selected-config cells and
Param19 metadata. Native proof parameter access preserves both typed pruned-error
forms and never decodes pruned payload bytes as a global ID. Wire signature
parsing retains its separate carrier error boundary. Three further C++ controls
keep the key BlockExtra root, McBlockExtra root and auxiliary cell unavailable
when pruned; the structural key-config reader checks each before decoding.
The explicit finality context accepts supplied membership/session and raw wire
block coordinates without constructing an admitted-chain token. Native APIs
check carrier compatibility, set/role/session/candidate identity, signed-member
key identity and weight, every signature, quorum and finally a final-proof weight
claim. The actual unbounded signature loop is shared with production finality;
production governing-set, canonical candidate and masterchain approval admission
guards remain. Pair field validation is also shared with the cell serializer.
Eighteen clean-C++ controls pin ordering, mixed members, unsigned versus signed
key faults, raw coordinates, and the certificate-only proof envelope boundary.
This operation never authenticates the envelope's block root or declared ID;
proof-link validation must establish those separately. An additional input
probe matches1612 effects and169 mutual protocol errors in1781 contexts; those
protocol errors are not passing fixtures. Signer counts400/401/1024/1025 also
match: unknown signer / too many / too many / protocol error. A raw extra final
field is outside the shared schema and is excluded from the579-case corpus.
The native two-envelope proof-link API checks masterchain direction, Merkle roots,
headers, governing key-block or zerostate config, validator subset and certificate.
Its caller-supplied source is an anchor, not independently authenticated chain
state. This input carries no source-state proof, so backward links are incomplete.
Forward links verify actual signer weight without enforcing the separate finality
operation's declared-weight claim. Ordinary and Simplex Ed25519 certificates share
native signature verification; PQ certificates reuse explicit native finality.
Twenty-three clean-C++ controls cover opaque envelope IDs/source certificates,
missing-certificate priority, pruned fields, header-hash priority, zerostate
anchors, classical signatures and missing validator sets. Proof selection reads
legacy options before decoding the selected protocol and visits only recognized
noncritical parameter keys. Strict production config accessors retain their
contract; complete state readers retain their existing auxiliary-cell profile.
Thirty further controls pin required Param34/35 availability, missing/invalid
validator sets before legacy options, and governing sets of1024/1025 members.
Proof readers prefer35 over34, fail on an invalid selected value and leave the
unused fallback opaque. Proof linkage uses the wire uint16 member count; the
explicit supplied-context constructor retains its1024-member bound. Pruned-value
controls use distinct unavailable hashes so C++ cold and warm batch effects agree;
they do not deny C++'s ability to reuse a previously validated cached set.
The native configuration readers now share a 100-entry validator-set LRU keyed
by representation hash. Only successfully decoded sets enter it; a root loader
error still fails on a hit, and live usage tracking disables both lookup and
insertion so Merkle proof generation visits the full set. Cached values own
parsed sets, without retaining cell graphs or usage trees. Proof readers share
immutable sets; existing owned getters return independent copies. Disabled-cache,
wire/schema and bounded decoding remain independent. Ordered cache families must
run in a single process per family: 108 additional controls cover cold misses,
known pruned roots, recency refresh, eviction and cross-entry reuse.
Another51 controls cover exact configuration dictionary reference shape and
structural Param19 metadata. Dictionary values require zero bits and one
reference before any cache lookup. Structural metadata reads the first signed
32 bits of an ordinary cell, reports null if shorter, and leaves trailing bits
and references opaque; it does not replace production governing-ID validation.
Malformed dictionary entries preserve the reference operation's error class.
The cache cap is an entry count inherited from the reference, not a byte budget;
large-set memory and production hardware qualification remain separate work.
Session JSON retains the two double tokens until binary64 conversion, preserving
correct rounding, negative zero and C++'s finite saturation on overflow. The API
package's dev-only serde_json features enable precise float parsing and borrowed
raw values; the node's production JSON dependency is unchanged. Twelve of the
controls pin this conversion, including ordinary positive decimals and large
integer tokens. The independent review found590 differences in2000 random finite
doubles on the prior adapter; the corrected adapter matches all2000. This fixes
the test protocol boundary, without changing the native session hash rules.

The native configuration schema now requires both queue-limit fields in CP43 v3
and rejects CP47, which the pinned C++ schema does not define. The older compressed
native corpus stays intact. Its 390 CP43/47 inputs use separately refreshed C++
verdicts, tied to their original input fingerprints; 11 verdicts changed. To
reproduce, export with the ignored `export_existing_schema_43_47_contexts` test
and `RTOS_CFG_CORPUS_OUT` pointing outside Git, then use
`ci/conformance/refresh_config_schema.py --help`. Keep raw contexts and effects on
retained storage. The script checks the clean reference commit against `REFERENCE`
and never uses Rust effects to fill expectations.

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

`tick-precompiled-scope` contains12 pinned C++ controls proving that configured
precompiled costs apply to ordinary transactions, while tick/tock uses normal
VM gas and steps. The optional global precompiled-list record still decodes;
tick/tock skips only the contract lookup and cost override.

`signed-flat-gas-fee` contains12 C++ controls around the31-gas ACCEPT execution
cost, flat limits0/31/32 and flat prices on both sides of the signed64 boundary.
The transaction fee helper returns a checked result: flat-only fees keep unsigned
prices; variable fees add the signed64 flat price. Negative fees fail rather than
enter unsigned Coins. Both compute paths and the BlockchainConfig wrapper use
the checked result; standalone VM fee opcodes keep their own reference semantics.

`storage-finalization-rules` and `storage-hash-version-boundary` add21 C++
controls for forced recounts, masterchain hash removal, and version9/10/11
currency-count/hash gates. Before execution, snapshot the input account's usage
and roots. Size limits use code/data/library roots; pre10 billing additionally
counts the currency root. Finalization preserves supplied usage only when the
selected roots are unchanged, forces a recount above25 stored cells without a
hash when hash storage is enabled, and applies the configured hash threshold
after recounting. Hash storage is enabled from11 and excludes masterchain.
`Account::finalize_storage_stat` is shared by emulator, conformance, collator
and validator. The controls also check that repeated finalization is idempotent.
Snapshots/cache views are in-memory only and retain at most four input roots.

## Block target

Build `cargo build -p rtos_executor --example block_conformance --locked` and run
the shared runner against `$TOS_REFERENCE/test/conformance/vectors/block`.
`block_conformance block` accepts one context per line, limited to 16 MiB.
It validates and applies the native Merkle update, derives configuration and
previous-block history from the supplied chain state, and re-executes every
transaction in account/LT order through the transaction target's executor path.
It checks transaction and account hashes and each final ShardAccount against the
applied state. Shard contexts must supply the referenced masterchain block and
state together; block identity includes its original file hash. Split/merge
blocks are rejected, as in the reference. Execution is capped at 4096 transactions.

The frozen block fixtures are negative controls. Also run the positive REL-02
corpus, using the pinned reference exporter and the independent chain checker:

```sh
python3 "$TOS_REFERENCE/test/conformance/migrate/block_chain.py" chain \
  "$TOS_BUILD/test/conformance/conformance-block-export" \
  "$CARGO_TARGET_DIR/debug/examples/block_conformance" \
  "$TOS_REFERENCE/test/rel02/corpus"
```

The checker compares all accepted effects with hashes decoded from the on-chain
blocks and transactions in the manifest. Retain exported contexts and results
outside Git. Passing this boundary does not qualify full validator validation,
archive replay, networking or the remaining conformance harnesses.

Also pass `executor/src/tests/data/conformance/block/fixtures` to the runner.
These C++ checked controls cover a shared cell reached at two Merkle depths and
a zero-state history record with an incorrect sequence number. The first uses
a synthetic non-ShardState previous root: successful update validation and
application must reach `prev_state_malformed`. The second must fail configuration
extraction before any transaction, even when the account-block dictionary is empty.

## Getter target

Build `cargo build -p rtos_vm --example get_method_conformance --locked`, then run
the shared runner with that target against
`$TOS_REFERENCE/test/conformance/vectors/get_method`. Its `get_method` line protocol
accepts the account, masterchain snapshot and block identity, explicit time/LT,
seed, signed64 method ID, arguments and gas limit. It uses the node getter's c7
helper and native VM, rather than libemulator's different getter profile. Library
selection uses global dictionaries first and excludes account libraries from15.
Missing-library hashes come from actual failed native VM lookups.

From version16 the node getter c7 has19 fields, with its last field always null;
it has no authenticated incoming-message statistics. The shared frozen fixtures
remain unchanged. The legacy getter TSVs retain their older snapshot hashes;
`python3 ci/conformance/refresh_getter_shape.py "$TOS_REFERENCE"` updates only the
scalar shape probes and the final null field of legacy c7 expectations, using
the pinned C++ effects. It never executes Rust to derive expected values.

Inputs remain limited to16MiB per line,255 initial arguments and depth32; output
uses the VM target's canonical stack renderer with depth512 and2^20 visited values.
Malformed protocol inputs refuse; unavailable configuration and inactive account
states produce their reference outcome classes. Only executed frozen cases with
zero differences/refusals/skips prove this getter boundary, not whole RPC or
validator qualification.

Run `vm/tests/data/conformance/get_method` alongside the frozen corpus. Its seven
clean-C++ controls cover absent, uninitialized, frozen and malformed accounts,
an active account without code, and configuration failure before account-state
classification. An absent code root returns fatal(-13) without execution or gas;
an ordinary empty code cell remains an executable program. The optional-code VM
setup is shared by the node getter and this target.

Two review controls also require the standard C++ Account constructor tag and
skip precompiled lookup when code is absent, even with a pruned CP45 dictionary.
The node's optional-code c7 helper and initial-c7 responses preserve this absence.
A pruned Account is an incomplete context and refuses after configuration has
been checked. Its separate protocol test is outside the shared fixture corpus;
refusals must not be counted as executed conformance successes.

## Fee target

Build `cargo build -p rtos_executor --example fee_conformance --locked`, then run
the shared runner against `$TOS_REFERENCE/test/conformance/vectors/fee` and
`executor/src/tests/data/conformance/fee`. This target calls native storage,
gas-purchase and message-price arithmetic; it does not implement its own fee
formulas. Amount/price inputs use full unsigned decimal strings, fractions use
u32 as in the C++ calculation constructor, and storage vectors have at most64
periods. Line inputs remain limited to16MiB.

Native `MsgPrices` preserves both C++ profiles: scalar node fees wrap at64 bits,
whereas RefInt256 fees preserve signed scalar conversions. Wire configuration
fractions remain u16. Node fee callers use the scalar profile and VM forward-fee
opcodes use the wide profile. Checked Coins helpers preserve negative-fee errors
and handle large intermediate products without integer overflow. Exact gas
thresholds retain their sign; the existing nonnegative purchase threshold view
remains valid for nonnegative balances. Invalid gas quotients follow the
reference's signed-minimum conversion, including reachable zero-price cases.

Explicit storage calculations can return a null fee; this is an effect, not a
protocol refusal. Chain history loading still validates strictly increasing
price periods before computation, while the explicit-vector harness follows the
reference calculation's own ordering/early-return behavior. Transaction and VM
storage fee paths use their respective reference scalar conversions.

The seven additional C++ fee controls cover signed storage products, null fees,
raw special-account history handling, gas and forward-fee widths. Three C++ VM
controls in `vm/tests/data/conformance/vm` cover signed storage prices on valid
VM operands. Existing shared expectations remain unchanged.

Fee qualification is limited to the executed frozen corpus and added controls.
An additional750-case deterministic boundary probe found22gas differences
(14fee,8purchase) caused by a signed-limb overflow path shared by pinned TOS and
current TON (`RefInt` scalar add/subtract through `BigInt::add_tiny`). For example,
gas price0, limit1, flat limit0, flat price9223372036854775807 and balance1 yield
C++ fee-9223372036854775809 versus the Rust mathematical9223372036854775807.
The prior native implementation already had this discrepancy. The evidence is
recorded in memo; deployment/fork reachability and UBSan confirmation are not
claimed. Under the workspace upstream-first rule, this batch neither changes
the shared C++ path nor emulates its undefined overflow in Rust. It must not be
described as equivalence for arbitrary accepted u64 gas contexts.


## Latest network destination boundary

The latest TOS5af405d channel harness routes through the peer table. Its destination
lookup is shared with the Rust socket receive pipeline: local identities take
precedence over inbound channel registrations, before any decryption. An unknown
destination is refused by that lookup. The standalone Channel API retains its
channel-only namespace. The latest corpus has1290 equal effects,zero mismatches,refusals or skips.
This finite network corpus does not qualify every asynchronous runtime caller.
The earlier640 additional channel comparisons against the latest C++ actor harness
retain their ebe81eb9 source scope. Native
checks cover registry precedence, unknown/short destinations, four channel tests
and12 actual node lifecycle tests. This does not qualify the separate channel
crypto/parser API as fully installed in the asynchronous peer/channel lifecycle.

OverlayNode can bind a BroadcastClock at construction. Broadcast dates, date-window
checks, source-certificate expiry and Plumtree messages use that node-owned clock;
the default uses system wall time. Transport deadlines and rate-limit windows
retain monotonic time. Real UDP tests cover ordinary/FEC delivery at equal clocks,
rejection at21seconds skew, a certificate valid at the supplied historical time
and an expired certificate. This clock boundary prepares the broadcast adapter;
the clock increment alone did not qualify the45 additional broadcast contexts.

The broadcast adapter now runs fixed-member OverlayNode instances with a recording
network edge after native authorization/construction, and application callbacks
that approve checks and record actual deliveries. It reads explicit context inputs
only. Transport reachability supplies no membership authority; fixed members and
source privacy rules still apply. Bindings are immutable once an overlay exists,
and overlay retirement drains producers before the adapter returns.

Ordinary TOS broadcasts use the native local check/relay/deliver path and propagate
to the full neighbour set, including the forwarding peer. Legacy behavior remains
in its own wire profile. Fixed-member opaque messages, empty messages, foreign TL
objects and trailing data reach the raw application callback, following the C++
actor. Source certificates do not extend authority in this profile. An explicit
FEC API preserves a FEC carrier for small payloads. Locally generated TOS FEC parts
also pass through native signature checks, reassembly, propagation and delivery.
The sender completes four-symbol waves, with a10ms interval and the C++ send target;
ordinary FEC relays use the full neighbour set. Legacy pacing remains scoped.
Ordinary TOS source admission refuses forbidden sources; the local protocol performs the
application check once before delivery/relay. Both simple/FEC approval and refusal
are covered, including zero emissions on refusal.

All45 additional contexts match the latest C++ actor effects;zero differ or
are unsupported. Six additional raw-message controls agree after five actual
before-change differences. Native checks include transport binding/retirement,
fixed-member certificate restrictions and small explicit FEC; three behavior
mutations demonstrate that these checks fail when the guards are removed.

FixedMemberOverlayOptions binds two-step mode and the live sender backend at
creation. With a sender installed, native FEC dispatch selects two-step unless
FLAG_BCAST_NO_TWOSTEP is set; that control flag is removed from the wire carrier.
Without a configured sender, the ordinary overlay/FEC path remains available,
following C++. TOS uses a reliable sender for small and large two-step messages;
Legacy retains its earlier transport and signature profile.

TOS two-step uses boxed signing preimages, at least513bytes and five intermediates
for FEC, and k=(intermediates-1)/2. Part assignment follows the C++ peer-key order.
The source delivers its validated local payload as C++ does; receiving applications
observe the signing source identity separately from the forwarding ADNL peer.
The adapter hands off whole emission batches before the next scheduler round,
matching the reference without sorting recorded effects. Fifteen additional C++
controls cover thresholds, membership count/order, source rules and flag behavior;
an empty-inbound-array control also agrees after its prior harness refusal.

Plumtree uses the existing native engine, fixed-member policy and node-owned clock.
Its immutable broadcast edge now carries both messages and bounded repair queries;
the live path continues through QUIC. A message-only edge refuses queries explicitly,
as the reference recording edge does. Overlay retirement cancels pending queries
and sends before joining its owned tasks. The adapter activates Plumtree only after
its broadcast subscription is active; it supplies original-sender membership and
validator eager limit1, then records actual native effects. Source publication
refusals (invalid size or source policy) are typed separately from transport failures.
The original sender ignores IHave, including flipped signatures, before payload
signature verification, following the reference's actual role-specific path.

The native overlay receiver also handles overlay.unicast as an application message:
it checks transport membership, passes the inner bytes to the raw message callback
with the forwarding ADNL identity, and does not apply broadcast source rules or
deduplicate repeats. Empty, opaque and nested TL payloads remain unchanged.
overlay.fec.received/completed are consumed without delivery or relay, as in C++.
Nine certificate-issuer/flags controls agree with C++ under fixed-member rules;
that probe found no certificate-parser ordering difference and changed no such code.

Broadcast date fields retain their uint32 wire meaning across the signed i32
boundary. Timeout addition and diagnostic FEC age subtraction widen before
arithmetic. Native source/receiver tests cover equal clocks, dates on opposite
sides of that boundary, and20/21second future skew; the accepted window is unchanged.

## Offline candidate-validation target

Build `cargo build -p rtos --example validate_conformance --locked -j32` and run
that target with the shared runner against `$TOS_REFERENCE/test/conformance/vectors/validate`.
All643 current contexts agree with clean CPP5af405d:610 accepted candidates and33
negative outcomes, zero differences/refusals/skips. The original CPP1181 subset of638
remains covered. This is the executed corpus, not
arbitrary-block or whole-node/latest-TOS qualification.

The adapter supplies original block/collated bytes and up to32 explicit state
roots to the node's actual ValidateQuery. Merkle proofs retain virtualization and
pruned-cell failures. Setup errors remain protocol errors; missing requested input
is distinct from a candidate rejection. Native validation returns the accepted
millisecond timestamp only after the entire validation core succeeds. No fixture
expectations are read and no result is inferred from a structural header check.

Reference masterchain account dictionaries are prepared with masterchain metadata,
so a pruned required root fails before auxiliary governing-state requests. The core
follows CPP early LT alignment, committed previous-state hash checks,
state-header validation order, governing-state selection for shard descriptors,
zero-state neighbour exclusion, time-before-queue-failure ordering and deferred
transaction-account reads. Aggregate fee reconciliation follows transaction
validation. Shard transaction configuration avoids parameter31, which CPP reads
only for masterchain special contracts. Ordinary constructor callers retain their
full-configuration profile. Supplied roots acquire no peer/network authority and
successful offline validation neither publishes nor persists a block.

A descriptor's permission to carry no signatures is separate from verifying a
present signature. Only an actually empty permitted classical carrier selects the
unsigned path; governing metadata checks precede skip-signature handling, and PQ
authentication remains required before cache/fake/skip paths. The older descriptor
APIs retain their default governing-state argument; this checkpoint explicitly
loads governing states in ValidateQuery and does not qualify every other caller.

Inputs are bounded to16MiB per JSON line,4MiB per block/collated/state BOC field
and8MiB of states in total. All encoded state sizes are checked before any state
is decoded, matching CPP. The shared boundary control refuses four oversized inputs,
executes a block at the bound and then answers a frozen input in the same process.
These are adapter input bounds, not measured process-memory or validator-work quotas. Reason classes
are rendered from actual native errors, including Rust's nested diagnostic forms.
Additional unsupported provider operations or panics are harness failures, not
passing rejection outcomes. Latest-TOS regeneration, asynchronous transport wiring,
archive/runtime/resource/CI/review/release gates remain open.

### VM failure-order regressions

`vm_failure_order_contexts.py` emits the stack-depth, dynamic-gas, FITSX/UFITSX,
and variable-width integer-store precedence matrix. Generate contexts, then fill
`vm/tests/data/conformance/vm/fixtures/vm-failure-order.jsonl` with the pinned TOS
`runner/conformance.py create --harness vm --family vm-failure-order --source authored`.
Expected effects always come from the C++ reference. The companion
`vm-fuzz-order-minimized.jsonl` retains 12 minimized failures from grammar seed
141123, cases 0..9999; its inline contexts can be refilled with `regenerate`.

At TOS5af405d, C++ and TON857b8a57 check full operand depth before FITSX/UFITSX
parameter types, stack availability before variable stack-movement gas, and
variable storage width before builder/value types. RTOS follows that order.
The 156 authored cases include both successful operations and invalid operand
combinations; 12 minimized fuzz cases preserve the original discovered classes.
This is a finite regression corpus, not coverage-guided fuzz-budget qualification.

`vm_context_edges.py` emits adjacent boundaries for variable integer stores,
random-seed tuple extension, slice reference windows, and stack-index limits at
versions 3/4. Fill its contexts as family `vm-context-edges` with the same pinned
C++ runner. `vm-fuzz-context-minimized` retains nine failures from seed 141123,
cases 10000..109999. Signed variable-integer zero uses a zero-byte payload;
SETRAND can extend the inner c7 tuple to index 6; LDSLICE preserves an already
consumed reference offset even when its result has no references. The old
maximum stack index of 255 applies before version 4 only. These checks cover
historical profiles as well as active-version behavior and are not a release gate.

### Publication custody fixture

`generate_publication_fixture.py --cpp-build <pinned-TOS-Ninja-build> --out <empty-directory>`
rebuilds the synthetic `v2-publication-spool.json` fixture. The native build must
use the clean commit in `REFERENCE`. Set `CARGO_TARGET_DIR` when sharing an existing
Rust build. The command writes a separate `fixture.json`; copy it into the testdata
directory only after the generation receipt and node tests have been checked.
Native ML-DSA signatures use randomized signing, so repeated runs need not produce
identical bytes. Retain the exact output and generation receipts together.

The native helper derives three explicitly public test seeds from
`SHA256("rtos/publication-custody-fixture/v1/<index>")`, where index is 0, 1 or 2.
It reads no operational keys. The Rust preparer replaces committee keys and all
dependent masterchain references, validator hashes, session identities and
candidate preimages. The native helper independently checks both original and
replacement governing states, block identities and three signing preimages per
candidate. Native verification checks 18 signatures and rejects 36 modified-message
or signature-domain controls; mismatched governing states and candidate block IDs
also fail. The Rust verifier checks final, approval and candidate signatures.
These receipts qualify fixture construction; node acceptance, persistence and
restart tests remain separate requirements.

The Engine fixture loads the matching public seed through the normal protected
key-file loader, with a private directory and mode-0600 file. Historical transport
fixtures continue to hold no consensus key. `v2-publication-history-anchor.json`
preserves the original spool fixture byte for byte because the separately signed
`v2-publication-history.json` chain commits to that zerostate. The historical test
uses this anchor without a retired consensus key; do not mix that signed chain
with the regenerated custody fixture's zerostate.

Reproduce the collator proof-budget traversal controls:

```sh
python3 ci/conformance/proof_budget_reference.py \
  --cpp-build /tos/build/rtos-conformance-latest-5af405d \
  --out /datax/rtos-conformance/proof-budget-reference
```

This focused probe uses native `vm::ProofStorageStat` with the preorder budget
walk from pinned TOS `validator/impl/collator.cpp:3075-3122` (also present in
TON `857b8a57`). Its fixed graphs model cells that all belong to the original
storage dictionary; it does not execute native full-block collation. Ten
controls cover a pruned parent's refund before an absent child, refusal before
a later refund, and a cumulative budget across roots. The prefix peak, rather
than only the final size delta, determines acceptance. Rust regression
`proof_storage_stat_native_preorder_budget_boundaries` also checks that rejected
walks leave the original statistic intact. Build commands and native
source/binary hashes are retained in the output receipt.

Four additional native controls exercise `ProofStorageStat::add_loaded_cells`:
a dictionary proof selected for an earlier account contributes its loaded cells
and pruned boundaries to later accounts' budgets, without downgrading full cells.
The Rust regression `proof_storage_stat_merge_selected_dictionary_proof` checks
the same merge and budget boundaries. The collator now includes selected
dictionary proofs in its running statistic, as pinned TOS does at line 3130.

For offline inspection of `test_collated_data2`, set
`RTOS_COLLATOR_PROOF_EXPORT=/datax/rtos-conformance/<run>/export` when running the
exact node test. The helper writes regenerated `block.boc` and `collated.boc`
under each fixture basename before checking the original proof-count assertion.
These are public synthetic test outputs, not an authenticated historical replay.

Replay the real eight-account proof-selection profile with native TOS:

```sh
python3 ci/conformance/proof_selection_reference.py \
  --cpp-build /tos/build/rtos-conformance-latest-5af405d \
  --out /datax/rtos-conformance/proof-selection-reference
```

The JSON fixture and its SHA-bound generated TSV view retain decision prefixes
from the historical `56703839` collator fixture, captured on Rust `d83c410d`.
The native probe rebuilds each complete storage dictionary from the existing
original state, verifies its root, recreates the frozen `ProofStorageStat`, checks
every captured membership and budget against native primitives, then runs the
native preorder decision. All eight cases agree: seven dictionary proofs and
one state-proof branch. The collator regression derives its expected count from
these choices and checks the exact dictionary hashes, candidate bytes and proof
root multiset. Neighbor proof order is unspecified; their content hashes are
unchanged when tracing is enabled or disabled.

Only cells beyond the stopping prefix are pruned in the compact inputs. The
Rust unit test replays the same frozen prefixes and checks refusal atomicity;
the native verifier checks the JSON/TSV correspondence. The capture is a Rust
usage snapshot, not native full-block collation. An additional full native
validation attempt stopped with `pruned_input` in the historical served context;
it is not an acceptance or whole-history replay result. Capture instrumentation
and raw input hashes are retained under
`/datax/rtos-conformance/2026-11-15-collated-proof-selection`, rather than adding
tracing paths to production code.

### Legacy collator size-limit fixtures

`collator_size_limits_reference.py --cpp-build <pinned-TOS-Ninja-build> --out <empty-directory>`
reads the three public collator bundles named in the script. It virtualizes their
actual masterchain-state Merkle proofs and requires native TOS to reject the old
configuration43. TON857b8a57's version2 includes a trailing optional library-load
limit; TOS5af405d carries that field in version3. These are different reference
schemas, not evidence that the original TON inputs are corrupt.

The native helper validates the version2 common prefix, preserves every remaining
optional-limit bit, switches to version3 and appends the four new fields from
native `SizeLimitsConfig` defaults. Native decoding must accept the result and
recover the same optional library limit. Output contains the old/new cells and
hashes, source-file hashes and a pinned build receipt. Input files are capped at
64MiB before allocation and must not grow during the exact-length read. Each input
is released before the next; no operational key or network is used.

After checking the receipt, install the separate `migrations.json` output as
`rtos/src/tests/data/collator-size-limits-migrations.json`. The test-only
`CollatorTestBundle::use_native_size_limits_fixture` explicitly applies this
small hash-indexed table to the trusted masterchain test context, verifies every
legacy field including the optional limit, and reproduces the native replacement
cell exactly. Unknown invalid configurations still fail. Ordinary bundle loading
and production decoders do not perform this conversion.

This is a synthetic trusted-context migration for the existing pruned-subtree,
message-queue and storage-stat regressions. It does not authenticate a rewritten
historical chain or qualify a native full-block replay. Original trace files stay
unchanged. This conversion preserves the proof-coverage assertions. The separate
proof-selection profile above derives the historical root count from native
per-account decisions; the size-limit conversion does not supply that evidence.


### Workchain local-role fixture context

The local-role validator test creates MC1 anew. Its two frozen negative WC
candidates refer to historical MC1 hashes, so the test explicitly rebinds only
`BlockInfo.master_ref` to the generated MC1 and recomputes the candidate ID.
The original fixture files and WC body references remain unchanged. Unknown
engine and nonzero TVM mode still require their specific rejection; a freshly
collated TVM candidate must validate successfully in the same test.

Export the test context from the node test directory and verify it independently:

```sh
cd rtos
RTOS_EXECUTION_CONTEXT_EXPORT=/absolute/path/context \
  cargo test -j32 --release -p rtos --features ci_run --bin rtos \
  collator_test_bundle::workchain_execution_callers::execution_validator_local_role -- --exact
cd ..
python3 ci/conformance/workchain_context_reference.py \
  --cpp-build /absolute/path/native-build \
  --export /absolute/path/context --out /absolute/path/new-verification-directory
```

Leave `RTOS_EXECUTION_EXPORT` unset for this validation run. The native probe
uses the clean source revision pinned by `REFERENCE`, rebuilds its libraries,
reconstructs the migrated WC root independently, checks the MC state-update
hash, and requires the native registry's exact unknown-engine/nonzero-mode
errors. A TVM descriptor control must resolve. Each of the eight input files is
limited to 4 MiB; two native processes each have a 60-second deadline. This is
an offline context and registry control, not native validation of the complete
historical WC block or proof of chain authenticity. Raw exports and build logs
stay outside Git; `receipt.json` records their hashes and the commands.


### Truncated TL payloads and download limits

The bounded download test separates malformed input from complete over-budget
input. A declared 0x7fffff-byte proof with no payload must return the slice
parser's `UnexpectedEof` before allocation-budget checks. A complete real
`DataFull` reply is also decoded with a TL budget one byte below its proof
length and must return the exact `DecodeLimitExceeded` limit/actual values.
The peer download then repeats the complete reply with its proof BOC limit
one byte too small and must refuse after exactly one query. Cell-count and
depth refusals and a successful complete-reply control remain in the same test.

```sh
cd rtos
NODE_SKIP_TEST_LOGS=yes cargo test -j32 --release -p rtos --features ci_run \
  --bin rtos bounded_download_e2e_ -- --test-threads=1
```

This follows the native `TlParser::fetch_string` payload-length check before
returning a string. It changes test expectations, with no decoder or downloader
behavior change. The direct TL control isolates its allocation budget from the
transport's separate whole-response cap.

### Native public history for GC fixture migration

Generate a bounded four-height MC/WC history with three native public test keys:

```sh
python3 ci/conformance/generate_gc_history_fixture.py \
  --cpp-build /tos/build/rtos-conformance-latest-5af405d \
  --target-dir /tos/worktrees/rtos/cpp-alignment/target \
  --out /datax/rtos-conformance/native-gc-history
```

The output directory must be empty. `node_recovery_fixture --gc-history-keys`
accepts exactly three ML-DSA-44 public keys from a file capped at 16 KiB, including
concurrent growth. It creates MC/WC 1–4, a key block at MC 3 and a nonzero parent
for target MC 2. The frozen output is
`rtos/src/full_node/finality/testdata/native-gc-history.json`.

The pinned C++ helper's separate `--check-history` mode binds each MC transition
input to its old state, and each WC master reference to the actual governing MC
block and resulting state. It recomputes subsets, sessions and vote preimages;
24 native final signatures are checked independently. Wrong state, governing
block and candidate controls refuse. The 16 KiB key boundary, wrong key length,
2 MiB native token cap and the original two publication contexts are exercised.
Native signing is randomized: retain the generated bytes and receipt.

This prepares authenticated synthetic inputs; it does not integrate the fixture
into Engine/GC tests or qualify whole-block transaction execution, actual cold
boot, recovery or soak. Four heights do not satisfy the production floor
advancement lag of 1024 blocks. Tests must establish a valid persisted/startup floor
or provide sufficient authenticated history; the floor policy must not be
relaxed. Original source/repair failures remain failures until those tests run.
