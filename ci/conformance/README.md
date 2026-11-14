# Shared conformance target

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
Together the original268 and added122 contexts yield390 equal, zero mismatches,
refusals or skips. Param29 options expose the full uint64
height-coefficient product while committing its low32 wire bits; the block-hash
flag follows the version2 boundary. A separate raw probe pins a product above
uint32; it is outside the shared fixture schema and is not counted in390.
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
field is outside the shared schema and is excluded from the390-case corpus.
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
