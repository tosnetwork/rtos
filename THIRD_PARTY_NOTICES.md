# Upstream attribution

RTOS incorporates source from this upstream repository:
https://github.com/RSquad/ton-rust-node

Original copyright statements from RSquad Blockchain Lab, EverX, and other
contributors remain in their respective source files. Imported changelogs
retain their historical records with updated project terminology. Renaming the
project does not imply endorsement by the upstream authors.

The root GPLv3 license is retained. Component licenses remain applicable,
including the Apache-2.0 licenses in `common` and `adnl/raptorq`, and
the MIT license in `lockfree`. Dependency licenses and authorship remain
with their respective packages; this document does not replace those notices.

On 2026-10-10, the RTOS project changed project identifiers, selected Cargo
package names and imports, executable names, paths, build and deployment
references, documentation, logging targets, and metric prefixes. These are
RTOS modifications to the imported source. The [migration record](https://github.com/tosnetwork/memo/blob/main/rtos/renaming.md)
is maintained in the memo repository.

`block/src/pq_bytes.rs` and `block/tests/data/pq-bytes-vectors.txt` incorporate
protocol code and test data from `tosnetwork/tos` at
`8f083dc06bff16705710a01de15eb3123d5d696b`. The code retains its copyright:
Copyright 2026 TOS Blockchain Teams, LGPL-2.0-or-later. The license text is in
[LICENSES/LGPL-2.0.txt](LICENSES/LGPL-2.0.txt). RTOS adjusts the fixture location
for independent workspace builds. Detailed import provenance is maintained in
[memo](https://github.com/tosnetwork/memo/blob/main/rtos/source-imports.json).

`block/src/validators.rs` and `block/src/tests/test_validators.rs` merge descriptor,
identity, subset commitment and reference-test changes from the same fixed source
commit. Their GPLv3 headers and EverX/RSquad copyright notices are retained.
The `validator-descr-*` and `validator-set-*` files in `block/tests/data` are
unmodified public reference fixtures from its `test/pq-native` directory, covered
by that repository's GPLv3 license. File digests and merge details are recorded
in the memo import manifest linked above.

`tl/rtos_api/src/session_identity.rs` adapts the canonical session derivation
and member mapping from the same fixed reference commit's
`crypto/block/validator-session-id.cpp` and `validator-session-members.cpp`.
The source retains the 2026 contributor copyright and LGPL-2.0-or-later notice.
The two session fixtures under `tl/rtos_api/tests/data` are copied unchanged
from that commit's `test/pq-native` directory. Schema and import digests are
recorded in the memo manifest.

`block/src/signature.rs` merges the persisted PQ block-signature carrier from
that fixed commit's `tosctl/src/block/src/signature.rs`, retaining its GPLv3
header and original copyright notices. The corresponding vector test retains
its 2026 contributor copyright and LGPL-2.0-or-later notice. Its additional
400-signer regression adapts `test/pq-native/block-signature-carrier-common.h`
under the same license and checks the fixed measurement digest. The fixture
`block/tests/data/pq-block-signature-vectors.txt` is copied unchanged from
`test/pq-native`. Parsing these carriers is distinct from authenticating finality.

`pq-crypto` provides a Rust verification interface under LGPL-2.0-or-later,
with its license text included in that crate. The portable C compilation tree
in `pq-crypto/native/mldsa-native` is copied unchanged from the fixed reference
commit above, which pins mldsa-native v2.0.0 at
`834a90d5e846ffa1e1611bd24e160bb2e9b86d35`. Its authorship, LICENSE and
RELICENSE.md are retained (Apache-2.0 OR ISC OR MIT). The verification build
configuration adapts the reference's LGPL-2.0-or-later configuration with an
RTOS symbol namespace. No C++ protocol verifier is included in this crate.

The ML-DSA test corpus includes public OpenSSL fixtures from the fixed
reference, NIST ACVP-Server vectors at `975de31eb83d87039ec88934fdc47d8c312b892d`,
and C2SP Wycheproof vectors at `3fa63dd0344abb611f1fb1d77e119938603ea230`.
RTOS acknowledges the National Institute of Standards and Technology as the
source of the ACVP material. On 2026-10-10, RTOS extracted the pure ML-DSA-44
external-interface cases into TSV and classified inputs outside the bounded
verification profile as malformed. The complete NIST notice and Wycheproof
Apache-2.0 license are retained beside the fixtures. Public context-binding
fixtures use explicitly public deterministic test seeds. Import digests,
corpus selection and shared-backend limitations are recorded in memo.

`tl/rtos_api/src/pq_finality.rs` adapts final-vote preimage and governing
context rules from the fixed reference's `crypto/block/signature-set.cpp`
and `validator/pq-finality-verification.h` under LGPL-2.0-or-later. The
contributor notice is retained. Its public deterministic test fixtures use
seeds 0xa0/0xa1 repeated 32 times with the same native test-signing backend;
they are not independent cryptographic or chain-authentication references.

`vm/src/executor/pq.rs` adapts the ML-DSA-44 instruction and canonical byte-chain
reader from the fixed reference's `tosctl/src/vm/src/executor/pq.rs`, retaining
its GPL-3.0-only contributor notice. RTOS uses the existing self-contained
`rtos_pq_crypto` backend rather than the reference VM's external build paths.
The assembler mnemonic and decoder follow the reference instruction F93100.
The VM differential fixture derives from the public crypto corpus acknowledged
above and public malformed-input scenarios; generation and reference build
provenance are recorded in memo. The transaction body fixtures use the same
public OpenSSL verification vector and a deliberately corrupted signature.
On 2026-10-10, RTOS encoded those public vectors as VM Cell BOCs, added malformed
structure and gas/version boundary cases, and recorded reference execution
outcomes. The ACVP notice and Wycheproof license are also retained beside the
VM fixture. NIST is acknowledged as the source of the ACVP material.
