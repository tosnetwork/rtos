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
