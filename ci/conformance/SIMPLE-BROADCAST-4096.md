# Simple broadcast limit alignment (2026-11-24)

WIP: aligns TOS `80c98557dd2f1c244257057581bbb813989ec3e3`.
TOS `7e61bf80e2f6cd1f07c2eb6dd4e9a3bcf034b885` uses 4096 bytes;
TON `99143587` retains 768. This is a TOS-specific change.

The production sender and certificate default flags share
`MAX_SIMPLE_BROADCAST_SIZE`. The network adapter uses the same limit for simple
payloads and retains its separate bounded FEC fixture input.

Evidence is retained at `/datax/rtos-conformance/2026-11-24-resume/`:

- `net-baseline-comparison.json`: latest three TOS vector families, 73 inputs,
  2 differences before the change; `net-fixed-comparison.json`: 73 equal.
- `privacy-replay-summary.json`: 3843 reconstructed certificate inputs, complete
  C++/Rust effects equal. Native source is `6224453b5`, whose difference from
  latest TOS is two operational scripts, with identical network/reference code.
- `extract-privacy-contexts.py`, `replay-privacy-contexts.py` and
  `refill-certificate-records.py`: reconstruct and refill T/C records from native
  outputs, including exact preimages, normalization and verdicts.
- `regenerate-console.py` and `console-native-signatures.json`: native signing
  verifies old key/encoding correspondence before generating updated Q signatures.
  Q verdicts are then checked through native `overlay_certificate`.
- `refill-eligibility.py`, `eligibility-native-primitives.json`: fresh-verifier E
  records compose native privacy-rule checks, signing and certificate checks in
  `overlay/overlay.cpp:822-865` order. This is a composition of native primitives,
  not a direct actor/cache/rate-limiter replay. No stateful qualification is added.
- `privacy-regenerated-tests-6.log`: 30 privacy tests pass. Earlier failed runs
  remain retained, including generator flag and verdict spelling corrections.

The relay normalization test now uses limit+1 to preserve its FEC-default-flag
purpose. Full ADNL validation, independent review and integration remain pending.
The global REFERENCE pin is unchanged until the broader latest-TOS delta is audited.
