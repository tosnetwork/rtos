# RTOS

RTOS is the TOS network's Rust node project, derived from
[RSquad/ton-rust-node](https://github.com/RSquad/ton-rust-node).

This checkout currently contains the upstream node with RTOS project, crate,
binary, and deployment names. TOS protocol adaptation and validator compatibility
have not yet been completed or validated. The inherited network examples and
fixtures describe the upstream network; they are not TOS deployment configurations.

## Source Code

The node source code is available under the [GNU General Public License v3.0](LICENSE). The Cargo workspace and build files are at the repository root.

## Crates

| Crate | Description |
|---|---|
| `rtos` | Node binary and library in `rtos/` |
| `adnl` | ADNL/RLDP/Overlay/DHT protocol stack |
| `rtos_block` | Blockchain data types in `block/` |
| `rtos_block_json` | JSON serialization in `block-json/` |
| `rtos_vm` | TVM in `vm/` |
| `rtos_executor` | Transaction executor in `executor/` |
| `rtos_assembler` | TVM assembler/disassembler in `assembler/` |
| `rtos_api`, `rtos_tl_codegen` | TL schema types and codegen in `tl/` |
| `emulator` | TVM emulator C-compatible library |
| `rtosctl` | rtosctl — node management CLI |
| `secrets-vault` | Cryptographic key/secrets management |

## Building

Run from the repository root, using the pinned toolchain:

```bash
cargo build --release --locked --bin rtos --bin rtosctl
```

Executables are written to `target/release/rtos` and `target/release/rtosctl`.
Linux builds require a C/C++ toolchain, Clang/libclang, pkg-config, OpenSSL,
zstd, and the native dependencies used by RocksDB.

### Running tests

```
cargo test --release --package catchain -- --nocapture --test-threads=1
cargo test --release --package storage -- --nocapture --test-threads=1
cargo test --release --package validator_session -- --nocapture --test-threads=1
cargo test --release -- --nocapture --test-threads=1
```

## Documentation

- [Release guidelines](RELEASE.md) — versioning, branching, and release process
- [Naming and upstream provenance](https://github.com/tosnetwork/memo/blob/main/rtos/renaming.md) — package and path mapping

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).
Original RSquad, EverX, and other authors' copyright and component
license notices are retained. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
