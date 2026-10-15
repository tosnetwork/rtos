# Offline archive recovery precheck

Build with `cargo build -p rtos --bin archive_recovery_check`.
Stop the node and keep it stopped through the check and any downgrade. Run:

```sh
archive_recovery_check --node-config /path/to/config.json --node-working-directory /actual/node/working-directory
```

If the node used an explicit database-root override, supply the same effective
path with `--db-root-override /path/to/database-root`. Otherwise the checker uses
`internal_db_path` from the JSON configuration, defaulting to `node_db`. Relative
database and epoch paths resolve against the supplied working directory.

Exit0 reports the complete inspected provider inventory and the configuration
SHA256. It means this check found no unresolved recovery marker in that inventory;
it is not a database integrity certificate or a guarantee of compatibility with
an arbitrary older binary. A nonzero exit is inconclusive or identifies pending
state. The utility never repairs, truncates, deletes or clears an operation.
Resolve pending state with the appropriate current implementation before downgrade.

The check includes the main node database, ordinary epoch archive providers,
key archives in the main database, orphan archive status families and known
staging paths. Unknown status keys are refused. Missing/inaccessible providers,
ambiguous epoch ranges and symlinked inputs are refused rather than skipped.
It restores the native counter merge operator before strict WAL replay.

Linux advisory read locks remain held on existing provider LOCK files during
inspection. Concurrent invocations inside one process are serialized because
POSIX file locks are process-owned. These locks do not control arbitrary raw
filesystem mutations or an operator bypassing this utility. The tool additionally
checks path identities and inventories, and requires an offline deployment.

The rocksdb Rust wrapper attempts mkdir on an existing database directory even
for read-only open. Verified calls return EEXIST; they are reported separately
in native test evidence. The check performs no successful target modification.
