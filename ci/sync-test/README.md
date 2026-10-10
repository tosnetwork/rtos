# Sync-test helpers

This directory contains inherited helpers for an externally managed sync test.
The repository does not provide a deployment chart or a sync-test deployment
workflow.

- `gen-node-config.sh <ip>` generates a node configuration with fresh test keys.
  Its output contains private key material and belongs in the isolated test
  environment.
- `watcher.sh` runs in an Alpine sidecar, polls the node's Prometheus metrics,
  and reports the result as a GitHub commit status. It requires `METRICS_PORT`,
  `SYNC_TIMEOUT`, `NETWORK`, `GITHUB_TOKEN`, `GITHUB_SHA`, and `GITHUB_REPO`.
- `values.yaml` is an inherited deployment configuration sample. It requires
  separately maintained deployment tooling; it is not a runnable deployment
  definition on its own.

Build the node image from the repository root using `Dockerfile`. Supply the
network configuration, volumes, credentials, and deployment lifecycle through
external test infrastructure before using these helpers.
