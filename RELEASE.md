# Release Guidelines

## Versioning

This project follows [Semantic Versioning](https://semver.org/): `MAJOR.MINOR.PATCH`.

Version tags include an artifact prefix and `v`: `rtos/v1.2.0`, `rtosctl/v0.3.0`.
A network qualifier may be appended as a pre-release suffix: `rtos/v0.1.2-mainnet`.

Each artifact is versioned independently.

| Artifact       | Tag format                | Examples                                  |
|----------------|---------------------------|-------------------------------------------|
| Node           | `rtos/v<semver>`          | `rtos/v1.2.0`, `rtos/v0.1.2-mainnet`     |
| rtosctl        | `rtosctl/v<semver>`       | `rtosctl/v0.3.0`                          |

## Commits

[Conventional Commits](https://www.conventionalcommits.org/): `type(scope): short description`

**Types:** `feat`, `fix`, `docs`, `chore`, `refactor`, `test`, `ci`

**Scopes:** `rtosctl`, `rtos`

## Branches

| Branch              | Purpose                                                              |
|---------------------|----------------------------------------------------------------------|
| `main`            | Production-ready code. All final release tags live here.             |
| `release/<artifact>/<version>` | Release branch. Features and changes are merged here, then the branch is merged into `main` for release. |
| `hotfix/<version>`  | Urgent fix for a previously released version. Branched off the relevant release tag. |

This is a monorepo with independent release cycles for each product (node, rtosctl). Release branches are product-scoped:

- `release/rtos/v0.2.0-mainnet`
- `release/rtosctl/v0.3.0`

## Release Process

### 1. Create release branch

Branch off `main`:

```bash
git checkout main && git pull
git checkout -b release/<artifact>/v<version>
```

### 2. Develop on the release branch

Merge feature branches and fixes into the release branch. This is where all changes for the release are collected.

### 3. Test with RC tags (optional)

Tag release candidates **only from the release branch** to trigger CI:

```bash
git tag <artifact>/v<version>-rc.1
git push origin <artifact>/v<version>-rc.1
```

CI builds and publishes the RC automatically. RC releases are marked as **Pre-release** on GitHub.

> **Internal/test builds:** If you need to build an image for testing outside of a release branch, use the `alpha` or `beta` pre-release suffix: `<artifact>/v<version>-alpha.1`. These builds are strictly internal — never distribute or deploy them to production.

### 4. Open PR into main

When the release is ready, open a PR from the release branch into `main`:
- **PR title:** `release/<artifact>:v<version>` (e.g. `release/rtosctl:v0.3.0`)
- **PR body:** changelog entry (without the `## [version]` header)

### 5. Merge into main

Squash-merge the PR:

```bash
gh pr merge <N> --squash --admin
```

### 6. Tag final release

```bash
git checkout main && git pull
git tag <artifact>/v<version>
git push origin <artifact>/v<version>
```

### 7. CI publishes automatically

CI triggers on the tag and handles everything:
- Builds artifacts (containers and binaries)
- Pushes to registries
- Creates a GitHub Release

### 8. Finalize GitHub Release

CI creates the release, but the body may need updating. Edit with the changelog entry:

```bash
gh release edit <tag> -F- <<< '<changelog entry>'
```

For **node releases only**, Latest is default. All other artifacts:

```bash
gh release edit <tag> --latest=false
```

Verify:

```bash
gh release list   # only node release should be Latest
```

### 9. Cleanup

```bash
git branch -d release/<artifact>/v<version>
git push origin --delete release/<artifact>/v<version>
```

## CI Pipelines

### On Node Tags (`rtos/v*`)

1. Build container image from `Dockerfile`.
2. Push to `ghcr.io/tosnetwork/rtos/rtos`.
3. Create GitHub Release.

| Git Tag                 | Docker Tags                | GitHub Release |
|-------------------------|----------------------------|----------------|
| `rtos/v1.2.0-mainnet`  | `v1.2.0-mainnet`, `sha-*`  | Latest         |
| `rtos/v1.2.0-rc.1`     | `v1.2.0-rc.1`, `sha-*`     | Pre-release    |

### On rtosctl Tags (`rtosctl/v*`)

1. Build cross-platform binaries (linux/amd64, linux/arm64, darwin/arm64, windows/amd64).
2. Build container image from `Dockerfile.rtosctl`.
3. Push image to `ghcr.io/tosnetwork/rtos/rtosctl`.
4. Create GitHub Release with binaries attached.

| Git Tag              | Docker Tags                    | Binaries                | GitHub Release  |
|----------------------|--------------------------------|-------------------------|-----------------|
| `rtosctl/v0.3.0`    | `v0.3.0`, `latest`, `sha-*`   | linux, darwin, windows  | `latest: false` |
| `rtosctl/v0.3.0-rc.1` | `v0.3.0-rc.1`, `sha-*`      | linux, darwin, windows  | Pre-release     |

### On Pull Requests

CI runs on PRs targeting `main` or `release/**`:

- `audit` — cargo security audit
- `fmt` — formatting check (nightly rustfmt)
- `check` — clippy + cargo check
- `tests` — cargo tests
- `tests-net` — network integration tests

## Registries

| Artifact | Registry |
|----------|----------|
| Node image | `ghcr.io/tosnetwork/rtos/rtos:<tag>` |
| rtosctl image | `ghcr.io/tosnetwork/rtos/rtosctl:<tag>` |

## GitHub Releases

- Only **node** releases on `main` are marked as **Latest**.
- All other releases (rtosctl) use `make_latest: false`.
- Release candidates are marked as **Pre-release**.
- Hotfixes for older versions use `make_latest: false`.

## Changelogs

| Changelog | Artifact | Versioned by |
|-----------|----------|--------------|
| `CHANGELOG.md` | Node | `rtos/v*` tags |
| `rtosctl/CHANGELOG.md` | rtosctl | `rtosctl/v*` tags |

All changelogs use [Keep a Changelog](https://keepachangelog.com/) format.

## Hotfixes

### Hotfix (latest version)

Create a feature branch from `main`, fix, merge via PR, tag on `main`.

### Hotfix (older version)

Create `hotfix/<version>` from the relevant release tag. Fix and tag on that
branch. Cherry-pick into `main` if applicable. GitHub Release is published
with `make_latest: false`.
