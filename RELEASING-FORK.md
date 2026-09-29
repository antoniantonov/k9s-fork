# Publishing a K9s Fork Release

This guide describes how to build and publish a release from
`antoniantonov/k9s-fork` with downloadable artifacts similar to the releases in
`derailed/k9s`.

## Where to publish

| Artifact | Publish location |
|---|---|
| Git tag and downloadable binaries/packages | <https://github.com/antoniantonov/k9s-fork/releases> |
| Optional container image | Prefer `ghcr.io/antoniantonov/k9s-fork:<version>` |
| Optional Homebrew formula | A separate tap owned by the fork, such as `antoniantonov/homebrew-k9s-fork` |

Do not publish fork releases to `derailed/k9s`. The current GitHub account has
administrative access to `antoniantonov/k9s-fork` but read-only access to
`derailed/k9s`.

At the time this guide was written, the fork had no GitHub releases or remote
tags. Its first release will appear at:

<https://github.com/antoniantonov/k9s-fork/releases>

## What the repositories currently provide

The fork and upstream repository currently have identical `.goreleaser.yml`
and `Makefile` files.

The checked-in GoReleaser v2 configuration produces:

- Linux binaries for amd64, arm64, armv7, ppc64le, and s390x;
- macOS binaries for amd64 and arm64;
- Windows binaries for amd64 and arm64;
- FreeBSD binaries for amd64 and arm64;
- `.tar.gz` archives and Windows `.zip` archives;
- Linux `.deb`, `.rpm`, and `.apk` packages;
- `checksums.sha256`;
- a Syft SBOM JSON file for each archive.

This matches the shape of the assets attached to upstream releases.

Neither repository currently has a GitHub Actions release workflow. The
workflows in `.github/workflows/` run tests, linting, and repository
maintenance only. Publishing is therefore a manual GoReleaser process unless a
release workflow is added later.

## Important fork-specific issues

### GoReleaser infers the release repository from `origin`

The current `.goreleaser.yml` does not explicitly set `release.github`.
GoReleaser therefore extracts the destination from the `origin` remote.

Before publishing, verify:

```shell
git remote get-url origin
```

It must point to:

```text
https://github.com/antoniantonov/k9s-fork.git
```

For a long-term fork, make the destination explicit in `.goreleaser.yml`:

```yaml
release:
  github:
    owner: antoniantonov
    name: k9s-fork
  prerelease: auto
```

The repository currently has `release.prerelease: false`. If fork versions use
a SemVer prerelease suffix, change this to `auto` or mark the GitHub release as
a prerelease when publishing the draft.

### The Homebrew destination belongs to upstream

The current configuration publishes a formula to:

```yaml
brews:
  - repository:
      owner: derailed
      name: homebrew-k9s
```

The fork owner cannot write there. For a GitHub-only release, skip this
publisher:

```shell
goreleaser release ... --skip=homebrew
```

To publish Homebrew later, create a fork-owned tap and change the repository in
the GoReleaser configuration. The existing `brews` feature is deprecated in
recent GoReleaser v2 releases, so also plan a migration to the currently
recommended Homebrew publisher before relying on it.

### Docker publication is separate

GoReleaser does not build a container image with the current configuration.
The `Makefile` has separate `imgx` and `pushx` targets.

The default is dangerous for a fork:

```make
IMG_NAME := derailed/k9s
```

Always override `IMG_NAME`; never run the default `pushx` target against an
upstream-owned image name.

### Package metadata still identifies upstream

The Go module path remains `github.com/derailed/k9s`, which is expected for a
source-compatible fork and is used by the linker flags. The GoReleaser
configuration also contains upstream maintainer, homepage, and Homebrew
metadata. Decide whether to keep or replace that metadata before a public fork
release.

## Required tools and access

Install and pin:

- the Go version required by `go.mod`;
- GoReleaser v2;
- Syft, because `sboms` uses the external `syft` executable;
- GitHub CLI (`gh`);
- Git;
- Docker with Buildx only if publishing a container image.

Check the tools:

```shell
go version
goreleaser --version
syft version
gh --version
git --version
```

Run:

```shell
goreleaser healthcheck
gh auth status
```

GoReleaser's official GitHub documentation requires a token supplied through
`GITHUB_TOKEN`. A classic token needs the `repo` scope. A fine-grained token
must be allowed to write repository contents/releases in this fork. Container
publication to GHCR additionally needs package write access.

Never commit, print, or place a token in a command history file.

## Version policy

Choose the version deliberately before creating a tag.

- Use a valid SemVer tag beginning with `v`.
- Do not reuse an upstream tag in a way that makes a fork build appear to be an
  official upstream build.
- A suffix that identifies the fork or feature line is clearer than an
  upstream-looking stable version.
- Never move or replace a tag after a release has been published. Publish a new
  version to correct a bad release.

The commands below use `vX.Y.Z-fork.N` as a placeholder. Replace it with the
approved version; do not run the placeholder literally.

```shell
export VERSION=vX.Y.Z-fork.N
export REPO=antoniantonov/k9s-fork
```

Confirm that the version is unused:

```shell
git fetch origin --tags
git ls-remote --tags origin "refs/tags/${VERSION}"
gh release view "${VERSION}" --repo "${REPO}"
```

Both lookups should report that nothing exists.

## Recommended manual release process

### 1. Select and test the exact source commit

Release only from a clean, reviewed commit on `master`:

```shell
git switch master
git pull --ff-only origin master
git status --short
git log -1 --oneline
```

The worktree must be clean.

Run the repository validation:

```shell
go test ./...
```

Run any feature-specific integration suite required by the changes being
released.

### 2. Prepare release metadata

Upstream release commits normally update:

- `Makefile` `VERSION`;
- `snap/snapcraft.yaml` `version` when Snap publication is relevant;
- a release-notes file such as
  `change_logs/release_vX.Y.Z-fork.N.md`;
- occasionally README version or contributor information.

For the fork, prepare these changes in a reviewed release PR and merge it before
tagging. This is safer than creating an unmerged release-only commit.

The `Makefile` version controls normal `make build` and Docker image version
metadata. GoReleaser itself takes the release version from the Git tag.

If Snap is not being published, do not claim that it was published. The current
Snap configuration points its source at the upstream repository and requires
separate Snap Store credentials and ownership.

### 3. Perform a local non-publishing build

From the clean release commit:

```shell
goreleaser healthcheck
goreleaser release --snapshot --clean
```

This builds locally without publishing. Inspect `dist/` and confirm that the
expected archives, packages, checksums, and SBOMs were produced.

Also verify a normal local binary:

```shell
make build VERSION="${VERSION}"
./execs/k9s version
```

### 4. Create and push an annotated tag

Tag the exact tested commit:

```shell
git tag -a "${VERSION}" -m "release ${VERSION}"
git describe --exact-match --tags HEAD
git push origin "${VERSION}"
```

The upstream project also uses annotated tags. Its latest inspected release,
`v0.51.0`, used an annotated tag named `v0.51.0`.

### 5. Publish a draft GitHub Release with GoReleaser

Use the token already authenticated by GitHub CLI without printing it:

```shell
export GITHUB_TOKEN="$(gh auth token)"
```

Publish as a draft first and skip the upstream Homebrew destination:

```shell
goreleaser release \
  --clean \
  --draft \
  --skip=homebrew \
  --release-notes "change_logs/release_${VERSION}.md"
```

If no custom release-notes file is supplied, GoReleaser generates a changelog
from commits since the previous tag, excluding commits matched by the filters
in `.goreleaser.yml`.

Remove the token from the shell when finished:

```shell
unset GITHUB_TOKEN
```

The draft should now be visible to repository administrators at:

<https://github.com/antoniantonov/k9s-fork/releases>

### 6. Verify the draft

Inspect its metadata and asset list:

```shell
gh release view "${VERSION}" \
  --repo "${REPO}" \
  --json url,name,tagName,isDraft,isPrerelease,assets
```

Download the draft assets to a temporary directory and validate:

- `checksums.sha256` matches every downloadable artifact;
- macOS archives contain the expected amd64 and arm64 binaries;
- Linux archives and packages cover the configured architectures;
- Windows archives contain the expected executable;
- SBOM files exist;
- `k9s version` reports the intended tag and commit;
- release notes clearly state that this is a fork build.

Do not publish if any artifact is missing or identifies the wrong commit.

### 7. Publish the draft

For a normal fork release:

```shell
gh release edit "${VERSION}" \
  --repo "${REPO}" \
  --draft=false
```

For a SemVer prerelease/fork suffix, mark it as a prerelease:

```shell
gh release edit "${VERSION}" \
  --repo "${REPO}" \
  --draft=false \
  --prerelease
```

The public URL will be:

```text
https://github.com/antoniantonov/k9s-fork/releases/tag/<VERSION>
```

## Optional: publish a multi-platform container image to GHCR

GitHub Releases and container registries are independent. Publishing the
release assets does not publish a Docker image.

Create a token with package write access, then authenticate:

```shell
export GHCR_TOKEN=...
printf '%s' "${GHCR_TOKEN}" |
  docker login ghcr.io --username antoniantonov --password-stdin
```

Push the versioned amd64/arm64 image with the existing Makefile:

```shell
make pushx \
  IMG_NAME=ghcr.io/antoniantonov/k9s-fork \
  VERSION="${VERSION}" \
  BUILD_PLATFORMS=linux/amd64,linux/arm64
```

Then make the resulting GitHub package public if it is not already public.
Verify its manifest:

```shell
docker buildx imagetools inspect \
  "ghcr.io/antoniantonov/k9s-fork:${VERSION}"
```

Do not publish to `derailed/k9s` on Docker Hub or another upstream-owned
registry.

## Optional: automate future releases

A future `.github/workflows/release.yml` can run GoReleaser for tags, but no
such workflow exists today.

A safe workflow should:

1. trigger only for approved `v*` tags or a protected manual dispatch;
2. use `permissions: contents: write`;
3. check out the complete Git history and tags;
4. install the Go version from `go.mod`;
5. install a pinned GoReleaser v2 and Syft version;
6. run tests before publishing;
7. run GoReleaser with `--clean` and `--skip=homebrew`, unless a fork-owned tap
   is configured;
8. publish a draft first for manual inspection;
9. use a separate secret with access to any cross-repository package or
   Homebrew destination.

The default GitHub Actions token cannot publish a formula to a different
Homebrew repository unless that destination is separately authorized.

## Alternative: build with GoReleaser and create the release with `gh`

If GoReleaser publishing is intentionally disabled, use:

```shell
goreleaser release --clean --skip=publish
```

Then create a draft with `gh release create`, explicitly listing the validated
files from `dist/`:

```shell
gh release create "${VERSION}" <validated-assets...> \
  --repo "${REPO}" \
  --verify-tag \
  --draft \
  --title "${VERSION}" \
  --notes-file "change_logs/release_${VERSION}.md"
```

Do not upload every file in `dist/` blindly. Use GoReleaser's
`dist/artifacts.json` and the expected upstream asset list to select only
release artifacts.

## What upstream currently does

The inspected upstream release process is manual rather than Actions-driven:

- the latest release is `v0.51.0`;
- an upstream release commit updated `Makefile`,
  `snap/snapcraft.yaml`, README content, and
  `change_logs/release_v0.51.0.md`;
- an annotated tag points to that release commit;
- the GitHub release uses the release-notes file;
- GoReleaser-style archives, packages, checksums, and SBOM files are attached;
- no release workflow is present in `.github/workflows/`.

The `v0.51.0` release commit is not an ancestor of the current upstream
`master`; the histories have diverged since the tag. That detached
release-commit pattern should not be copied unless there is a specific reason.
A reviewed release metadata commit merged into the fork's `master`, followed
by a tag on the tested commit, is easier to audit and reproduce.

## References

- Fork releases: <https://github.com/antoniantonov/k9s-fork/releases>
- Upstream releases: <https://github.com/derailed/k9s/releases>
- Repository release configuration: `.goreleaser.yml`
- Local and container build targets: `Makefile`
- Container build definition: `Dockerfile`
- Upstream-style release notes: `change_logs/`
- GoReleaser quick start:
  <https://goreleaser.com/getting-started/quick-start/>
- GoReleaser GitHub publishing:
  <https://goreleaser.com/customization/publish/scm/github/>
- GoReleaser release configuration:
  <https://goreleaser.com/customization/publish/scm/>
- GitHub CLI release creation:
  <https://cli.github.com/manual/gh_release_create>
