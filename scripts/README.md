# scripts/

Developer scripts for running K9s in Docker against a local kind (Kubernetes IN
Docker) cluster.

Prerequisites: `docker` and `kubectl`. `go` is only needed if the `kind` CLI is
missing and has to be installed automatically.

## docker-build-and-run.sh

Builds a fresh, auto-versioned local k9s image, removes older k9s images and
containers, prints the exact launch command, and starts k9s in Docker.

```shell
./scripts/docker-build-and-run.sh
```

| Flag | Effect |
| --- | --- |
| `--build-only` | Build and print the run command without starting k9s. |
| `--kubeconfig PATH` | Target a cluster other than the local kind one. The file is mounted read-only at `/root/.kube/config`. Skips all kind checks. |
| `--test-workloads` | Seed the NetworkPolicy demo topology into the local kind cluster first. Rejected together with `--kubeconfig`. |
| `--yes`, `-y` | Answer yes to every prompt; never blocks on input. |
| `-h`, `--help` | Show help. |

Behaviour:

- **Without `--kubeconfig`** k9s runs against the local kind cluster. The script
  checks that the cluster's control-plane container is running and, when it is
  not, asks whether to start it via `install-kind.sh` (`--yes` accepts
  automatically). It then mounts the cluster's *internal* kubeconfig and joins
  the kind Docker network so the container can reach the API server.
- **With `--kubeconfig`** the kind checks, prompt and workload seeding are all
  skipped — useful for a remote cluster. The Docker network is only joined when
  the kubeconfig's current context is itself a local kind context.
  The image is a minimal Alpine carrying only `k9s` and `kubectl`, so
  kubeconfigs relying on `exec:` credential plugins (`aws`, `gcloud`, `az`, ...)
  or on certificate/key files given as host paths won't work; use embedded
  `*-data` fields or a static token instead.
- **`--test-workloads`** runs `netpol-demo-workloads.sh --check` first and only
  applies the topology when the check fails. It is refused alongside
  `--kubeconfig` so demo workloads never land in someone's real cluster.
- Non-interactive stdin without `--yes` fails with an actionable message instead
  of hanging.

Environment overrides: `IMAGE_NAME` (default `k9s`), `KIND_CLUSTER` (default
`k9s-netpol`), `KIND_NODE_IMAGE` (default `kindest/node:v1.34.0`),
`KIND_NETWORK`, `NPG_DEPLOYMENT` (default `api`), `NPG_NAMESPACE` (default
`netpol-demo-app`).

```shell
# Local kind, fully unattended, with the demo topology.
./scripts/docker-build-and-run.sh --test-workloads --yes

# Build the image only and print the launch command.
./scripts/docker-build-and-run.sh --build-only

# Point the containerised k9s at a remote cluster.
./scripts/docker-build-and-run.sh --kubeconfig ~/.kube/prod.yaml

# Build a differently named image.
IMAGE_NAME=my-k9s ./scripts/docker-build-and-run.sh --build-only
```

## install-kind.sh

Idempotently ensures the local kind cluster exists and is running. Reuses a
running cluster, restarts a stopped control-plane container, recreates the
cluster when kind metadata is stale, and creates it from scratch otherwise.
Installs the `kind` CLI with `go install sigs.k8s.io/kind@<version>` when it is
not on `PATH` (Linux and macOS).

```shell
./scripts/install-kind.sh            # ensure the cluster is up
./scripts/install-kind.sh --check    # report state only, no mutations
./scripts/install-kind.sh --delete   # delete the cluster and its kubeconfigs
```

Flags: `--cluster NAME` (default `k9s-netpol`), `--node-image REF` (default
`kindest/node:v1.34.0`), `--kind-version VER` (default `v0.32.0`),
`--check`/`--status`, `--delete`, `-h`/`--help`. Each also has a matching
environment variable.

On success it exports two kubeconfigs and waits for the node to be `Ready`:

- `.kube/<cluster>.kubeconfig` — for `kubectl` on the host
- `.kube/<cluster>.internal.kubeconfig` — for containers on the kind network

## netpol-demo-workloads.sh

Canonical location of the NetworkPolicy demo topology: namespaces, workloads and
policies covering every result state the K9s reachability view can render. It
bootstraps the kind cluster itself when needed.
`.github/skills/netpol-graph-testing/scripts/netpol-demo-workloads.sh` is a thin
delegate to this script.

```shell
./scripts/netpol-demo-workloads.sh                  # create/refresh the topology
./scripts/netpol-demo-workloads.sh --check          # verify only, no mutations
./scripts/netpol-demo-workloads.sh --delete         # remove the demo namespaces
./scripts/netpol-demo-workloads.sh --delete-cluster # remove the kind cluster
./scripts/netpol-demo-workloads.sh --help           # all options
```
