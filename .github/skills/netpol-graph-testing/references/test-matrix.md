# NetworkPolicy reachability test matrix

Automated cases are in `scripts/k9s-tui-smoke.exp`; setup/build phases are in `scripts/run-tests.sh`.

## Harness phase matrix

| Phase/path | Coverage | Expected invariant |
|---|---|---|
| Cluster/workload setup | `ensure-cluster`, `ensure-workloads`, `--force-workloads` | `netpol-demo-workloads.sh --check` runs before population; original stale-native checks remain, and new labels/readiness/policy `spec`/`specs` are checked |
| Default Go validation | Full run | `go clean -cache -testcache` and `go test ./...` run before the scoped race suites |
| Branch-diff coverage | `coverage` | Committed branch and staged/unstaged/untracked production Go changes are at least 80% covered overall, and `internal/netpol/policy.go` is at least 80%; missing changed executable functions fail rather than shrinking the denominator |
| Cached image build | Default run | Tracked and untracked build sources affect the fingerprint; errors cannot reuse a cache; its tag is resolved and recorded as an immutable image ID |
| Clean image build | `--clean-image` / `--no-image-cache` | A unique tag is built with `docker build --pull --no-cache`; `.image-cache` and other local images are never fallback candidates |
| Exact-image TUI | Successful build, or `--only tui-tests --image REF` | The requested/built ref is resolved once and both the probe and Expect smoke run use that immutable image ID |
| Failed build isolation | Full or `--from build-image` run | TUI fails without consulting `.image-cache` or another local k9s image |
| Uncertainty sequencing | Last two `tui-tests` suites | Known fixtures first; identity and unsupported Cilium each get a unique owned policy and a fresh TUI process; cleanup and normal `--check` run after success/failure |
| Cleanup safety | `--delete`, `--probe ... --delete` | No implicit cluster bootstrap, no shared CRD deletion; conflicting check/delete flags are rejected before external commands; probes require exact ownership |
| Verdict accounting | Pure manifest + combined summary | Exactly 70 expected cases: 66 known, 2 identity, 2 unsupported; missing, duplicate, unexpected and failed verdicts fail |
| Offline harness regression tests | Explicit `go test ./.github/skills/netpol-graph-testing/diffcover` | Tests include shell stubs, fixture JSON/scoping, whole-file/procedure Tcl compilation, fresh row/port parsing, and summary reconciliation without live tools |

## Live TUI matrix

| Area | Coverage | Automated case | Notes |
|---|---|---|---|
| Launch commands | `:npg` opens with no direction rule selected, Effective Applicability for Ingress, and the exact `read-only graph` badge under the logo | `launch-npg-view` | `:netpolgraph`/`:npgraph` aliases covered by Go command tests/manual |
| Context launch | Shift-R from Pod/Deployment/Job/Namespace | Manual-only | Requires navigating source resource tables |
| `i` / `e` | Hide/show ingress and egress; both hidden placeholder | `direction-toggles-placeholder` | Verifies exact placeholder text |
| `m` | Global Rules ↔ Primitives projection; both panels switch and Effective Applicability stays hidden in Primitives mode | `rules-primitives-global-toggle` | Also used by open-resource cases |
| `p` | Primitive Kinds dialog; CIDR, Pod, Namespace, Deployment, Job; Apply/Cancel | `primitive-kinds-apply-cancel-zero` | Asserts both buttons are visible immediately at the smoke terminal's 50x200 size, without arrow-down scrolling; applies zero kinds and verifies the empty-kinds message |
| `o` | Open selected native Kubernetes primitive from Subject, Ingress, Egress, Applicability, and Primitive Details | `open-primitive-from-subject`, `open-primitive-from-direction-panels`, `open-primitive-from-applicability`, `enter-navigation-primitive-details` | Eligible states assert the exact `<o> Open Primitive` header hint and select by that hint rather than fixed row ordering; Rules direction rows open their NetworkPolicy |
| `o` disabled | Rule Details does not offer Open Primitive | `open-primitive-disabled-in-rule-details` | Rule Details remains open after lowercase `o` |
| `s` | Subject picker lists Pod, Deployment, Job, Namespace subjects | `subject-picker-kinds` | Selection of each subject kind is manual-only in TUI; topology supports all |
| `/` | Search Apply, Clear, Cancel | `search-apply-clear-cancel` | Uses `frontend` filter |
| `r` | Auto-refresh toggle; no manual refresh shortcut is advertised | `auto-refresh-toggle`, `launch-npg-view` | Asserts status text and absence of `Ctrl-R` |
| Rule type column | Rules show the full policy type between name and ports for native and custom policies | `rule-policy-type-column` | Verifies `NetworkPolicy`, `CiliumNetworkPolicy`, `CiliumClusterwideNetworkPolicy`, and `AuthorizationPolicy` against live rules and their expected ports |
| Custom policies | Original custom-only ingress fixtures plus isolated paired ingress/egress cases below | Original four custom cases and the new application inventory | New cases assert one fresh subject/direction/peer row with exact state and protocol/port set, not unrelated text tokens |
| `y` | YAML view of selected Kubernetes, Cilium, or Istio policy; hidden for synthetic rules and CIDR applicability | `yaml-view`, three custom-policy cases, `yaml-hidden-without-a-manifest` | Navigates to real rules by their advertised action |
| `Enter` | Rule selected → Applicability focus | `enter-navigation-rule-selected` | Headline behavior |
| `Enter` | No rule selected → Effective Applicability focus | `enter-navigation-effective-applicability` | Exercises Egress from the default no-selection state; the selected-rule case exercises Ingress |
| `Enter` | Primitives selected → details text focus | `enter-navigation-primitive-details` | Plain text detail pane; the case then verifies lowercase `o` opens the selected native primitive from Primitive Details |
| `Enter` | Applicability focused → remains in Applicability | `enter-stays-in-applicability` | Selects a native row through the Open Primitive hint and proves a second Enter does not navigate |
| `Ctrl-S` | **Set As Subject**: promote a supported Subject workload or applicability primitive to the graph subject | `ctrl-s-set-subject-from-subject-panel`, `ctrl-s-set-subject-from-applicability` | Promotes the selected API Pod from Subject, then independently filters Effective Applicability to `Deployment netpol-demo-web/frontend`; both cases assert focus returned to Subject through the renewed Ctrl-S hint |
| `Esc` | Clear selection before back navigation; back from opened primitive | `escape-clears-selection-before-back`, open-primitive cases | Dialog cancel also covered |
| `←` / `→` | Focus Ingress/Egress | `left-right-direction-focus` | Uses ANSI cursor sequences |
| `Tab` / `Shift-Tab` | Subject → Ingress → Ingress details → Ingress applicability → Egress → Egress details → Egress applicability focus ring | `tab-and-shift-tab-focus-ring` | Each direction owns the detail stops that follow it, so its applicability is reachable without passing through the other panel. Focus opens on Subject. Visual focus is indirectly asserted by stable repaint |
| Freeze/hang | Rapid arrows, refreshes, mode/direction/autorefresh toggles while scrolling | `freeze-hang-stress` | Sends `SIGQUIT` on repaint timeout |

## Original UX inventory retained in the known suite

These 28 original cases retain explicit verdicts:

`launch-npg-view`, `subject-picker-kinds`, `direction-toggles-placeholder`,
`rules-primitives-global-toggle`, `primitive-kinds-apply-cancel-zero`,
`search-apply-clear-cancel`, `tab-and-shift-tab-focus-ring`,
`left-right-direction-focus`, `enter-navigation-rule-selected`,
`enter-navigation-effective-applicability`,
`enter-navigation-primitive-details`,
`enter-stays-in-applicability`, `open-primitive-from-subject`,
`open-primitive-from-direction-panels`,
`open-primitive-from-applicability`,
`open-primitive-disabled-in-rule-details`, `yaml-view`,
`rule-policy-type-column`,
`cilium-network-policy-details-and-yaml`,
`cilium-clusterwide-policy-details-and-yaml`,
`istio-authorization-policy-details-and-yaml`,
`istio-authorization-effective-deny`,
`yaml-hidden-without-a-manifest`, `auto-refresh-toggle`,
`escape-clears-selection-before-back`,
`ctrl-s-set-subject-from-subject-panel`,
`ctrl-s-set-subject-from-applicability`, and
`freeze-hang-stress`.

## Isolated application inventory

This is Kubernetes-API/NPG behavior only. No Cilium/Istio installation, packet
listeners, ServiceEntry or dataplane tests are involved. The fixture library is
`scripts/netpol-edge-fixtures.sh`, sourced by the existing demo entry point.

Namespace suffixes below are relative to `${prefix}`:

- **S** = `edge-src`, namespace labels `netpol-scenario=${prefix}-edges`,
  `netpol-side=source`.
- **D** = `edge-dst`, same scenario label, `netpol-side=destination`.
- **O** = `edge-other`, same scenario label, `netpol-side=other`.

All new CCNP endpoint selectors include the scenario namespace-label constraint.
The 18 bare pods have stable names, one pod per subject, an `app` label and
`netpol-role`. `O/control` is otherwise unrestricted and distinct from every
empty-rule subject. New policies do not select the five original demo namespaces.

### Paired effective rows: 26 cases

Every row below produces **two exact case names**, `<stem>-ingress` and
`<stem>-egress`. Ingress opens the destination subject and asserts the source
peer; egress opens the source subject and asserts the destination peer.
Each case filters to one peer, checks the subject/direction/effective mode, and
compares the complete row state and port set. A mismatch/deny case cannot pass
using another row's `Disallowed` text or ports.

| Case stem | Source → destination | Labels/policy relationship | Exact state and ports, both perspectives |
|---|---|---|---|
| `cnp-overlap` | S/cnp-client → D/cnp-server | CNP source `specs[0]` permits TCP 8080/8081; CNP target permits 8081/8082 | Allowed; TCP/8081 |
| `cnp-mismatch` | S/cnp-client → D/cnp-mismatch | Source peer matches; destination ingress permits only TCP/9090 | Disallowed; no ports |
| `cnp-egress-deny` | S/cnp-client → D/cnp-denied | Target has `app=cnp-server,netpol-role=egress-denied`; source `specs[1]` denies TCP/8081 | Disallowed; no ports |
| `cnp-ingress-deny` | S/cnp-blocked → D/cnp-server | Source has `app=cnp-client,netpol-role=blocked`; destination CNP ingress deny removes TCP/8081 | Disallowed; no ports |
| `cnp-unmatched-source` | O/control → D/cnp-server | CNP ingress source selector/namespace does not match | Disallowed; no ports |
| `cnp-unmatched-target` | S/cnp-client → O/control | CNP egress target selector/namespace does not match | Disallowed; no ports |
| `ccnp-overlap` | S/ccnp-client → D/ccnp-server | CCNP source spec allows TCP 9090–9092; target spec allows 9091/9092 and denies 9091 | Allowed; TCP/9092 |
| `ccnp-egress-deny` | S/ccnp-client → D/ccnp-denied | Target role `egress-denied`; CCNP source deny removes 9091/9092 | Disallowed; no ports |
| `ccnp-unmatched-source` | O/control → D/ccnp-server | Scenario source namespace label and workload selector do not match | Disallowed; no ports |
| `ccnp-unmatched-target` | S/ccnp-client → O/control | Scenario destination namespace label and workload selector do not match | Disallowed; no ports |
| `istio-ports` | S/authz-client → D/authz-server | Native source/destination permit TCP 8080/8081, UDP 5353, SCTP 9000; identity-free destination ALLOW permits TCP 8080/8081 and DENY removes 8081 | Allowed; TCP/8080, UDP/5353, SCTP/9000 |
| `istio-no-tcp` | S/authz-client → D/authz-no-tcp | Same native permissions; destination ALLOW has empty `rules` | Allowed; UDP/5353, SCTP/9000; explicitly no TCP |
| `istio-empty-allow` | S/authz-client → D/authz-closed | TCP/8080-only destination network allow plus empty AuthorizationPolicy ALLOW | Disallowed; no ports |

### Empty Cilium allow rules: four required regression cases

| Exact case name | Subject/direction | Peer | Required result |
|---|---|---|---|
| `cnp-empty-rule-ingress` | S/cnp-empty, Ingress | O/control | Disallowed; no ports |
| `cnp-empty-rule-egress` | S/cnp-empty, Egress | O/control | Disallowed; no ports |
| `ccnp-empty-rule-ingress` | S/ccnp-empty, Ingress | O/control | Disallowed; no ports |
| `ccnp-empty-rule-egress` | S/ccnp-empty, Egress | O/control | Disallowed; no ports |

Each subject is selected for **both** `ingress: [{}]` and `egress: [{}]`.
These are Cilium default-deny forms, not native NetworkPolicy empty allow rules.
Do not replace them with explicit `ingressDeny`/`egressDeny` fixtures.

### Selected rule, type columns and navigation: six cases

Every case checks one name/full-type/ports row, selected rule action/API version,
`o` resource opening followed by the selected resource's YAML, return to the
same graph rule, direct graph `y`, then selected-rule applicability.

| Exact case name | Subject/direction and origin | Rule ports → exact selected applicability ports |
|---|---|---|
| `cnp-ingress-rule-navigation` | D/cnp-server, Ingress; D/cnp-target, CiliumNetworkPolicy ALLOW | TCP 8081–8082 → TCP/8081 from S/cnp-client |
| `cnp-egress-spec-rule-navigation` | S/cnp-client, Egress; S/cnp-source `specs[0]`, CiliumNetworkPolicy ALLOW | TCP 8080–8081 → TCP/8081 to D/cnp-server |
| `ccnp-ingress-spec-rule-navigation` | D/ccnp-server, Ingress; `${prefix}-edge-ccnp` target spec, CiliumClusterwideNetworkPolicy ALLOW | TCP 9091–9092 → TCP/9092 from S/ccnp-client |
| `ccnp-egress-spec-rule-navigation` | S/ccnp-client, Egress; same cluster policy's source spec | TCP 9090–9092 → TCP/9092 to D/ccnp-server |
| `istio-ingress-rule-navigation` | D/authz-server, Ingress; D/authz-ports-allow, AuthorizationPolicy ALLOW | TCP 8080–8081 → TCP/8080 from S/authz-client |
| `native-egress-istio-opposite-navigation` | S/authz-client, Egress; S/authz-source-network, NetworkPolicy | TCP 8080–8081, UDP 5353, SCTP 9000 → TCP/8080, UDP/5353, SCTP/9000 to D/authz-server |

The selected Istio rule is TCP-only; non-TCP pass-through is asserted separately
in the **effective** paired cases. No synthetic source-local Istio egress rule
is created.

### Other deterministic controls: two cases

- `istio-source-ingress-deny-egress-control`: S/authz-client has a real local
  ingress AuthorizationPolicy DENY. Its egress rule table must contain the
  native network rule, not AuthorizationPolicy; its ingress table/details must
  expose the actual DENY policy. The paired `istio-ports` cases independently
  prove its outgoing permissions remain unchanged.
- `cilium-cidr-narrow-deny`: S/cidr-client allows TCP/443 to
  `203.0.113.0/24` except `203.0.113.64/26` and denies TCP/443 to the narrower
  `203.0.113.128/25`. The broad CIDR row must not advertise the whole range as
  Allowed. CIDR handling must not fabricate an opposite pod check.

### Snapshot-wide uncertainty: four isolated final cases

Ordinary population creates the probe **pods**, not these policies. The runner
checks the clean known topology before each probe suite and restores/checks it
afterward even if Expect fails. Probe names and ownership labels include the
unique run ID; only that exact policy may be deleted.

| Suite and exact case | Policy/subject | Assertion |
|---|---|---|
| identity / `istio-identity-ingress-partial-data` | D/probe-identity-`${id}` selects D/authz-identity; ALLOW source namespace S is certificate-derived | Destination ingress row for S/authz-client is Partial Data; UDP/5353 and SCTP/9000 remain, no ports outside the declared network set; selected policy has an identity/mTLS uncertainty note |
| identity / `istio-identity-egress-partial-data` | Same policy viewed from S/authz-client egress | Same Partial Data/non-TCP expectations for D/authz-identity; no assertion treats inferred TCP identity as known |
| unsupported / `unsupported-cilium-rule-details` | S/probe-unsupported-`${id}` selects S/uncertain-client with `toFQDNs` | Full CiliumNetworkPolicy identity/API version, field-specific warning and Partial Data are visible in selected rule details |
| unsupported / `unsupported-snapshot-egress-partial-data` | Unrelated S/cnp-client → D/cnp-server while that probe is active | Egress row is Partial Data with exact TCP/8081, proving snapshot-wide uncertainty is visible without changing known network permissions |

**Total:** 28 original + 26 paired + 4 empty-rule + 6 navigation + 2 controls =
66 known-fixture cases; 2 identity + 2 unsupported = **70 required verdicts**.
The exact machine-readable inventory is available without starting Docker:

```bash
EXPECT_CASE_MANIFEST=1 expect .github/skills/netpol-graph-testing/scripts/k9s-tui-smoke.exp
```

## Functional data matrix

| Dimension | Values | Coverage |
|---|---|---|
| Subject kind | Pod, Deployment, Job, Namespace | Demo topology + `subject-picker-kinds`; Pod promotion from Subject and Deployment promotion from Applicability are automated by the Ctrl-S cases, while Job and Namespace promotion remain unit-tested/manual |
| Primitive kind | CIDR, Pod, Namespace, Deployment, Job | Demo topology + `primitive-kinds-apply-cancel-zero`; resource opening covered for selected primitive, exhaustive kind-by-kind opening manual-only |
| Projection | Rules, Primitives | `rules-primitives-global-toggle`, Enter/open cases |
| Direction | Ingress, Egress | Launch, direction toggle/focus, shared mode cases |
| Access state | Allowed, Disallowed, Partial, Unknown, Partial Data, rule-only `[EMPTY]` | Original topology preserves mixed/ambiguous/zero-pod cases; new exact custom positive/negative rows cover both directions; isolated identity/unsupported probes automate Partial Data without contaminating known fixtures |
| Details target | Rule Details text, Applicability table with direction title, Effective Details, Effective Applicability with direction title, Primitive Details text | Enter navigation and Esc cases |
| Dialogs | Subject picker, Primitive Kinds, Search | Dedicated dialog cases |
| Resource opening | NetworkPolicy, Pod, Namespace, Deployment, Job; CIDR remains non-openable | Lowercase `o` covers selected native rows from Subject, both Rules direction panels, Applicability, and Primitive Details; exhaustive primitive-kind row selection is manual-only |
