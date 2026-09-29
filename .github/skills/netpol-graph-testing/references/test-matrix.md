# NetworkPolicy reachability test matrix

Automated cases are in `scripts/k9s-tui-smoke.exp`; setup/build phases are in `scripts/run-tests.sh`.

## Harness phase matrix

| Phase/path | Coverage | Expected invariant |
|---|---|---|
| Cluster/workload setup | `ensure-cluster`, `ensure-workloads`, `--force-workloads` | `netpol-demo-workloads.sh --check` runs before population; original stale-native checks remain, and new labels/readiness/policy `spec`/`specs` are checked |
| Default Go validation | Full run | `go clean -cache -testcache` and `go test ./...` run before the scoped race suites |
| Branch-diff coverage | `coverage` | Against `origin/master` by default (or `master` without that remote branch; `DIFF_COVER_BASE` overrides), committed branch and staged/unstaged/untracked production Go changes are at least 80% covered overall, and `internal/netpol/policy.go`, `policy_cilium.go`, `policy_istio.go`, `mesh.go` and `selection.go` are each at least 80%; missing changed executable functions fail rather than shrinking the denominator |
| Cached image build | Default run | Tracked and untracked build sources affect the fingerprint; errors cannot reuse a cache; its tag is resolved and recorded as an immutable image ID |
| Clean image build | `--clean-image` / `--no-image-cache` | A unique tag is built with `docker build --pull --no-cache`; `.image-cache` and other local images are never fallback candidates |
| Exact-image TUI | Successful build, or `--only tui-tests --image REF` | The requested/built ref is resolved once and both the probe and Expect smoke run use that immutable image ID |
| Startup/command readiness | Each fresh process and edge-subject command | Bounded fresh-frame waits require the expected subject and ready workload rows, open then closed command prompt, and no evaluation/workload-loading marker; Partial Data is permitted; failed setup stops further input but retains explicit verdicts |
| Shared terminal reader | Snapshot, regex, grouped, navigation and prompt waits | One drain/repaint per operation; terminal cells and split escapes advance incrementally without repeatedly parsing the full prefix; the final-size bottom breadcrumb is required, grouped assertions share one frame, and the read deadline begins after bounded preparation |
| Fragmented applicability repaint | Paired and selected-rule rows | A single fresh repaint accumulates chunks until the requested heading, exact peer and closing border exist, bounded by 20 seconds; state/flag/port mismatches are rejected, not polled until they change |
| Failed build isolation | Full or `--from build-image` run | TUI fails without consulting `.image-cache` or another local k9s image |
| Uncertainty sequencing | Eight sequential probe suites | Known fixtures first; each suite gets run-owned policies and a fresh TUI process; cleanup and normal `--check` run after success/failure, including all four `istio-features` policies |
| Cleanup safety | `--delete`, `--probe ... --delete` | No implicit cluster bootstrap, no shared CRD deletion; conflicting check/delete flags are rejected before external commands; probes require exact ownership |
| Verdict accounting | Pure manifest + combined summary | Exactly 125 expected cases: 101 known and 24 probes; missing, duplicate, unexpected and failed verdicts fail; consumed process EOF cannot skip the summary |
| Offline harness regression tests | Explicit `go test ./.github/skills/netpol-graph-testing/diffcover` | Tests include shell stubs, 40-pod/30-policy inventories/scoping and metadata, whole-file/procedure Tcl compilation, fresh headerless rule/applicability parsing, exact CIDR/selected-rule contracts with spec entries and action suffixes, per-layer synthetic rows, prefix-matched hostNetwork rows, delayed startup/prompt frames, effective unsupported diagnostics, cleanup after failures/signals for every probe mode, full population reaching its tail, and summary reconciliation without live tools |
| Optional conformance lane | `scripts/netpol-conformance.sh` (not part of `run-tests.sh`) | A dedicated kind cluster runs real Cilium and Istio (sidecar mode); HTTP probes through Service ClusterIPs are compared with graph verdicts by `go test -tags conformance ./internal/netpol/conformance`; definitive verdicts must agree with enforcement |

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
| Synthetic rows | Network and authorization layers explain their own isolation | `istio-authorization-default-deny-row` | D/authz-no-tcp shows `default-deny #-1` and `authorization default-deny (TCP) #-1`, both `Synthetic` with `no ports`, and no `unrestricted` row |
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

S and D (and `${prefix}-app`) are also labeled `istio.io/dataplane-mode=ambient`
so their pods are Istio mesh workloads; O is outside the mesh.

All new CCNP endpoint selectors include the scenario namespace-label constraint.
The 40 bare pods have stable names, one pod per subject, and an `app` label.
All except D/native-target also have `netpol-role`; its absent label is deliberate.
D/authz-unenrolled opts out with `istio.io/dataplane-mode=none`,
and D/authz-unknown carries a `sidecar.istio.io/status` annotation without an
`istio-proxy` container. `O/control` is otherwise unrestricted and distinct from
every empty-rule subject. New policies do not select the five original demo
namespaces.

### Paired effective rows: 42 cases

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
| `istio-ports` | S/authz-client → D/authz-server | Native source/destination permit TCP 8080/8081, UDP 5353, SCTP 9000; identity-free destination ALLOW permits TCP 8080/8081 and DENY removes 8081 | Allowed; exact text `SCTP/9000, TCP/8080, UDP/5353` |
| `istio-no-tcp` | S/authz-client → D/authz-no-tcp | Same native permissions; destination ALLOW has empty `rules` | Allowed; exact text `SCTP/9000, UDP/5353`; explicitly no TCP |
| `istio-empty-allow` | S/authz-client → D/authz-closed | TCP/8080-only destination network allow plus empty AuthorizationPolicy ALLOW | Disallowed; no ports |
| `istio-unenrolled` | S/authz-client → D/authz-unenrolled | Native permissions as above; allow-nothing ALLOW selects a pod outside the mesh, so it is not enforced | Allowed; exact text `SCTP/9000, TCP/8080, TCP/8081, UDP/5353` |
| `istio-enrollment-unknown` | S/authz-client → D/authz-unknown | Native permissions as above; ALLOW TCP/8080 selects a pod whose enrollment is unknown | Partial Data; `SCTP/9000, TCP/8080, UDP/5353` (authorization modeled as enforced) |
| `cilium-l7-scoped` | O/control → D/l7-server | CNP `cnp-l7` allows TCP/8080 from O/control with an HTTP rule NPG cannot evaluate | Partial Data; TCP/8080 |
| `cilium-l7-unmatched-peer` | S/authz-client → D/l7-server | The same isolating CNP cannot match this source; the source egress does not allow the pod | Disallowed; no ports, and no Partial Data on screen |
| `native-range-protocol` | S/native-client → D/native-target | Source TCP/8000-8002, UDP/5353, SCTP/9000 intersects destination TCP/8001-8003, UDP/5353; destination lacks `netpol-role`, matching NotIn | Allowed; `TCP/8001-8002, UDP/5353` |
| `istio-default-action` | S/authz-client → D/authz-default | Native four-port baseline; omitted action and `rules: [{}]` mean TCP ALLOW-all | Allowed; `SCTP/9000, TCP/8080, TCP/8081, UDP/5353` |
| `istio-deny-only` | S/authz-client → D/authz-denyonly | DENY-only removes TCP/8081 without activating authorization default-deny | Allowed; `SCTP/9000, TCP/8080, UDP/5353` |
| `istio-no-enforcement` | S/authz-client → D/authz-noenforce | AUDIT empty rules and dry-run DENY-all do not enforce | Allowed; `SCTP/9000, TCP/8080, TCP/8081, UDP/5353` |

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

### Selected rule, type columns and navigation: nine baseline-style cases

Every case checks one name/full-type/ports row, selected rule action/API version,
`o` resource opening followed by the selected resource's YAML, return to the
same graph rule, direct graph `y`, then selected-rule applicability.
The Rules panel uses **headerless blocks**, with the full type between the name
and declared ports. Raw declared lists remain separate entries, in canonical
order; they are not the merged effective permission summary.

| Exact case name | Subject/direction and origin | Rule ports → exact selected applicability ports |
|---|---|---|
| `cnp-ingress-rule-navigation` | D/cnp-server, Ingress; D/cnp-target, CiliumNetworkPolicy ALLOW | `TCP/8081, TCP/8082` → `TCP/8081` from S/cnp-client |
| `cnp-egress-spec-rule-navigation` | S/cnp-client, Egress; S/cnp-source `specs[0]`, CiliumNetworkPolicy ALLOW | `TCP/8080, TCP/8081` → `TCP/8081` to D/cnp-server |
| `ccnp-ingress-spec-rule-navigation` | D/ccnp-server, Ingress; `${prefix}-edge-ccnp` target spec, CiliumClusterwideNetworkPolicy ALLOW | `TCP/9091, TCP/9092` → `TCP/9092` from S/ccnp-client |
| `ccnp-egress-spec-rule-navigation` | S/ccnp-client, Egress; same cluster policy's source spec | `TCP/9090, TCP/9091, TCP/9092` → `TCP/9092` to D/ccnp-server |
| `istio-ingress-rule-navigation` | D/authz-server, Ingress; D/authz-ports-allow, AuthorizationPolicy ALLOW | `TCP/8080, TCP/8081` → `TCP/8080` from S/authz-client |
| `native-egress-istio-opposite-navigation` | S/authz-client, Egress; S/authz-source-network, NetworkPolicy | `SCTP/9000, TCP/8080, TCP/8081, UDP/5353` → `SCTP/9000, TCP/8080, UDP/5353` to D/authz-server |
| `native-range-rule-navigation` | S/native-client, Egress; S/native-source | `SCTP/9000, TCP/8000-8002, UDP/5353` → `TCP/8001-8002, UDP/5353` to D/native-target |
| `istio-default-action-rule-navigation` | D/authz-default, Ingress; D/authz-default, omitted action displayed as ALLOW | `TCP/all` → `TCP/8080, TCP/8081` from S/authz-client |
| `istio-deny-only-rule-navigation` | D/authz-denyonly, Ingress; D/authz-denyonly DENY | `TCP/8081` → Disallowed, `no ports`, Peer `true`, Opposite `false` |

All positive selected rows require literal Peer `true`, Opposite `true`.
The following controls run **within** these existing cases, before the case's
single verdict; they do not add or replace manifest cases:

| Existing case | Additional selected rule / peer | Exact selected row |
|---|---|---|
| `cnp-egress-spec-rule-navigation` | Source ALLOW / D/cnp-mismatch (only TCP/9090 ingress) | Peer `true`, Opposite `false`, Disallowed, `no ports` |
| `cnp-egress-spec-rule-navigation` | Source ALLOW / O/control (unmatched selector) | Peer `false`, Opposite `false`, Disallowed, `no ports` |
| `cnp-egress-spec-rule-navigation` | Source DENY in `specs[1]` / D/cnp-denied | Peer `true`, Opposite `false`, Disallowed, `no ports` |
| `ccnp-ingress-spec-rule-navigation` | Target DENY TCP/9091 / S/ccnp-client | Peer `true`, Opposite `false`, Disallowed, `no ports`, despite effective TCP/9092 remaining Allowed |

The first rule index resets independently per spec/direction/action, so labels
name the spec entry of multi-spec resources and the action of deny rules: the
source CNP allow in `specs[0]` is `…/cnp-source specs[0] #0` and the deny in
`specs[1]` is `…/cnp-source specs[1] deny #0`; the single-spec target is
`…/cnp-target #0`. Selected Cilium details must show
`Rule index: 0 in <entry> (spec index <n>)`, native and Istio details must show
a plain `Rule index: 0`, and an invented `Spec index:` label is rejected. Full policy types are required;
shorthand labels cannot satisfy the row or selected-details assertions.

The selected Istio rule is TCP-only; non-TCP pass-through is asserted separately
in the **effective** paired cases. No synthetic source-local Istio egress rule
is created.

### Other deterministic controls: five cases

- `istio-source-ingress-deny-egress-control`: S/authz-client has a real local
  ingress AuthorizationPolicy DENY. Its egress rule table must contain the
  native network rule, not AuthorizationPolicy; its ingress table/details must
  expose the actual DENY policy. The paired `istio-ports` cases independently
  prove its outgoing permissions remain unchanged.
- `cilium-cidr-narrow-deny`: S/cidr-client allows TCP/443 to
  `203.0.113.0/24` except `203.0.113.64/26` and denies TCP/443 to the narrower
  `203.0.113.128/25`. Two fresh effective egress screens must identify that
  subject and each exact prefix once. The broad `/24` is **Unknown** and the
  fully denied `/25` is **Disallowed**; both require exact `no ports`, Peer
  `true` and Opposite `n/a`. Neither screen may report snapshot-wide
  **Partial Data**. An arbitrary non-Allowed state is insufficient: the broad
  range is not uniformly Disallowed, and no opposite pod check is fabricated.
- `cilium-hostnetwork-peer-partial-data`: D/cnp-server ingress from the
  `hostNetwork` kube-proxy pod (matched by the `Pod kube-system/kube-proxy-`
  prefix, exactly one row) is **Partial Data** with `no ports`, because Cilium
  identifies it as host or remote-node rather than by pod labels.
- `hostnetwork-peer-native-control`: the same peer of D/authz-server, whose
  ingress is governed only by NetworkPolicy and Istio, is a definitive
  **Disallowed** with `no ports` and no Partial Data on screen.
- `istio-authorization-default-deny-row`: see the synthetic rows entry above.

### Original scoped uncertainty: four isolated cases

Ordinary population creates the probe **pods**, not these policies. The runner
checks the clean known topology before each probe suite and restores/checks it
afterward even if Expect fails. Probe names and ownership labels include the
unique run ID; only that exact policy may be deleted.

| Suite and exact case | Policy/subject | Assertion |
|---|---|---|
| identity / `istio-identity-ingress-note` | D/probe-identity-`${id}` selects D/authz-identity; ALLOW source namespace S | Both pods are mesh workloads, so the source identity is evaluated from workload metadata: the destination ingress row for S/authz-client is a definitive Allowed with exact `SCTP/9000, TCP/8080, TCP/8081, UDP/5353` and no Partial Data; scrolling the selected rule's details from the top shows `State: Allowed (Allowed)` and the `mesh mTLS` approximation note, and never `Partial Data` or `Warnings:` |
| identity / `istio-identity-egress-note` | Same policy viewed from S/authz-client egress | Same exact Allowed row for D/authz-identity |
| unsupported / `unsupported-cilium-rule-details` | S/probe-unsupported-`${id}` selects S/uncertain-client with `toFQDNs` | Subject `PARTIAL DATA` badge and applicability `Partial Data` cells, plus the exact per-rule diagnostic `CiliumNetworkPolicy <namespace>/probe-unsupported-<id>: egress allow rule 0: toFQDNs requires live DNS resolution` in **Effective Details** (scrolled from the top). The details summary itself uses lowercase `partial data`. Disabled raw rules need not be selectable; known navigation cases retain API version/YAML checks |
| unsupported / `unsupported-scoped-egress-control` | Unrelated S/cnp-client → D/cnp-server while that probe is active | Egress row stays a definitive Allowed with exact TCP/8081 and no Partial Data, proving uncertainty is scoped to the pods the probe selects |

**Total:** 28 original + 42 paired + 4 empty-rule + 9 navigation + 5 original
controls + 13 campaign controls = **101 known-fixture cases**.
The eight sequential suites contribute 24 cases: identity 2, unsupported 2,
cilium-features 3, cilium-rejected 2, istio-features 8, istio-custom 2,
istio-targetrefs 2, istio-root 3: **125 required verdicts**.
The exact machine-readable inventory is available without starting Docker:

```bash
EXPECT_CASE_MANIFEST=1 expect .github/skills/netpol-graph-testing/scripts/k9s-tui-smoke.exp
```

## Campaign feature contracts and traceability

These entries identify **added assertions**, not a claim that the latest live
run passed. The authoritative campaign log supplies final pass/fail status.
No packet enforcement is tested. Stable population is 40 pods and 30 policies;
probe policies are excluded from those stable counts. S/D/O retain the namespace
definitions above. `F` below means the exact full baseline
`SCTP/9000, TCP/8080, TCP/8081, UDP/5353`; `N` means
`SCTP/9000, UDP/5353`. Positive effective rows are `true/true` unless stated.

### Added stable controls (13 cases)

| Behavior / exact live case | Subject, direction, peer and exact result | Unit/helper evidence |
|---|---|---|
| Native podSelector-only scope / `native-same-namespace-selector`, `native-podselector-scope` | S/native-client Egress → S/native-local: Allowed `SCTP/9000, TCP/8000-8002, UDP/5353`; → D/native-local-lookalike: Disallowed `no ports`, `false/false` | `TestNativeSelectorExpressionBoundaries`; `TestExpandedFixtureMetadataAndPolicyContracts` |
| Native expression exclusions and AND scope / `native-notin-blocked`, `native-doesnotexist-excluded`, `native-namespace-and-control` | Same source Egress → D/native-blocked (NotIn), D/native-excluded (DoesNotExist), O/native-lookalike (namespace AND pod): each Disallowed `no ports`, `false/false`; D/native-target absence control passes in paired cases | `TestNativeSelectorExpressionBoundaries`; native peer-matcher tests |
| CNP namespace scope and non-isolating deny / `cilium-nonisolating-deny-egress`, `cilium-cnp-namespace-scope-control-egress` | S/cnp-observe Egress → O/control: Allowed `SCTP/9000, TCP/8080, UDP/5353`; same-app O/cnp-scope → O/control: Allowed `F`; CNP cannot cross its policy namespace | `TestCiliumDirectionIsolationMatrix`; `TestCiliumSelectorSourceAliasesRemainConjunctive` |
| Alias conjunction and combined entries / `cilium-nonisolating-combined-spec-navigation` | Native baseline isolates; CNP `spec` rule 0 contradictory `any:netpol-role=other` AND `k8s:netpol-role=control`, TCP/80 has zero peer matches and is hidden as an empty nonsynthetic rule. The live Rules panel must contain exactly CNP `spec #1` TCP/8080 and `specs[0] deny #0` TCP/8081, with no `spec #0`. Selectable `spec` rule 1: `true/true`, Allowed TCP/8080. `specs[0]` DENY: `true/false`, Disallowed `no ports`; detail ordinal is 1, not 0. Resource and direct YAML retain full policy identity. The hidden rule's underlying API applicability remains `false/false`, Disallowed `no ports`, asserted offline | `TestCiliumSelectorSourceAliasesRemainConjunctive`; `TestGeneratedCiliumAliasRulePresentationContract`; `TestNonisolatingRulesHideOnlyEmptyAliasRule`; `TestRuleDetailsShowsCiliumSpecEntry`; `TestFormatRuleNameDisambiguatesSpecsAndActions`; `TestExpandedExactDiagnosticsAndSpecOrdinals` |
| Non-enforcing actions / `istio-audit-dryrun-rules-absent` | D/authz-noenforce Ingress from S/authz-client remains Allowed `F`; exact native rule remains, no AuthorizationPolicy row | Existing `TestIstioPolicyActionsScopeOperationsAndMatching`; `TestDryRunAnnotationDriftIsRejected` |
| Injection metadata / `istio-inject-annotation`, `istio-inject-label-precedence` | O/authz-inject-annotation (annotation true, no proxy), O/authz-inject-label (label true over annotation false), Ingress from O/control: `true/false`, Partial Data `no ports`; full pod-qualified missing-proxy enforcement diagnostic required | `TestIstioInjectionSignalPrecedence`; `TestMeshEnrollmentDetection`; metadata inventory regression |
| Explicit injection opt-out / `istio-inject-optout-precedence` | O/authz-inject-optout label false overrides annotation true: Ingress from O/control Allowed TCP/8080, no Partial Data cell | Same injection tests |
| Zero-pair representation / `native-zero-pair-not-applicable` | Existing app/scaled-to-zero Deployment, Ingress, O/control peer: exact `0 pods`, Unknown state, Peer/Opposite/Ports all `n/a`; no loading frame accepted | `TestApplicabilityTableReportsUnevaluatedColumnsAsNotApplicable`; empty-subject readiness helper regression |

### Added sequential probe contracts (20 cases)

Every diagnostic is matched within Effective Details with exact policy,
direction, action and rule index; line wrapping alone is normalized.
The final column lists complete unaffected controls, not a claim of global
snapshot completeness. The uppercase subject badge may summarize other pairs.

| Probe / exact cases | Selected scenario and exact required result | Diagnostic / control |
|---|---|---|
| `cilium-features` / `cilium-unsupported-fields-diagnostics` | S/uncertain-client Egress → O/control: Partial Data TCP/443, `true/true` | One CNP has rules 0 toRequires, 1 toGroups, 2 CIDR-group selector, 3 unsupported `io.cilium.k8s.policy.unmodeled` key, 4 originatingTLS to exact O/control. All five concrete normalizer warning messages must appear. `TestCiliumUnsupportedFieldBranchesAreScoped` |
| `cilium-features` / `cilium-unsupported-fields-no-modeled-ports`, `cilium-unsupported-fields-control` | Selected source → D/cnp-server: Partial Data `no ports`, `false/false`; unaffected S/cnp-client → D/cnp-server: Allowed TCP/8081 | Disabled dynamic rules do not invent matching or port evidence; TLS peer scoping remains separate from the dynamic rules |
| `cilium-rejected` / `cilium-rejected-sibling-diagnostics`, `cilium-rejected-sibling-control` | Valid `spec` egress443 selects S/uncertain-client; invalid `specs[0]` port70000 selects absent app. Resource rejection removes all enforced entries: to O/control Partial Data `SCTP/all, TCP/all, UDP/all`, `true/true`; known CNP pair stays Allowed TCP/8081 | Exact `spec: Cilium rejects this policy: specs[0]: egress allow rule 0: unable to parse port "70000": strconv.ParseUint: parsing "70000": value out of range`. CRD normalizer fixture, **not vendor-admission-valid**. `TestCiliumRejectedEntryInvalidatesSiblingSpecs`; `TestNetworkPolicyGraphRejectedSiblingDiagnosticsStayPairScoped` |
| `istio-features` / `istio-l7-allow-diagnostics`, `istio-l7-allow-unmatched-control` | D/authz-l7-allow Ingress from S/authz-client: Partial Data `SCTP/9000, TCP/8080, UDP/5353`; from O/control: Allowed `N` | Combined hosts/notHosts/methods/notMethods/paths/notPaths preserves tentative ALLOW TCP/8080; exact L7 warning. Namespace-constrained peer excludes O. `TestIstioUnsupportedPredicateBranchesAreScoped` |
| `istio-features` / `istio-l7-deny-diagnostics`, `istio-l7-deny-unmatched-control` | D/authz-l7-deny from S: Partial Data `F`; from O/control: Allowed `F` | HTTP DENY cannot subtract TCP/8080; both L7 and `DENY has unmodeled L7 predicates; its ports are not subtracted` messages required |
| `istio-features` / `istio-request-allow-diagnostics`, `istio-request-allow-unmatched-control` | D/authz-request-allow from S: Partial Data `N`; O/control: Allowed `N` | Rule 0 notRequestPrincipals: JWT identity diagnostic; rule 1 notRemoteIpBlocks: proxy-forwarding diagnostic. Disabled source predicates grant no modeled TCP |
| `istio-features` / `istio-request-deny-diagnostics`, `istio-request-deny-unmatched-control` | D/authz-request-deny from S: Partial Data `F`; O/control: Allowed `F` | Same two exact per-rule warnings; unsupported DENY removes no modeled ports |
| `istio-custom` / `istio-custom-diagnostics`, `istio-custom-unmatched-control` | D/authz-default from S: Partial Data `F`; O/control: Allowed `F` | Exact `ingress custom rule 0: CUSTOM authorization depends on an external provider`; no provider installed. Existing action tests |
| `istio-targetrefs` / `istio-targetrefs-diagnostics`, `istio-targetrefs-other-namespace-control` | D/authz-default from S: Partial Data `F`; O/authz-inject-optout from O/control: Allowed TCP/8080 | Exact unresolved targetRefs selection diagnostic; uncertainty affects mesh destinations throughout D, so control is outside D. `TestIstioTargetRefsUncertaintyIsNamespaceScoped` covers singular/plural representation |
| `istio-root` / `istio-root-scope-ingress`, `istio-root-unmatched-control`, `istio-root-policy-navigation` | Prefix-scoped root ALLOW8080 selects only D/authz-identity: ingress from S/authz-client Allowed `SCTP/9000, TCP/8080, UDP/5353`; D/authz-default stays Allowed `F`; selected root rule Allowed TCP/8080 | Root namespace `istio-system` retained/reused without relabeling or changing mesh config. Exact root-policy API/YAML and resolved-root note. `TestIstioAuthorizationRootAndWorkloadScope`; `TestRootNamespaceConflictsMakeRootPoliciesSelectionUnknown` |

### Boundary classification and retained limitations

| Feature class | Status and evidence boundary |
|---|---|
| Native default policyTypes / empty egress before admission | Unit-only: Kubernetes defaults admitted NetworkPolicy objects, so a raw pre-admission distinction cannot honestly be deployed. `TestNativeEmptyEgressBeforeAPIDefaulting`; extended `TestPolicyDirectionDefaults` |
| Selector aliases for service accounts/namespaces and CNP/CCNP permutations | `TestCiliumSelectorAliasTargets` and `TestCiliumSelectorSourceAliasesRemainConjunctive` parameterize these alongside the live pod-label alias representative; no redundant live cross-product |
| Invalid native ranges/ports, malformed snapshots, discovery failures | Unit/fake-client-only; the native API rejects malformed objects or live snapshot timing cannot be forced safely |
| Cilium host/network identities, unknown entities/sources, dynamic FQDN/service/group/CIDR-group peers, requires, auth, L7/TLS/SNI/listeners, ICMP limitations | Deliberately unsupported portions stay explicit uncertainty. Existing policy matrix, normalization and scoping tests cover recognized branches; live representatives are the existing L7/FQDN/hostNetwork cases plus new branch-tail suite. No DNS, service resolution, provider, TLS or packet behavior is claimed |
| Istio principal/namespace/SA identity, IP predicates, negative matching, when/notPorts, unknown actions, root revision ambiguity, sidecar/native-sidecar/ambient/redirection enrollment | Existing policy/mesh/root matrices provide unit coverage; identity live suite proves metadata approximation, new request suites prove unsupported request classes, and new injection cases prove signal precedence. Root disagreement requires fake snapshots; no live revision configuration is changed |
| Async stale subject/result/workload delivery and error recovery | Deterministic UX/model unit tests; fixture metadata cannot force callback queue ordering. Existing subject changes/auto-refresh remain live controls |
| Deployment mixed pairs/named-port ambiguity, Job/Namespace subject promotion and exhaustive resource-kind opening | Existing topology retained; unit/manual coverage as identified below. Only the scaled-to-zero gap gains a new exact live case here; do not relabel manual checks as automated passes |
| Enforcement, Cilium/Istio installation, conformance build tag | Explicitly excluded from this campaign. Fixture CRDs and enrollment metadata only |
| Test skips | The helper tests do not intentionally skip new fixture cases. Full repository test/race skip inventory and any environment skips must be reported from the coordinator's actual logs; scope excludes the previously documented unrelated broad UI/model race tests, not new NPG tests |

Offline integrity evidence includes `TestProbeInventoryAndMultiplePolicyOwnership`,
`TestMultiProbeCleanupContinuesAfterDeletionFailure`,
`TestProbeSuiteRestoresTopologyAfterFailure` (success, apply/Expect/delete/restore
failure, termination, checked reuse across all eight modes),
`TestConsumedEOFStillFinishesSmokeAccounting`, `TestSmokeManifestInventory`, and
`TestCombinedSmokeSummaryRejectsMissingAndDuplicateCases`. Any failed cleanup or
restoration remains a validation failure even if every presentation case passes.
The generated-manifest tests `TestGeneratedStableFixtureSemantics`,
`TestGeneratedCiliumProbeSemantics`, and `TestGeneratedIstioProbeSemantics`
also evaluate the actual shell-rendered policies and metadata with the production
evaluator. They check all new semantic classes' exact effective states, ports,
flags and warnings before deployment, without substituting a hand-built test
policy for the manifest that the live suite will use.

## Functional data matrix

| Dimension | Values | Coverage |
|---|---|---|
| Subject kind | Pod, Deployment, Job, Namespace | Demo topology + `subject-picker-kinds`; Pod promotion from Subject and Deployment promotion from Applicability are automated by the Ctrl-S cases, while Job and Namespace promotion remain unit-tested/manual |
| Primitive kind | CIDR, Pod, Namespace, Deployment, Job | Demo topology + `primitive-kinds-apply-cancel-zero`; resource opening covered for selected primitive, exhaustive kind-by-kind opening manual-only |
| Projection | Rules, Primitives | `rules-primitives-global-toggle`, Enter/open cases |
| Direction | Ingress, Egress | Launch, direction toggle/focus, shared mode cases |
| Access state | Allowed, Disallowed, Partial, Unknown, Partial Data, rule-only `[EMPTY]` | Original topology preserves mixed/ambiguous/zero-pod cases (zero-pair Peer/Opposite/Ports are `n/a`); new exact custom positive/negative rows cover both directions; broad CIDR overlap is Unknown without Partial Data; scoped Partial Data is automated for an L7 rule, unknown mesh enrollment, hostNetwork peers under Cilium and the unsupported probe, each with a definitive control |
| Details target | Rule Details text, Applicability table with direction title, Effective Details, Effective Applicability with direction title, Primitive Details text | Enter navigation and Esc cases |
| Dialogs | Subject picker, Primitive Kinds, Search | Dedicated dialog cases |
| Resource opening | NetworkPolicy, Pod, Namespace, Deployment, Job; CIDR remains non-openable | Lowercase `o` covers selected native rows from Subject, both Rules direction panels, Applicability, and Primitive Details; exhaustive primitive-kind row selection is manual-only |
