# NetworkPolicy reachability test matrix

Automated cases are in `scripts/k9s-tui-smoke.exp`; setup/build phases are in `scripts/run-tests.sh`.

## Harness phase matrix

| Phase/path | Coverage | Expected invariant |
|---|---|---|
| Cluster/workload setup | `ensure-cluster`, `ensure-workloads`, `--force-workloads` | `netpol-demo-workloads.sh --check` runs before every path that can populate workloads |
| Default Go validation | Full run | `go clean -cache -testcache` and `go test ./...` run before the scoped race suites |
| Cached image build | Default run | A matching tree cache may be reused, but its tag is resolved and recorded as an immutable image ID |
| Clean image build | `--clean-image` / `--no-image-cache` | A unique tag is built with `docker build --pull --no-cache`; `.image-cache` and other local images are never fallback candidates |
| Exact-image TUI | Successful build, or `--only tui-tests --image REF` | The requested/built ref is resolved once and both the probe and Expect smoke run use that immutable image ID |
| Failed build isolation | Full or `--from build-image` run | TUI fails without consulting `.image-cache` or another local k9s image |

## Live TUI matrix

| Area | Coverage | Automated case | Notes |
|---|---|---|---|
| Launch commands | `:npg` opens with no direction rule selected, Effective Applicability for Ingress, and the exact `read-only graph` badge under the logo | `launch-npg-view` | `:netpolgraph`/`:npgraph` aliases covered by Go command tests/manual |
| Context launch | Shift-R from Pod/Deployment/Job/Namespace | Manual-only | Requires navigating source resource tables |
| `i` / `e` | Hide/show ingress and egress; both hidden placeholder | `direction-toggles-placeholder` | Verifies exact placeholder text |
| `m` | Global Rules ↔ Primitives projection; both panels switch | `rules-primitives-global-toggle` | Also used by open-resource cases |
| `f` | Primitive Kinds dialog; CIDR, Pod, Namespace, Deployment, Job; Apply/Cancel | `primitive-kinds-apply-cancel-zero` | Applies zero kinds and verifies empty-kinds message |
| `o` | Open Rule is offered only for real rules and hidden in Primitives mode | `open-rule-only-for-real-rules`, `open-rule-hidden-in-primitives` | Synthetic default-deny is asserted not to advertise the action |
| `s` | Subject picker lists Pod, Deployment, Job, Namespace subjects | `subject-picker-kinds` | Selection of each subject kind is manual-only in TUI; topology supports all |
| `/` | Search Apply, Clear, Cancel | `search-apply-clear-cancel` | Uses `frontend` filter |
| `r` / `Ctrl-R` | Auto-refresh toggle and manual refresh | `refresh-controls` | Asserts repaint/status text |
| `y` | YAML view of selected NetworkPolicy; hidden for synthetic rules and CIDR applicability | `yaml-view`, `yaml-hidden-without-a-manifest` | Navigates to real rules by their advertised action |
| `Enter` | Rule selected → Applicability focus | `enter-navigation-rule-selected` | Headline behavior |
| `Enter` | No rule selected → Effective Applicability focus | `enter-navigation-effective-applicability` | Exercises the default launch state directly |
| `Enter` | Primitives selected → details text focus | `enter-navigation-primitive-details` | Plain text detail pane |
| `Enter` | Applicability focused → opens highlighted primitive; `Esc` returns | `enter-opens-applicability-primitive` | Moves off the first CIDR row before opening |
| `Ctrl-S` | Promote a supported Subject workload or applicability primitive to the graph subject | `ctrl-s-set-subject-from-subject-panel`, `ctrl-s-set-subject-from-applicability` | Promotes the selected API Pod from Subject, then independently filters Effective Applicability to `Deployment netpol-demo-web/frontend`; both cases assert focus returned to Subject through the renewed Ctrl-S hint |
| `Esc` | Clear selection before back navigation; back from opened resource | `escape-clears-selection-before-back`, open cases | Dialog cancel also covered |
| `←` / `→` | Focus Ingress/Egress | `left-right-direction-focus` | Uses ANSI cursor sequences |
| `Tab` / `Shift-Tab` | Subject → Ingress → Ingress details → Ingress applicability → Egress → Egress details → Egress applicability focus ring | `tab-and-shift-tab-focus-ring` | Each direction owns the detail stops that follow it, so its applicability is reachable without passing through the other panel. Focus opens on Subject. Visual focus is indirectly asserted by stable repaint |
| Freeze/hang | Rapid arrows, refreshes, mode/direction/autorefresh toggles while scrolling | `freeze-hang-stress` | Sends `SIGQUIT` on repaint timeout |

## Authoritative automated smoke inventory

The Expect summary contains these 21 cases, each with an explicit verdict:

`launch-npg-view`, `subject-picker-kinds`, `direction-toggles-placeholder`,
`rules-primitives-global-toggle`, `primitive-kinds-apply-cancel-zero`,
`search-apply-clear-cancel`, `tab-and-shift-tab-focus-ring`,
`left-right-direction-focus`, `enter-navigation-rule-selected`,
`enter-navigation-effective-applicability`,
`enter-navigation-primitive-details`,
`enter-opens-applicability-primitive`, `open-rule-only-for-real-rules`,
`open-rule-hidden-in-primitives`, `yaml-view`,
`yaml-hidden-without-a-manifest`, `refresh-controls`,
`escape-clears-selection-before-back`,
`ctrl-s-set-subject-from-subject-panel`,
`ctrl-s-set-subject-from-applicability`, and
`freeze-hang-stress`.

## Functional data matrix

| Dimension | Values | Coverage |
|---|---|---|
| Subject kind | Pod, Deployment, Job, Namespace | Demo topology + `subject-picker-kinds`; Pod promotion from Subject and Deployment promotion from Applicability are automated by the Ctrl-S cases, while Job and Namespace promotion remain unit-tested/manual |
| Primitive kind | CIDR, Pod, Namespace, Deployment, Job | Demo topology + `primitive-kinds-apply-cancel-zero`; resource opening covered for selected primitive, exhaustive kind-by-kind opening manual-only |
| Projection | Rules, Primitives | `rules-primitives-global-toggle`, Enter/open cases |
| Direction | Ingress, Egress | Launch, direction toggle/focus, shared mode cases |
| Access state | Allowed, Disallowed, Partial, Unknown, Partial-data, rule-only `[EMPTY]` | Demo topology covers Allowed/Disallowed/Partial/Unknown, including zero-pod-pair primitives as `Unknown`; rule-level `[EMPTY]` remains for empty subject-policy matches; Partial-data requires induced informer/API warning and is manual-only |
| Details target | Rule Details text, Applicability table with direction title, Effective Details, Effective Applicability with direction title, Primitive Details text | Enter navigation and Esc cases |
| Dialogs | Subject picker, Primitive Kinds, Search | Dedicated dialog cases |
| Resource opening | NetworkPolicy, Pod, Namespace, Deployment, Job, CIDR warning | `o`/Enter cases cover selected rows; exhaustive primitive-kind row selection manual-only |
