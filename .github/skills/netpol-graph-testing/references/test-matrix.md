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
| `m` | Global Rules ↔ Primitives projection; both panels switch and Effective Applicability stays hidden in Primitives mode | `rules-primitives-global-toggle` | Also used by open-resource cases |
| `p` | Primitive Kinds dialog; CIDR, Pod, Namespace, Deployment, Job; Apply/Cancel | `primitive-kinds-apply-cancel-zero` | Asserts both buttons are visible immediately at the smoke terminal's 50x200 size, without arrow-down scrolling; applies zero kinds and verifies the empty-kinds message |
| `o` | Open selected native Kubernetes primitive from Subject, Ingress, Egress, Applicability, and Primitive Details | `open-primitive-from-subject`, `open-primitive-from-direction-panels`, `open-primitive-from-applicability`, `enter-navigation-primitive-details` | Eligible states assert the exact `<o> Open Primitive` header hint and select by that hint rather than fixed row ordering; Rules direction rows open their NetworkPolicy |
| `o` disabled | Rule Details does not offer Open Primitive | `open-primitive-disabled-in-rule-details` | Rule Details remains open after lowercase `o` |
| `s` | Subject picker lists Pod, Deployment, Job, Namespace subjects | `subject-picker-kinds` | Selection of each subject kind is manual-only in TUI; topology supports all |
| `/` | Search Apply, Clear, Cancel | `search-apply-clear-cancel` | Uses `frontend` filter |
| `r` | Auto-refresh toggle; no manual refresh shortcut is advertised | `auto-refresh-toggle`, `launch-npg-view` | Asserts status text and absence of `Ctrl-R` |
| `y` | YAML view of selected NetworkPolicy; hidden for synthetic rules and CIDR applicability | `yaml-view`, `yaml-hidden-without-a-manifest` | Navigates to real rules by their advertised action |
| `Enter` | Rule selected → Applicability focus | `enter-navigation-rule-selected` | Headline behavior |
| `Enter` | No rule selected → Effective Applicability focus | `enter-navigation-effective-applicability` | Exercises Egress from the default no-selection state; the selected-rule case exercises Ingress |
| `Enter` | Primitives selected → details text focus | `enter-navigation-primitive-details` | Plain text detail pane; the case then verifies lowercase `o` opens the selected native primitive from Primitive Details |
| `Enter` | Applicability focused → remains in Applicability | `enter-stays-in-applicability` | Selects a native row through the Open Primitive hint and proves a second Enter does not navigate |
| `Ctrl-S` | **Set As Subject**: promote a supported Subject workload or applicability primitive to the graph subject | `ctrl-s-set-subject-from-subject-panel`, `ctrl-s-set-subject-from-applicability` | Promotes the selected API Pod from Subject, then independently filters Effective Applicability to `Deployment netpol-demo-web/frontend`; both cases assert focus returned to Subject through the renewed Ctrl-S hint |
| `Esc` | Clear selection before back navigation; back from opened primitive | `escape-clears-selection-before-back`, open-primitive cases | Dialog cancel also covered |
| `←` / `→` | Focus Ingress/Egress | `left-right-direction-focus` | Uses ANSI cursor sequences |
| `Tab` / `Shift-Tab` | Subject → Ingress → Ingress details → Ingress applicability → Egress → Egress details → Egress applicability focus ring | `tab-and-shift-tab-focus-ring` | Each direction owns the detail stops that follow it, so its applicability is reachable without passing through the other panel. Focus opens on Subject. Visual focus is indirectly asserted by stable repaint |
| Freeze/hang | Rapid arrows, refreshes, mode/direction/autorefresh toggles while scrolling | `freeze-hang-stress` | Sends `SIGQUIT` on repaint timeout |

## Authoritative automated smoke inventory

The Expect summary contains these 23 cases, each with an explicit verdict:

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
`yaml-hidden-without-a-manifest`, `auto-refresh-toggle`,
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
| Resource opening | NetworkPolicy, Pod, Namespace, Deployment, Job; CIDR remains non-openable | Lowercase `o` covers selected native rows from Subject, both Rules direction panels, Applicability, and Primitive Details; exhaustive primitive-kind row selection is manual-only |
