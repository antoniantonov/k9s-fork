# NetworkPolicy reachability test matrix

Automated cases are in `scripts/k9s-tui-smoke.exp`; setup/build phases are in `scripts/run-tests.sh`.

| Area | Coverage | Automated case | Notes |
|---|---|---|---|
| Launch commands | `:npg` opens graph and renders Subject, Ingress, Egress, Details | `launch-npg-view` | `:netpolgraph`/`:npgraph` aliases covered by Go command tests/manual |
| Context launch | Shift-R from Pod/Deployment/Job/Namespace | Manual-only | Requires navigating source resource tables |
| `i` / `e` | Hide/show ingress and egress; both hidden placeholder | `direction-toggles-placeholder` | Verifies exact placeholder text |
| `m` | Global Rules ↔ Primitives projection; both panels switch | `rules-primitives-global-toggle` | Also used by open-resource cases |
| `f` | Primitive Kinds dialog; CIDR, Pod, Namespace, Deployment, Job; Apply/Cancel | `primitive-kinds-apply-cancel-zero` | Applies zero kinds and verifies empty-kinds message |
| `o` | Rules opens NetworkPolicy; Primitives opens primitive resource or CIDR warning | `open-resource-o-both-projections` | CIDR branch may be reached depending selected row |
| `s` | Subject picker lists Pod, Deployment, Job, Namespace subjects | `subject-picker-kinds` | Selection of each subject kind is manual-only in TUI; topology supports all |
| `/` | Search Apply, Clear, Cancel | `search-apply-clear-cancel` | Uses `frontend` filter |
| `r` / `Ctrl-R` | Auto-refresh toggle and manual refresh | `refresh-controls` | Asserts repaint/status text |
| `y` | YAML view of selected NetworkPolicy | `yaml-view` | Synthetic rows are manual-only |
| `Enter` | Rule selected → Applicability focus | `enter-navigation-rule-selected` | Headline behavior |
| `Enter` | No rule selected → Effective Applicability focus | `enter-navigation-effective-applicability` | Uses `Esc` to clear selection first |
| `Enter` | Primitives selected → details text focus | `enter-navigation-primitive-details` | Plain text detail pane |
| `Enter` | Applicability focused → opens highlighted primitive; `Esc` returns | `enter-opens-applicability-primitive` | Moves off the first CIDR row before opening |
| `Esc` | Clear selection before back navigation; back from opened resource | `escape-clears-selection-before-back`, open cases | Dialog cancel also covered |
| `←` / `→` | Focus Ingress/Egress | `left-right-direction-focus` | Uses ANSI cursor sequences |
| `Tab` / `Shift-Tab` | Subject → Ingress → Egress → Details → Applicability focus ring | `tab-and-shift-tab-focus-ring` | Visual focus is indirectly asserted by stable repaint |
| Freeze/hang | Rapid arrows, refreshes, mode/direction/autorefresh toggles while scrolling | `freeze-hang-stress` | Sends `SIGQUIT` on repaint timeout |

## Functional data matrix

| Dimension | Values | Coverage |
|---|---|---|
| Subject kind | Pod, Deployment, Job, Namespace | Demo topology + `subject-picker-kinds`; individual subject selection manual-only |
| Primitive kind | CIDR, Pod, Namespace, Deployment, Job | Demo topology + `primitive-kinds-apply-cancel-zero`; resource opening covered for selected primitive, exhaustive kind-by-kind opening manual-only |
| Projection | Rules, Primitives | `rules-primitives-global-toggle`, Enter/open cases |
| Direction | Ingress, Egress | Launch, direction toggle/focus, shared mode cases |
| Access state | Allowed, Disallowed, Partial, Unknown, Partial-data, `[EMPTY]` | Demo topology covers Allowed/Disallowed/Partial/Unknown/`[EMPTY]`; Partial-data requires induced informer/API warning and is manual-only |
| Details target | Rule Details text, Applicability table, Effective Details, Effective Applicability, Primitive Details text | Enter navigation and Esc cases |
| Dialogs | Subject picker, Primitive Kinds, Search | Dedicated dialog cases |
| Resource opening | NetworkPolicy, Pod, Namespace, Deployment, Job, CIDR warning | `o`/Enter cases cover selected rows; exhaustive primitive-kind row selection manual-only |
