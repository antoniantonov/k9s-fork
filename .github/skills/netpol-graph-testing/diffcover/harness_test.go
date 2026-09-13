// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func edgeLibrary(t *testing.T) string {
	t.Helper()
	runner, _, _ := harnessPaths(t)
	return filepath.Join(filepath.Dir(runner), "netpol-edge-fixtures.sh")
}

func TestEdgeFixturePolicyContracts(t *testing.T) {
	script := `source "$LIB"
PREFIX=stub-demo
NS_EDGE_SRC=stub-demo-edge-src
NS_EDGE_DST=stub-demo-edge-dst
EDGE_SCENARIO=stub-demo-edges
edge_policy() { printf '%s\000%s\000%s\000' "$2" "$5" "{$6}"; }
edge_policies`
	output, err := bashScript(t, script, "LIB="+edgeLibrary(t))
	if err != nil {
		t.Fatalf("render edge policies: %v\n%s", err, output)
	}
	fields := strings.Split(strings.TrimSuffix(string(output), "\x00"), "\x00")
	if len(fields) != 15*3 {
		t.Fatalf("expected 15 policy fixtures, got %d fields", len(fields))
	}
	for index := 0; index < len(fields); index += 3 {
		kind, name := fields[index], fields[index+1]
		var policy map[string]any
		if err := json.Unmarshal([]byte(fields[index+2]), &policy); err != nil {
			t.Fatalf("%s %s has invalid JSON: %v", kind, name, err)
		}
		if kind == "CiliumClusterwideNetworkPolicy" {
			specs := []any{policy["spec"]}
			if value, ok := policy["specs"].([]any); ok {
				specs = value
			}
			for _, value := range specs {
				spec := value.(map[string]any)
				selector := spec["endpointSelector"].(map[string]any)["matchLabels"].(map[string]any)
				if selector["k8s:io.cilium.k8s.namespace.labels.netpol-scenario"] != "stub-demo-edges" {
					t.Fatalf("unscoped CCNP %s: %v", name, selector)
				}
			}
		}
		if kind == "AuthorizationPolicy" && strings.Contains(fields[index+2], `"from"`) {
			t.Fatalf("known-state fixture %s contains identity constraints", name)
		}
		if name == "cnp-empty" || name == "stub-demo-edge-ccnp-empty" {
			spec := policy["spec"].(map[string]any)
			for _, direction := range []string{"ingress", "egress"} {
				rules := spec[direction].([]any)
				if len(rules) != 1 || len(rules[0].(map[string]any)) != 0 {
					t.Fatalf("%s does not exercise %s: [{}]", name, direction)
				}
			}
		}
	}
}

func TestEdgeFixturePodInventory(t *testing.T) {
	output, err := bashScript(t, `source "$LIB"
NS_EDGE_SRC=stub-demo-edge-src
NS_EDGE_DST=stub-demo-edge-dst
NS_EDGE_OTHER=stub-demo-edge-other
edge_pods`, "LIB="+edgeLibrary(t))
	if err != nil {
		t.Fatalf("render edge pods: %v\n%s", err, output)
	}
	counts := map[string]int{}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 4 || seen[fields[0]+"/"+fields[1]] {
			t.Fatalf("invalid or duplicate pod fixture %q", line)
		}
		seen[fields[0]+"/"+fields[1]] = true
		counts[fields[0]]++
	}
	if len(seen) != 18 || counts["stub-demo-edge-src"] != 8 ||
		counts["stub-demo-edge-dst"] != 9 || counts["stub-demo-edge-other"] != 1 ||
		!seen["stub-demo-edge-other/control"] {
		t.Fatalf("isolated pod inventory changed: %#v", counts)
	}
}

func TestEdgePolicyCheckDetectsSpecDrift(t *testing.T) {
	script := `source "$LIB"
PREFIX=stub-demo
PROBE=""
PROBE_ID=""
EDGE_MODE=check
fixture_kubectl() {
  case "$1" in
    create) cat >/dev/null; printf '%s' '{"ingress":[{}]}|' ;;
    get)
      case "$*" in
        *metadata.labels*) printf 'stub-demo|true||' ;;
        *) printf '%s' "$ACTUAL_SPEC" ;;
      esac ;;
  esac
}
KUBECTL=(fixture_kubectl)
edge_policy cnp CiliumNetworkPolicy cilium.io/v2 example empty '"spec":{"ingress":[{}]}'`
	for _, actual := range []string{`{"ingress":[{}]}|`, `{"ingress":[]}|`} {
		output, err := bashScript(t, script, "LIB="+edgeLibrary(t), "ACTUAL_SPEC="+actual)
		if strings.Contains(actual, "[{}]") && err != nil {
			t.Fatalf("matching policy check failed: %v\n%s", err, output)
		}
		if strings.Contains(actual, "[]") && (err == nil || !strings.Contains(string(output), "[stale]")) {
			t.Fatalf("changed empty-rule semantics were not detected: %v\n%s", err, output)
		}
	}
}

func TestProbeDeletionRequiresExactOwner(t *testing.T) {
	script := `source "$LIB"
PREFIX=stub-demo
PROBE="$PROBE_SUITE"
PROBE_ID=run-123
NS_EDGE_DST=stub-demo-edge-dst
NS_EDGE_SRC=stub-demo-edge-src
EDGE_MODE=delete
fixture_kubectl() {
  case "$1" in
    get) printf '%s' "$OWNER" ;;
    delete) printf 'DELETE %s\n' "$*" ;;
    *) return 90 ;;
  esac
}
KUBECTL=(fixture_kubectl)
edge_probe_policy`
	for _, probe := range []struct {
		suite, resource, namespace string
	}{
		{"identity", "authorizationpolicies.security.istio.io", "stub-demo-edge-dst"},
		{"unsupported", "ciliumnetworkpolicies.cilium.io", "stub-demo-edge-src"},
	} {
		name := "probe-" + probe.suite + "-run-123"
		for _, owner := range []string{
			name + "|stub-demo|run-123",
			name + "|another-prefix|run-123",
			name + "|stub-demo|another-run",
		} {
			output, err := bashScript(t, script,
				"LIB="+edgeLibrary(t), "OWNER="+owner, "PROBE_SUITE="+probe.suite)
			if owner == name+"|stub-demo|run-123" {
				if err != nil || !strings.Contains(string(output), "DELETE delete "+probe.resource+" "+name+" -n "+probe.namespace) {
					t.Fatalf("owned probe was not precisely deleted: %v\n%s", err, output)
				}
			} else if err == nil || strings.Contains(string(output), "DELETE") {
				t.Fatalf("unowned policy deletion was not refused: %v\n%s", err, output)
			}
		}
	}
}

func TestProbeSuiteRestoresTopologyAfterFailure(t *testing.T) {
	runner, _, _ := harnessPaths(t)
	for _, test := range []struct {
		name, expectStatus, applyStatus, deleteStatus, restoreStatus, probeCheckStatus, signal string
		wantFailure                                                                            bool
	}{
		{"success", "0", "0", "0", "0", "1", "", false},
		{"expect-failure", "7", "0", "0", "0", "1", "", true},
		{"apply-failure", "0", "5", "0", "0", "1", "", true},
		{"delete-failure", "0", "0", "9", "0", "1", "", true},
		{"restore-failure", "0", "0", "0", "4", "1", "", true},
		{"checked-existing-probe", "0", "0", "0", "0", "0", "", false},
		{"terminated-expect", "0", "0", "0", "0", "1", "TERM", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			writeExecutable(t, directory, "demo-stub", `#!/bin/sh
printf 'DEMO %s\n' "$*" >> "$COMMAND_LOG"
case "$*" in
  *--delete*) exit "$DELETE_STATUS" ;;
  *--probe*--check*) exit "$PROBE_CHECK_STATUS" ;;
  *--probe*) exit "$APPLY_STATUS" ;;
  *--check*)
    if [ -f "$CHECK_MARKER" ]; then exit "$RESTORE_STATUS"; fi
    : > "$CHECK_MARKER" ;;
esac
exit 0
`)
			writeExecutable(t, directory, "expect-stub", `#!/bin/sh
printf 'EXPECT %s %s %s %s %s\n' "$SMOKE_SUITE" "$K9S_IMAGE" "$KUBECONFIG_MOUNT" "$DOCKER_NETWORK" "$PROBE_ID" >> "$COMMAND_LOG"
if [ -n "$EXPECT_SIGNAL" ]; then kill -"$EXPECT_SIGNAL" "$PPID"; fi
exit "$EXPECT_STATUS"
`)
			script := `source /dev/stdin <<< "$(sed '/^while \[\[ \$# -gt 0 \]\]; do/,$d' "$RUNNER")"
DEMO_SCRIPT="$FIXTURE/demo-stub"
EXPECT_SCRIPT="$FIXTURE/expect-stub"
RUN_DIR="$FIXTURE"
RUN_ID=stub-run
run_probe_smoke "$PROBE_SUITE" image-stub config-stub network-stub`
			for _, suite := range []string{"identity", "unsupported"} {
				log := filepath.Join(directory, suite+".log")
				output, err := bashScript(t, script,
					"RUNNER="+runner, "FIXTURE="+directory, "COMMAND_LOG="+log,
					"CHECK_MARKER="+filepath.Join(directory, suite+".checked"), "PROBE_SUITE="+suite,
					"DELETE_STATUS="+test.deleteStatus, "EXPECT_STATUS="+test.expectStatus,
					"APPLY_STATUS="+test.applyStatus, "RESTORE_STATUS="+test.restoreStatus,
					"PROBE_CHECK_STATUS="+test.probeCheckStatus, "EXPECT_SIGNAL="+test.signal)
				if (err != nil) != test.wantFailure {
					t.Fatalf("%s probe returned wrong status: %v\n%s", suite, err, output)
				}
				commands, err := os.ReadFile(log)
				if err != nil {
					t.Fatal(err)
				}
				lines := strings.Split(strings.TrimSpace(string(commands)), "\n")
				probe := "--probe " + suite + " --probe-id stub-run"
				expected := []string{"--check", probe + " --check"}
				if test.probeCheckStatus != "0" {
					expected = append(expected, probe)
				}
				if test.applyStatus == "0" {
					expected = append(expected, "EXPECT "+suite+" image-stub config-stub network-stub stub-run")
				}
				expected = append(expected, probe+" --delete", "--check")
				if len(lines) != len(expected) {
					t.Fatalf("wrong probe lifecycle length:\n%s\n%s", commands, output)
				}
				for index, suffix := range expected {
					if !strings.HasSuffix(lines[index], suffix) ||
						(suffix == "--check" && strings.Contains(lines[index], "--probe")) {
						t.Fatalf("wrong lifecycle step %d: expected %q\n%s\n%s", index, suffix, commands, output)
					}
				}
			}
		})
	}
}

func harnessPaths(t *testing.T) (runner, demo, smoke string) {
	t.Helper()
	root, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(root, ".github/skills/netpol-graph-testing/scripts/run-tests.sh"),
		filepath.Join(root, "scripts/netpol-demo-workloads.sh"),
		filepath.Join(root, ".github/skills/netpol-graph-testing/scripts/k9s-tui-smoke.exp")
}

func bashScript(t *testing.T, script string, environment ...string) ([]byte, error) {
	t.Helper()
	command := exec.Command("bash", "-c", script)
	command.Env = append(os.Environ(), environment...)
	return command.CombinedOutput()
}

func expectScript(t *testing.T, script string, environment ...string) ([]byte, error) {
	t.Helper()
	_, _, smoke := harnessPaths(t)
	command := exec.Command("expect", "-c",
		"if {[catch {source $env(SCREEN_HELPER)\n"+script+"\n} message]} { puts stderr $message; exit 1 }")
	command.Env = append(os.Environ(), "SCREEN_HELPER="+filepath.Join(filepath.Dir(smoke), "k9s-screen-assertions.exp"))
	command.Env = append(command.Env, environment...)
	return command.CombinedOutput()
}

func writeExecutable(t *testing.T, directory, name, contents string) {
	t.Helper()
	writeTestFile(t, directory, name, contents)
	if err := os.Chmod(filepath.Join(directory, name), 0o700); err != nil {
		t.Fatal(err)
	}
}

func TestTreeHashIncludesUntrackedBuildSources(t *testing.T) {
	runner, _, _ := harnessPaths(t)
	repository := t.TempDir()
	runGit(t, repository, "init", "-b", "master")
	writeTestFile(t, repository, "main.go", "package main\n")
	runGit(t, repository, "add", "main.go")
	if err := os.Mkdir(filepath.Join(repository, "internal"), 0o700); err != nil {
		t.Fatal(err)
	}

	// Load definitions without invoking any runner phase, including on the old
	// script, so the regression cannot accidentally reach Docker or Kubernetes.
	script := `source /dev/stdin <<< "$(sed '/^while \[\[ \$# -gt 0 \]\]; do/,$d' "$RUNNER")"
REPO_ROOT="$FIXTURE"
before="$(tree_hash)" || exit
printf 'package added\n' > "$FIXTURE/internal/added.go"
after="$(tree_hash)" || exit
test "$before" != "$after"`
	output, err := bashScript(t, script, "RUNNER="+runner, "FIXTURE="+repository)
	if err != nil {
		t.Fatalf("untracked build input did not change image fingerprint: %v\n%s", err, output)
	}
}

func TestImageHashFailureCannotReuseCache(t *testing.T) {
	runner, _, _ := harnessPaths(t)
	directory := t.TempDir()
	script := `source /dev/stdin <<< "$(sed '/^while \[\[ \$# -gt 0 \]\]; do/,$d' "$RUNNER")"
REPO_ROOT="$FIXTURE"
SKILL_DIR="$FIXTURE"
tree_hash() { printf 'apparently-valid-hash'; return 1; }
docker() { printf 'UNEXPECTED_DOCKER\n'; return 90; }
phase_build_image`
	output, err := bashScript(t, script, "RUNNER="+runner, "FIXTURE="+directory)
	if err == nil || strings.TrimSpace(string(output)) != "" {
		t.Fatalf("fingerprint failure reached image selection: %v\n%s", err, output)
	}
}

func TestDemoCheckRejectsDeleteFlagsWithoutCommands(t *testing.T) {
	_, demo, _ := harnessPaths(t)
	for _, flag := range []string{"--delete", "--delete-cluster"} {
		t.Run(flag, func(t *testing.T) {
			directory := t.TempDir()
			for _, name := range []string{"docker", "kind", "kubectl"} {
				writeExecutable(t, directory, name, "#!/bin/sh\nprintf '%s\\n' \"$0 $*\" >> \"$COMMAND_LOG\"\nexit 90\n")
			}
			log := filepath.Join(directory, "commands.log")
			output, err := bashScript(t, `bash "$DEMO" --check "$DELETE_FLAG"`,
				"DEMO="+demo, "DELETE_FLAG="+flag, "COMMAND_LOG="+log,
				"PATH="+directory+":"+os.Getenv("PATH"))
			if err == nil {
				t.Fatalf("conflicting check/delete flags succeeded:\n%s", output)
			}
			if contents, err := os.ReadFile(log); err == nil {
				t.Fatalf("conflicting flags invoked an external cluster command:\n%s\n%s", contents, output)
			}
			if !strings.Contains(string(output), "cannot combine") {
				t.Fatalf("missing incompatible-flags diagnostic:\n%s", output)
			}
		})
	}
}

func TestDemoCleanupPreservesSharedCRDs(t *testing.T) {
	_, demo, _ := harnessPaths(t)
	directory := t.TempDir()
	writeExecutable(t, directory, "kubectl", `#!/bin/sh
printf '%s\n' "$*" >> "$COMMAND_LOG"
case "$*" in
  *"get crd "*) printf true ;;
esac
`)
	output, err := bashScript(t, `bash "$DEMO" --delete --no-cluster --prefix stub-demo`,
		"DEMO="+demo, "COMMAND_LOG="+filepath.Join(directory, "commands.log"),
		"PATH="+directory+":"+os.Getenv("PATH"))
	if err != nil {
		t.Fatalf("stubbed cleanup failed: %v\n%s", err, output)
	}
	commands, err := os.ReadFile(filepath.Join(directory, "commands.log"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(commands), "delete crd ") {
		t.Fatalf("ordinary cleanup deleted a shared CRD:\n%s", commands)
	}
}

func TestDemoCleanupNeverBootstraps(t *testing.T) {
	_, demo, _ := harnessPaths(t)
	directory := t.TempDir()
	writeExecutable(t, directory, "kubectl", "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$COMMAND_LOG\"\n")
	for _, name := range []string{"docker", "kind"} {
		writeExecutable(t, directory, name, "#!/bin/sh\nprintf 'BOOTSTRAP %s\\n' \"$*\" >> \"$COMMAND_LOG\"\nexit 90\n")
	}
	output, err := bashScript(t, `bash "$DEMO" --delete --prefix stub-demo`,
		"DEMO="+demo, "COMMAND_LOG="+filepath.Join(directory, "commands.log"),
		"PATH="+directory+":"+os.Getenv("PATH"))
	if err != nil {
		t.Fatalf("stubbed cleanup attempted bootstrap: %v\n%s", err, output)
	}
	commands, err := os.ReadFile(filepath.Join(directory, "commands.log"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(commands), "BOOTSTRAP") || strings.Contains(string(commands), " demo-ccnp-monitoring ") {
		t.Fatalf("custom-prefix cleanup touched cluster/default-prefix setup:\n%s", commands)
	}
}

func TestDemoPopulationCompletesWithStubbedCluster(t *testing.T) {
	_, demo, _ := harnessPaths(t)
	directory := t.TempDir()
	writeExecutable(t, directory, "kubectl", `#!/bin/sh
printf 'KUBECTL %s\n' "$*" >> "$COMMAND_LOG"
if [ "$1" = apply ]; then cat >/dev/null; fi
`)
	for _, name := range []string{"docker", "kind"} {
		writeExecutable(t, directory, name, "#!/bin/sh\nprintf 'UNEXPECTED %s\\n' \"$0 $*\" >> \"$COMMAND_LOG\"\nexit 90\n")
	}
	log := filepath.Join(directory, "commands.log")
	output, err := bashScript(t, `bash "$DEMO" --no-cluster --no-wait --prefix stub-demo`,
		"DEMO="+demo, "COMMAND_LOG="+log, "PATH="+directory+":"+os.Getenv("PATH"))
	if err != nil || !strings.Contains(string(output), "==> done. Remove everything with:") {
		t.Fatalf("stubbed population did not reach the immutable script tail: %v\n%s", err, output)
	}
	commands, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(commands), "UNEXPECTED") ||
		!strings.Contains(string(commands), "get networkpolicies -n stub-demo-edge-other --no-headers") {
		t.Fatalf("population skipped final summary or escaped stubs:\n%s", commands)
	}
}

func TestSmokeSyntaxCheckReadsWholeFile(t *testing.T) {
	_, _, smoke := harnessPaths(t)
	source, err := os.ReadFile(smoke)
	if err != nil {
		t.Fatal(err)
	}
	helper, err := os.ReadFile(filepath.Join(filepath.Dir(smoke), "k9s-screen-assertions.exp"))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, mainExtra, helperExtra, diagnostic string
	}{
		{"unclosed-command", "\nif {1} {\n", "", "incomplete Tcl command"},
		{"balanced-invalid-command", "\nset broken \"quoted\"suffix\n", "", "invalid Tcl syntax"},
		{"invalid-procedure-body", "", "\nproc broken {} { set value \"quoted\"suffix }\n", "invalid Tcl syntax in procedure broken"},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			writeTestFile(t, directory, "broken.exp", string(source)+test.mainExtra)
			writeTestFile(t, directory, "k9s-screen-assertions.exp", string(helper)+test.helperExtra)
			command := exec.Command("expect", filepath.Join(directory, "broken.exp"))
			command.Env = append(os.Environ(), "EXPECT_SYNTAX_CHECK=1")
			output, err := command.CombinedOutput()
			if err == nil || !strings.Contains(string(output), test.diagnostic) {
				t.Fatalf("syntax defect was not diagnosed without execution: %v\n%s", err, output)
			}
		})
	}
}

func TestFreshScreenRowsAndExactPorts(t *testing.T) {
	_, _, smoke := harnessPaths(t)
	helper := filepath.Join(filepath.Dir(smoke), "k9s-screen-assertions.exp")
	script := `
	source $env(SCREEN_HELPER)
	proc fail_case {message} { error "ASSERTION: $message" }
	set raw "Pod stale/server Allowed TCP/9999"
	append raw [format "\033\[2J\033\[3;1HEffective Applicability (Egress)\033\[4;1H%-50s %-8s %-10s %-14s %s\033\[5;1H%-50s %-8s %-10s %-14s %s\033\[6;1H%-50s %-8s %-10s %-14s %s" Primitive Peer Opposite State Ports {Pod scenario/server} true true Allowed TCP/8081 {Pod scenario/other} false false Disallowed {no ports}]
	set screen [render_screen $raw]
	if {[string first stale $screen] >= 0} { error "stale frame survived erase" }
	set row [exact_table_row $screen "Effective Applicability (Egress)" {Primitive Peer Opposite State Ports} "Pod scenario/server"]
	if {[dict get $row State] ne "Allowed" || [dict get $row Peer] ne "true" || [dict get $row Opposite] ne "true"} { error "mixed applicability columns: $row" }
	assert_ports [dict get $row Ports] TCP/8081
	if {![catch {assert_ports [dict get $row Ports] TCP/9999}]} { error "wrong ports passed" }
	if {![catch {exact_table_row $screen "Effective Applicability (Ingress)" {Primitive Peer Opposite State Ports} "Pod scenario/server"}]} { error "wrong direction passed" }
	if {![catch {exact_table_row $screen "Effective Applicability (Egress)" {Primitive Peer Opposite State Ports} "Pod stale/server"}]} { error "stale peer passed" }
	if {[port_set {TCP/8080-8081, UDP/5353, SCTP/9000}] ne [port_set {SCTP/9000 TCP/8081 TCP/8080 UDP/5353}]} { error "port normalization differs" }
	if {[port_set {no ports}] ne {}} { error "no ports is not empty" }
	foreach malformed {{all ports} {TCP/8080,9999} {TCP/not-a-port}} {
	  if {![catch {port_set $malformed}]} { error "malformed ports passed: $malformed" }
	}
	set literal {Pod namespace/a.b[0]}
	if {![regexp "^[regexp_quote $literal]$" $literal]} { error "literal regex escaping failed" }
	foreach rendered {{namespace/policy #0} {namespace/policy #1}} {
	  if {![rule_name_matches $rendered namespace/policy]} { error "policy identity did not match $rendered" }
	}
	foreach rendered {{namespace/policy-other #0} {namespace/policy [spec 1] #0} {namespace/policy #1/0} {namespace/policy #0.0} namespace/policy} {
	  if {[rule_name_matches $rendered namespace/policy]} { error "invalid visible rule identity passed: $rendered" }
	}
	puts "fresh screen/row/port assertions passed"
	`
	command := exec.Command("expect", "-c", "if {[catch {\n"+script+"\n} message]} { puts stderr $message; exit 1 }")
	command.Env = append(os.Environ(), "SCREEN_HELPER="+helper)
	if output, err := command.CombinedOutput(); err != nil || !strings.Contains(string(output), "fresh screen/row/port assertions passed") {
		t.Fatalf("screen assertion helper: %v\n%s", err, output)
	}
}

func TestIncrementalScreenRetainsSplitEscapesAndCursor(t *testing.T) {
	script := `
	set raw "stale frame\033\[2J\033\[3;1HContext: offline\033\[9;1H> \033\[s\033\]0;policy YAML\007\033(B\033\[12;1HRule Details\033\[ucommand\033\[49;1H<npg>"
	set expected [render_screen $raw]
	if {![command_prompt_open $expected] || ![complete_repaint $expected]} {
	  error "complete command frame was not recognized"
	}
	if {[string first stale $expected] >= 0} { error "old screen survived erase" }
	foreach size {1 2 7 64} {
	  reset_screen terminal 50 260
	  for {set offset 0} {$offset < [string length $raw]} {incr offset $size} {
	    append_screen terminal [string range $raw $offset [expr {$offset + $size - 1}]]
	  }
	  if {[screen_text terminal] ne $expected || $terminal(pending) ne ""} {
	    error "split CSI/OSC/charset or saved cursor changed the frame at chunk size $size"
	  }
	}
	reset_screen terminal 50 260
	append_screen terminal "\033\[1;1HContext: offline\033\[2;1HCluster: offline"
	if {[complete_repaint [screen_text terminal]]} { error "top-only repaint passed" }
	append_screen terminal "\033\[9;"
	if {$terminal(pending) ne "\033\[9;"} { error "partial cursor escape was discarded" }
	append_screen terminal "1H> \033\[49;1H<npg>"
	if {![command_prompt_open [screen_text terminal]] || ![complete_repaint [screen_text terminal]]} {
	  error "continuation did not complete the same repaint"
	}
	puts "incremental cells, split escapes, saved cursor and final-size footer passed"
	`
	output, err := expectScript(t, script)
	if err != nil {
		t.Fatalf("incremental terminal stream: %v\n%s", err, output)
	}
	t.Log(strings.TrimSpace(string(output)))
}

func TestRealStreamWaitsThroughPolicyYAMLReturnAndPrompt(t *testing.T) {
	directory := t.TempDir()
	writeExecutable(t, directory, "terminal-stub", `#!/bin/sh
stty -echo
while IFS= read -r stage; do
  [ "$stage" = done ] && exit 0
  printf '\033[1;1HContext: offline\033[2;1HCluster: offline'
  sleep 1.2
  case "$stage" in
    resource)
      printf '\033[12;1HCiliumNetworkPolicy scenario/cnp-target\033[49;1H<ciliumnetworkpolicies>' ;;
    yaml)
      printf '\033[12;1HapiVersion: cilium.io/v2\033[13;1Hkind: CiliumNetworkPolicy\033[14;1Hname: cnp-target\033[15;1Hnamespace: scenario\033[49;1H<ciliumnetworkpolicies-yaml>' ;;
    graph)
      printf '\033[12;1HIngress · Rules\033[18;1HRule Details\033[19;1HPolicy: scenario/cnp-target\033[20;1HPolicy type: CiliumNetworkPolicy\033[21;1HAction: allow\033[49;1H<npg>' ;;
    prompt)
      printf '\033[9;'
      sleep 0.1
      printf '1H> \033[49;1H<npg>' ;;
    *) exit 90 ;;
  esac
done
`)
	script := `
	set screen_rows 50
	set screen_columns 260
	set timeout 10
	set drains 0
	set repaints 0
	proc drain {args} { incr ::drains; return 1 }
	proc repaint {} {
	  incr ::repaints
	  if {$::repaints > $::operations} { error "wait restarted its force-redraw" }
	  send -- "$::stage\r"
	}
	proc fail_case {message} { error "ASSERTION: $message" }
	rename render_screen whole_frame_renderer
	proc render_screen {args} { error "stream reader reparsed its accumulated prefix" }
	proc graph_rule {screen} {
	  return [selected_policy_matches $screen CiliumNetworkPolicy scenario/cnp-target ALLOW]
	}
	log_user 0
	spawn -noecho sh $env(TERMINAL_STUB)
	match_max 262144
	set operations 0
	foreach stage {resource yaml graph prompt} {
	  incr operations
	  switch -- $stage {
	    resource {
	      if {[wait_for_frame [list screen_regexp {CiliumNetworkPolicy scenario/cnp-target}] 6] eq ""} {
	        error "resource screen did not finish after top-header chunk"
	      }
	    }
	    yaml { if {![assert_yaml_origin CiliumNetworkPolicy cilium.io/v2 cnp-target scenario]} { error "YAML failed" } }
	    graph { if {[wait_for_frame graph_rule 6] eq ""} { error "policy/YAML return lost the graph frame" } }
	    prompt { if {[wait_for_frame command_prompt_open 6] eq ""} { error "delayed prompt tail was lost" } }
	  }
	  if {$repaints != $operations || $drains != $operations || $timeout != 10} {
	    error "shared wait reset the stream or leaked its deadline"
	  }
	}
	send -- "done\r"
	expect eof
	puts "real PTY delayed top-two headers -> policy/YAML return -> prompt tail passed with one repaint per operation"
	`
	output, err := expectScript(t, script, "TERMINAL_STUB="+filepath.Join(directory, "terminal-stub"))
	if err != nil {
		t.Fatalf("shared real terminal stream: %v\n%s", err, output)
	}
	t.Log(strings.TrimSpace(string(output)))
}

func TestCIDRSmokeChecksBothExactRows(t *testing.T) {
	script := `
	set ns_edge_src scenario
	proc start_case {name args} {
	  if {$name ne "cilium-cidr-narrow-deny"} { error "unexpected case $name" }
	  incr ::started
	}
	proc pass_case {} { incr ::passed }
	proc fail_case {message} { lappend ::failed $message }
	proc open_edge_subject {subject namespace direction} {
	  if {[list $subject $namespace $direction] ne {cidr-client scenario Egress}} { error "wrong graph context" }
	  return 1
	}
	proc send_key {args} {}
	proc filter_to {peer} { set ::filter $peer; lappend ::filters $peer; return 1 }
	proc capture_screen {} {
	  set broad [expr {$::filter eq "CIDR 203.0.113.0/24"}]
	  set row [dict create Primitive $::filter Peer true Opposite n/a State Disallowed Ports {no ports}]
	  if {$broad} {
	    dict set row Primitive "$::filter except 203.0.113.64/26"
	    dict set row State Unknown
	  }
	  set heading "Pod scenario/cidr-client · 1 pod\nEgress · Rules\nSelection: none\nEffective Details"
	  set title "Effective Applicability (Egress)"
	  switch -- $::mutation {
	    broad-allowed { if {$broad} { dict set row State Allowed } }
	    broad-disallowed { if {$broad} { dict set row State Disallowed } }
	    narrow-unknown { if {!$broad} { dict set row State Unknown } }
	    broad-ports { if {$broad} { dict set row Ports TCP/443 } }
	    narrow-ports { if {!$broad} { dict set row Ports TCP/443 } }
	    wrong-peer { dict set row Peer false }
	    yes-peer { dict set row Peer Yes }
	    pod-opposite { dict set row Opposite false }
	    partial-data { append heading "\nPartial Data" }
	    wrong-subject { set heading [string map {cidr-client stale-client} $heading] }
	    wrong-direction { set title "Effective Applicability (Ingress)" }
	    selected-rule { set title "Applicability (Egress)"; set heading [string map {{Selection: none} {Selection: cnp-cidr #0}} $heading] }
	    wrong-prefix { dict set row Primitive "CIDR 203.0.113.0/240" }
	  }
	  set columns "%-70s %-8s %-10s %-14s %s"
	  set line [format $columns [dict get $row Primitive] [dict get $row Peer] [dict get $row Opposite] [dict get $row State] [dict get $row Ports]]
	  set screen "$heading\n$title\n[format $columns Primitive Peer Opposite State Ports]\n$line"
	  if {$::mutation eq "duplicate-row"} { append screen "\n$line" }
	  return $screen
	}
	foreach mutation {none broad-allowed broad-disallowed narrow-unknown broad-ports narrow-ports wrong-peer yes-peer pod-opposite partial-data wrong-subject wrong-direction selected-rule wrong-prefix duplicate-row} {
	  set started 0
	  set passed 0
	  set failed {}
	  set filters {}
	  verify_cidr_narrow_deny
	  if {$started != 1} { error "CIDR case was not started exactly once" }
	  if {$mutation eq "none"} {
	    if {$passed != 1 || [llength $failed] != 0 || $filters ne {{CIDR 203.0.113.0/24} {CIDR 203.0.113.128/25}}} {
	      error "valid CIDR contract did not assert both prefixes exactly once: $passed / $failed / $filters"
	    }
	  } elseif {$passed != 0 || [llength $failed] == 0} {
	    error "CIDR mutation escaped the assertions: $mutation"
	  }
	}
	puts "CIDR exact-state/row/port/context regressions passed"
	`
	output, err := expectScript(t, script)
	if err != nil {
		t.Fatalf("CIDR smoke contract: %v\n%s", err, output)
	}
	t.Log(strings.TrimSpace(string(output)))
}

func TestApplicabilityValuesUseLiteralFlagsAndCanonicalPorts(t *testing.T) {
	script := `
	proc fail_case {message} { error "ASSERTION: $message" }
	foreach {state ports peer opposite} {
	  Allowed TCP/8081 true true
	  Disallowed {no ports} true false
	  Disallowed {no ports} false false
	  Unknown {no ports} true n/a
	  Unknown n/a n/a n/a
	  Allowed {SCTP/9000, TCP/8080, UDP/5353} true true
	  Allowed {SCTP/9000, UDP/5353} true true
	} {
	  set row [dict create State $state Ports $ports Peer $peer Opposite $opposite]
	  if {![assert_applicability_values $row $state $ports $peer $opposite]} { error "valid row rejected: $row" }
	  foreach {column wrong} {State Partial Ports TCP/9999 Peer Yes Opposite No} {
	    set changed [dict replace $row $column $wrong]
	    if {![catch {assert_applicability_values $changed $state $ports $peer $opposite}]} {
	      error "wrong $column passed: $changed"
	    }
	  }
	}
	set row [dict create State Allowed Ports {TCP/8080, UDP/5353, SCTP/9000} Peer true Opposite true]
	if {![catch {assert_applicability_values $row Allowed {SCTP/9000, TCP/8080, UDP/5353} true true}]} {
	  error "noncanonical protocol ordering passed"
	}
	puts "literal applicability flags and exact rendered ports passed"
	`
	output, err := expectScript(t, script)
	if err != nil {
		t.Fatalf("applicability rendering contract: %v\n%s", err, output)
	}
	t.Log(strings.TrimSpace(string(output)))
}

func TestSelectedRuleIdentityAndDenyContracts(t *testing.T) {
	script := `
	proc fail_case {message} { error "ASSERTION: $message" }
	set columns "%-40s %-35s %s"
	set rules "┌ Egress · Rules ┐\n│[format $columns {scenario/cnp-source #0} CiliumNetworkPolicy {TCP/8080, TCP/8081}]│\n│subjects 1/1                       peer podSelector=app=cnp-server│\n│────────────                      ────────────│\n│[format $columns {scenario/cnp-source #0} CiliumNetworkPolicy TCP/8081]│\n└"
	foreach {action ports} {ALLOW {TCP/8080, TCP/8081} DENY TCP/8081} {
	  set screen "$rules\nRule Details\nPolicy: scenario/cnp-source\nPolicy type: CiliumNetworkPolicy\nPolicy API version: cilium.io/v2\nAction: [string tolower $action]\nRule index: 0\nApplicability (Egress)"
	  if {![assert_selected_edge_rule $screen Egress scenario/cnp-source CiliumNetworkPolicy cilium.io/v2 $action $ports]} {
	    error "valid $action #0 rule was rejected"
	  }
	  foreach {from to} {
	    {Policy: scenario/cnp-source} {Policy: scenario/cnp-source-other}
	    {Policy type: CiliumNetworkPolicy} {Policy type: CNP}
	    {API version: cilium.io/v2} {API version: cilium.io/v1}
	    {#0} {[spec 1] #0}
	    {Rule index: 0} {Rule index: 1}
	  } {
	    set changed [string map [list $from $to] $screen]
	    if {![catch {assert_selected_edge_rule $changed Egress scenario/cnp-source CiliumNetworkPolicy cilium.io/v2 $action $ports}]} {
	      error "incorrect selected origin passed: $from => $to"
	    }
	  }
	  if {![catch {assert_selected_edge_rule "$screen\nSpec index: 1" Egress scenario/cnp-source CiliumNetworkPolicy cilium.io/v2 $action $ports}]} {
	    error "invented spec-index detail label passed"
	  }
	  set other_action DENY
	  if {$action eq "DENY"} { set other_action ALLOW }
	  if {![catch {assert_selected_edge_rule $screen Egress scenario/cnp-source CiliumNetworkPolicy cilium.io/v2 $other_action $ports}]} {
	    error "same visible #0 label hid the wrong action"
	  }
	}
	set screen "┌ Ingress · Rules ┐\n│[format $columns {scenario-edge-ccnp #0} CiliumClusterwideNetworkPolicy {TCP/9091, TCP/9092}]│\n└\nRule Details\nPolicy: —/scenario-edge-ccnp\nPolicy type: CiliumClusterwideNetworkPolicy\nPolicy API version: cilium.io/v2\nAction: allow\nRule index: 0\nApplicability (Ingress)"
	if {![assert_selected_edge_rule $screen Ingress scenario-edge-ccnp CiliumClusterwideNetworkPolicy cilium.io/v2 ALLOW {TCP/9091, TCP/9092}]} {
	  error "cluster-scoped policy details did not match their namespace-free rule row"
	}
	if {![catch {assert_selected_edge_rule $screen Ingress scenario-edge-ccnp CiliumClusterwideNetworkPolicy cilium.io/v2 ALLOW TCP/9091-9092}]} {
	  error "raw declared ports were incorrectly accepted as a merged range"
	}
	set native [format "┌ Egress · Rules ┐\n│%-50s %-30s %s│\n└\n" {scenario/authz-source-network #0} NetworkPolicy {SCTP/9000, TCP/8080, TCP/8081, UDP/5353}]
	set rows [rule_rows $native "Egress · Rules"]
	if {[llength $rows] != 1 || [dict get [lindex $rows 0] Name] ne "scenario/authz-source-network #0" ||
	    [dict get [lindex $rows 0] Type] ne "NetworkPolicy" ||
	    [dict get [lindex $rows 0] Ports] ne "SCTP/9000, TCP/8080, TCP/8081, UDP/5353"} {
	  error "headerless native row lost its exact name/type/declared ports: $rows"
	}
	if {[llength [rule_rows $native "Ingress · Rules"]] != 0} { error "rules came from the opposite direction" }
	puts "same-index allow/deny rule identities and full origin checks passed"
	`
	output, err := expectScript(t, script)
	if err != nil {
		t.Fatalf("selected rule identity contract: %v\n%s", err, output)
	}
	t.Log(strings.TrimSpace(string(output)))
}

func TestGraphSetupWaitsForStartupAndClosedCommandPrompt(t *testing.T) {
	script := `
	proc fail_case {message} { lappend ::failed $message }
	proc ensure_rules {} { return 1 }
	proc send_key {key args} { lappend ::keys $key; lappend ::events "KEY:$key" }
	proc send {args} { lappend ::keys [lindex $args end]; lappend ::events "COMMAND:[lindex $args end]" }
	rename clock real_clock
	proc clock {operation args} {
	  if {$operation eq "milliseconds"} { return $::now }
	  return [real_clock $operation {*}$args]
	}
	proc capture_screen {args} {
	  lassign $args report predicate seconds
	  set deadline [expr {$::now + $seconds * 1000}]
	  set ::last_capture_matched 0
	  while {$::now < $deadline} {
	    incr ::now 1000
	    if {[llength $::frames] > 0} {
	      set ::frame [lindex $::frames 0]
	      set ::frames [lrange $::frames 1 end]
	    }
	    lappend ::events "FRAME:$::frame"
	    if {[complete_repaint $::frame] && [{*}$predicate $::frame]} {
	      set ::last_capture_matched 1
	      break
	    }
	  }
	  return $::frame
	}
	set summary "Pod scenario/authz-identity · 1 pod"
	set columns "%-8s %-16s %-25s %s"
	set pod_row [format $columns Pod scenario authz-identity {Running · 1/1 ready}]
	set ready "┌ Subject ┐\n│$summary · Ingress on · Egress on · PARTIAL DATA (1 warning(s))│\n│[format $columns KIND NAMESPACE NAME STATUS]│\n│$pod_row│\n└\nIngress · Rules\nEgress · Rules\nEffective Details\nSelection: none\nEffective Applicability (Ingress)\nPartial Data\n<npg>"
	set startup_rows {}
	foreach name {api-one api-two api-three} {
	  lappend startup_rows [format $columns Pod scenario $name {Running · 1/1 ready}]
	}
	set startup [string map [list $summary {Deployment scenario/api · 3 pods} $pod_row [join $startup_rows "│\n│"]] $ready]
	foreach marker {{Waiting for NetworkPolicy evaluation...} {workloads loading...} {🐶> npg pod authz-identity scenario} {> npg pod authz-identity scenario} {Reachability Search}} {
	  if {[graph_ready $summary "$ready\n│$marker│"]} { error "unready frame accepted: $marker" }
	}
	if {![graph_ready $summary $ready]} { error "snapshot-wide Partial Data prevented readiness" }
	if {![graph_ready {Deployment scenario/api · 3 pods} $startup]} { error "ready initial deployment was rejected" }
	if {[graph_ready $summary [string map [list $pod_row ""] $ready]] ||
	    [graph_ready $summary [string map {{Running · 1/1 ready} {Pending · 0/1 ready}} $ready]]} {
	  error "a ready summary hid missing or unready rendered workload rows"
	}
	foreach replacement {{Pod scenarioe/authz-identity · 0 pods} {Pod scenario/other · 1 pod}} {
	  if {[graph_ready $summary [string map [list $summary $replacement] $ready]]} { error "wrong subject was ready" }
	}
	set now 0
	set failed {}
	set keys {}
	set events {}
	set navigation_setup_error ""
	set frames [list "splash" "$startup\nWaiting for NetworkPolicy evaluation..." "$startup\nworkloads loading..." $startup \
	  $startup "$startup\n│🐶> │" \
	  "$startup\n│🐶> npg pod authz-identity scenario│" \
	  "$ready\nWaiting for NetworkPolicy evaluation..." "$ready\nworkloads loading..." \
	  "$ready\n│🐶> npg pod authz-identity scenario│" [string map [list $pod_row ""] $ready] $ready]
	if {![open_edge_subject authz-identity scenario Egress] || [llength $failed] != 0} {
	  error "delayed but valid graph setup failed: $failed"
	}
	if {$keys ne [list ":" "npg pod authz-identity scenario\r" "i" "\033\[C"]} {
	  error "setup sent unexpected or repeated commands: $keys"
	}
	set command_index [lsearch -exact $events "COMMAND:npg pod authz-identity scenario\r"]
	set prompt_index [lsearch -exact $events "FRAME:$startup\n│🐶> │"]
	set ready_index [lsearch -exact $events "FRAME:$ready"]
	set toggle_index [lsearch -exact $events "KEY:i"]
	if {$prompt_index >= $command_index || $ready_index >= $toggle_index} {
	  error "command or direction keys escaped the readiness barriers"
	}
	set now 0
	set failed {}
	set keys {}
	set frames [list "$ready\nworkloads loading..."]
	set navigation_setup_error ""
	if {[open_edge_subject authz-identity scenario Egress 2] || [llength $keys] != 0 || [llength $failed] != 1} {
	  error "bounded setup timeout sent keys or failed to report a verdict"
	}
	set reads [llength $events]
	if {[open_edge_subject authz-identity scenario Egress 2] || [llength $keys] != 0 || [llength $failed] != 2 || [llength $events] != $reads} {
	  error "a failed setup cascaded into more input instead of an explicit failure"
	}
	puts "bounded startup, command-prompt closure and failed-setup barriers passed"
	`
	output, err := expectScript(t, script)
	if err != nil {
		t.Fatalf("graph startup/command synchronization: %v\n%s", err, output)
	}
	t.Log(strings.TrimSpace(string(output)))
}

func TestFreshScreenDrainIsBoundedDuringContinuousRedraw(t *testing.T) {
	script := `
	set file [open "[file dirname $env(SCREEN_HELPER)]/k9s-tui-smoke.exp" r]
	set source [read $file]
	close $file
	set start [string first "proc drain " $source]
	set end [string first "# A TUI only emits" $source $start]
	eval [string range $source $start [expr {$end - 1}]]
	rename clock real_clock
	proc clock {args} { return $::now }
	rename expect real_expect
	proc expect {args} {
	  incr ::reads
	  incr ::now 1000
	  if {$::reads > 3} { error "continuous redraw escaped the drain deadline" }
	  uplevel 1 { set drained 1 }
	}
	set timeout 25
	set now 0
	set reads 0
	if {![drain 1 3] || $reads != 3 || $timeout != 25} {
	  error "drain did not stop at its deadline and restore the caller timeout"
	}
	puts "continuous redraw drain is bounded and restores timeout"
	`
	output, err := expectScript(t, script)
	if err != nil {
		t.Fatalf("bounded fresh-screen drain: %v\n%s", err, output)
	}
	t.Log(strings.TrimSpace(string(output)))
}

func TestShortReadBudgetStartsAfterFreshnessPreparation(t *testing.T) {
	script := `
	set screen_rows 50
	set screen_columns 260
	set timeout 25
	set now 0
	proc fail_case {message} { error $message }
	proc drain {args} { incr ::now 1000; return 1 }
	proc repaint {} { incr ::now 500 }
	rename clock real_clock
	proc clock {args} { return $::now }
	rename expect real_expect
	proc exp_continue {args} { set ::continued 1 }
	proc expect {body} {
	  set expires [expr {$::now + $::timeout * 1000}]
	  foreach {delay chunk} {0 "\033\[1;1HContext: offline\033\[2;1HCluster: offline" 100 "\033\[9;1H> \033\[49;1H<npg>"} {
	    if {$::now + $delay > $expires} { break }
	    incr ::now $delay
	    uplevel 1 [list set expect_out(0,string) [subst -nocommands -novariables $chunk]]
	    set ::continued 0
	    uplevel 1 [lindex $body 2]
	    if {!$::continued} { return }
	  }
	  set ::now $expires
	  uplevel 1 [lindex $body 4]
	}
	if {[wait_for_frame command_prompt_open 1] eq "" || $now != 1600} {
	  error "one-second read budget was spent draining/resizing before reading the prompt tail"
	}
	if {[dict get $last_capture_summary drain_ms] != 1000 ||
	    [dict get $last_capture_summary repaint_ms] != 500 ||
	    [dict get $last_capture_summary read_budget_ms] != 1000 || $timeout != 25} {
	  error "preparation and read deadlines were not kept separate"
	}
	puts "short read deadline starts after one bounded drain/repaint, without extending the read timeout"
	`
	output, err := expectScript(t, script)
	if err != nil {
		t.Fatalf("short fresh-stream deadline: %v\n%s", err, output)
	}
	t.Log(strings.TrimSpace(string(output)))
}

func TestProjectionToggleRequiresObservedMode(t *testing.T) {
	script := `
	set file [open "[file dirname $env(SCREEN_HELPER)]/k9s-tui-smoke.exp" r]
	set source [read $file]
	close $file
	set start [string first "proc ensure_rules " $source]
	set end [string first "proc verify_custom_policy_rule " $source $start]
	eval [string range $source $start [expr {$end - 1}]]
	proc wait_for_frame {args} { return $::frame }
	proc fail_case {message} { incr ::failed }
	proc send_key {key args} {
	  lappend ::keys $key
	  set ::frame [string map {Rules Primitives Primitives Rules} $::frame]
	}
	proc assert_screen {pattern args} { return [regexp $pattern $::frame] }
	foreach command {ensure_rules ensure_primitives} {
	  set frame ""
	  set keys {}
	  set failed 0
	  if {[$command] || $failed != 1 || [llength $keys] != 0} {
	    error "unobserved projection caused a blind mode toggle"
	  }
	  foreach mode {Rules Primitives} {
	    set frame "Ingress · $mode"
	    set keys {}
	    set failed 0
	    if {![$command] || $failed != 0} { error "observed mode could not be selected" }
	    set expected Rules
	    if {$command eq "ensure_primitives"} { set expected Primitives }
	    if {$frame ne "Ingress · $expected" || [llength $keys] != [expr {$mode ne $expected}]} {
	      error "mode toggle was not tied to the observed projection"
	    }
	  }
	}
	puts "missing mode frames fail without typing m; only an observed opposite mode is toggled"
	`
	output, err := expectScript(t, script)
	if err != nil {
		t.Fatalf("projection readiness: %v\n%s", err, output)
	}
	t.Log(strings.TrimSpace(string(output)))
}

func TestApplicabilityWaitsForFragmentedFreshRepaint(t *testing.T) {
	script := `
	set screen_rows 50
	set screen_columns 260
	set timeout 25
	proc fail_case {message} { lappend ::failed $message }
	proc drain {args} { incr ::drains; return 1 }
	proc repaint {} { incr ::repaints }
	rename clock real_clock
	proc clock {args} { return $::now }
	rename expect real_expect
	proc exp_continue {args} { set ::continued 1 }
	proc expect {body} {
	  set expires [expr {$::now + $::timeout * 1000}]
	  foreach fragment $::fragments {
	    lassign $fragment delay chunk
	    if {$::now + $delay > $expires} { break }
	    incr ::now $delay
	    uplevel 1 [list set expect_out(0,string) $chunk]
	    set ::continued 0
	    uplevel 1 [lindex $body 2]
	    if {!$::continued} { return }
	  }
	  set ::now $expires
	  uplevel 1 [lindex $body 4]
	}
	set first "\033\[2J\033\[8;1H┌ Subject ┐\033\[9;1HPod scenario/ccnp-server · 1 pod\033\[13;1H┌ Ingress · Rules ┐\033\[14;1Hscenario-edge-ccnp #0 CiliumClusterwideNetworkPolicy TCP/9091, TCP/9092\033\[19;1H─────────"
	set columns "%-55s %-8s %-10s %-14s %s"
	set row [format $columns {Pod scenario/ccnp-client} true true Allowed TCP/9092]
	set split [expr {[string first "9092" $row] + 1}]
	set second "\033\[23;1H┌ Effective Details ┐\033\[24;1HSelection: none\033\[28;1H└\033\[30;1H┌ Effective Applicability (Ingress) ┐\033\[31;1H[format $columns Primitive Peer Opposite State Ports]\033\[32;1H[string range $row 0 $split]"
	set third "[string range $row [expr {$split + 1}] end]\033\[33;1H└\033\[50;1H<npg>"
	set complete [render_screen "$first$second$third"]
	foreach scenario {delayed missing wrong-ports} {
	  set now 0
	  set drains 0
	  set repaints 0
	  set failed {}
	  set last_wait_screen $complete
	  set fragments [list [list 400 $first] [list 1200 $second] [list 500 $third]]
	  if {$scenario eq "missing"} { set fragments [list [list 400 $first]] }
	  if {$scenario eq "wrong-ports"} {
	    set fragments [list [list 400 $first] [list 1200 $second] [list 500 [string map {92 91} $third]]]
	  }
	  set ok [assert_edge_row ccnp-server scenario Ingress ccnp-client scenario Allowed TCP/9092 0 0 true true]
	  if {$scenario eq "delayed"} {
	    if {!$ok || [llength $failed] != 0 || $now != 2100} {
	      error "split repaint was asserted before its lower table completed: $failed"
	    }
	  } elseif {$ok || [llength $failed] != 1} {
	    error "missing surface or wrong complete port set passed: $scenario / $failed"
	  }
	  if {$scenario eq "wrong-ports" && $now != 2100} { error "wrong semantic values were polled instead of rejected" }
	  if {$drains != 1 || $repaints != 1 || $timeout != 25 || $now > 20000} {
	    error "freshness/deadline lost: $drains drains, $repaints repaints, time $now, timeout $timeout"
	  }
	}
	puts "fragmented repaint waits for its exact complete row; no stale frames or semantic retries"
	`
	output, err := expectScript(t, script)
	if err != nil {
		t.Fatalf("fragmented fresh applicability repaint: %v\n%s", err, output)
	}
	t.Log(strings.TrimSpace(string(output)))
}

func TestUnsupportedProbeUsesEffectiveDiagnostics(t *testing.T) {
	script := `
	set ns_edge_src netpol-demo-edge-src
	set probe_id 20260912-200409-79177
	set reference "$ns_edge_src/probe-unsupported-$probe_id"
	set file [open "[file dirname $env(SCREEN_HELPER)]/../diffcover/testdata/unsupported-snapshot.screen" r]
	set diagnostic [read $file]
	close $file
	set top $diagnostic
	set warning "Warning: snapshot resource \"ciliumnetworkpolicies\" could not be fully evaluated: $reference: egress allow rule 0: toFQDNs requires live DNS resolution"
	proc fail_case {message} { error "ASSERTION: $message" }
	proc start_case {name args} {
	  if {$name ne "unsupported-cilium-rule-details"} { error "manifest case changed" }
	}
	proc pass_case {} { incr ::passed }
	proc open_edge_subject {args} { return 1 }
	proc select_named_rule {args} { error "disabled empty rules need not be visible or selectable" }
	proc send_key {key args} { lappend ::keys $key }
	proc capture_screen {args} { return $::top }
	proc wait_for_frame {predicate args} {
	  if {[{*}$predicate $::diagnostic]} { return $::diagnostic }
	  set ::last_wait_screen $::diagnostic
	  return ""
	}
	set passed 0
	set keys {}
	if {[string first "Partial Data" [join [panel_lines $diagnostic "Effective Details"] "\n"]] >= 0} {
	  error "fixture invented a mixed-case Partial Data label inside Effective Details"
	}
	verify_unsupported_policy
	if {$passed != 1 || $keys ne [list "\t" "\033\[F"]} {
	  error "probe did not inspect effective diagnostics exactly once: $passed / $keys"
	}
	foreach {from to} {
	  {"ciliumnetworkpolicies"} {"networkpolicies"}
	  {probe-unsupported-20260912-200409-79177:} {probe-unsupported-another-run:}
	  {egress allow rule 0} {ingress allow rule 0}
	  {toFQDNs} {toEndpoints}
	  {Effective Details} {Rule Details}
	  {uncertain-client · 1 pod} {other-client · 1 pod}
	  {PARTIAL DATA (1 warning(s))} {}
	  {Partial Data} {Allowed}
	} {
	  if {[unsupported_diagnostics $reference [string map [list $from $to] $diagnostic]]} {
	    error "unsupported probe accepted wrong diagnostic identity: $from => $to"
	  }
	}
	set missing [string map [list $warning ""] $diagnostic]
	if {[unsupported_diagnostics $reference $missing] ||
	    [unsupported_diagnostics $reference "$missing\n$warning"]} {
	  error "partial header or warning outside Effective Details hid a missing diagnostic"
	}
	puts "exact live snapshot-resource diagnostic and partial-state surfaces replayed with negative controls"
	`
	output, err := expectScript(t, script)
	if err != nil {
		t.Fatalf("unsupported probe diagnostics: %v\n%s", err, output)
	}
	t.Log(strings.TrimSpace(string(output)))
}

func TestSmokeManifestInventory(t *testing.T) {
	_, _, smoke := harnessPaths(t)
	command := exec.Command("expect", smoke)
	command.Env = append(os.Environ(), "EXPECT_CASE_MANIFEST=1")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("read pure smoke manifest: %v\n%s", err, output)
	}
	counts := map[string]int{}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) != 2 || seen[fields[1]] {
			t.Fatalf("invalid or duplicate manifest entry %q", line)
		}
		seen[fields[1]] = true
		counts[fields[0]]++
	}
	if counts["known"] != 66 || counts["identity"] != 2 || counts["unsupported"] != 2 || len(seen) != 70 {
		t.Fatalf("smoke inventory changed without updating its contract: %#v", counts)
	}
	for _, name := range []string{
		"cnp-empty-rule-ingress", "cnp-empty-rule-egress",
		"ccnp-empty-rule-ingress", "ccnp-empty-rule-egress",
		"cilium-cidr-narrow-deny", "istio-source-ingress-deny-egress-control",
	} {
		if !seen[name] {
			t.Fatalf("required regression case %s disappeared", name)
		}
	}
}

func TestCombinedSmokeSummaryRejectsMissingAndDuplicateCases(t *testing.T) {
	runner, _, _ := harnessPaths(t)
	for _, kind := range []string{"complete", "missing", "duplicate", "unexpected", "failed"} {
		t.Run(kind, func(t *testing.T) {
			directory := t.TempDir()
			writeExecutable(t, directory, "manifest-stub", "#!/bin/sh\nprintf 'known\\tone\\nidentity\\ttwo\\nunsupported\\tthree\\n'\n")
			writeTestFile(t, directory, "smoke-known.verdicts", "PASS\tone\n")
			writeTestFile(t, directory, "smoke-identity.verdicts", "PASS\ttwo\n")
			switch kind {
			case "complete":
				writeTestFile(t, directory, "smoke-unsupported.verdicts", "PASS\tthree\n")
			case "duplicate":
				writeTestFile(t, directory, "smoke-unsupported.verdicts", "PASS\tthree\nPASS\tthree\n")
			case "unexpected":
				writeTestFile(t, directory, "smoke-unsupported.verdicts", "PASS\tthree\nPASS\tfour\n")
			case "failed":
				writeTestFile(t, directory, "smoke-unsupported.verdicts", "FAIL\tthree\n")
			}
			script := `source /dev/stdin <<< "$(sed '/^while \[\[ \$# -gt 0 \]\]; do/,$d' "$RUNNER")"
	RUN_DIR="$FIXTURE"
	EXPECT_SCRIPT="$FIXTURE/manifest-stub"
	summarize_smoke`
			output, err := bashScript(t, script, "RUNNER="+runner, "FIXTURE="+directory)
			if kind == "complete" {
				if err != nil || !strings.Contains(string(output), "3 case(s), 0 failure(s)") {
					t.Fatalf("complete summary failed: %v\n%s", err, output)
				}
			} else if err == nil || !strings.Contains(string(output), "FAIL") {
				t.Fatalf("%s verdicts passed the authoritative summary:\n%s", kind, output)
			}
		})
	}
}
