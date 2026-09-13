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
PROBE=identity
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
	for _, owner := range []string{
		"probe-identity-run-123|stub-demo|run-123",
		"probe-identity-run-123|another-prefix|run-123",
		"probe-identity-run-123|stub-demo|another-run",
	} {
		output, err := bashScript(t, script, "LIB="+edgeLibrary(t), "OWNER="+owner)
		if owner == "probe-identity-run-123|stub-demo|run-123" {
			if err != nil || !strings.Contains(string(output), "DELETE delete authorizationpolicies.security.istio.io probe-identity-run-123 -n stub-demo-edge-dst") {
				t.Fatalf("owned probe was not precisely deleted: %v\n%s", err, output)
			}
		} else if err == nil || strings.Contains(string(output), "DELETE") {
			t.Fatalf("unowned policy deletion was not refused: %v\n%s", err, output)
		}
	}
}

func TestProbeSuiteRestoresTopologyAfterFailure(t *testing.T) {
	runner, _, _ := harnessPaths(t)
	directory := t.TempDir()
	writeExecutable(t, directory, "demo-stub", `#!/bin/sh
printf 'DEMO %s\n' "$*" >> "$COMMAND_LOG"
case "$*" in
  *--delete*) exit "$DELETE_STATUS" ;;
  *--probe*--check*) exit 1 ;;
esac
exit 0
`)
	writeExecutable(t, directory, "expect-stub", "#!/bin/sh\nprintf 'EXPECT\\n' >> \"$COMMAND_LOG\"\nexit 7\n")
	script := `source /dev/stdin <<< "$(sed '/^while \[\[ \$# -gt 0 \]\]; do/,$d' "$RUNNER")"
DEMO_SCRIPT="$FIXTURE/demo-stub"
EXPECT_SCRIPT="$FIXTURE/expect-stub"
RUN_DIR="$FIXTURE"
RUN_ID=stub-run
run_probe_smoke identity image-stub config-stub network-stub`
	for _, deleteStatus := range []string{"0", "9"} {
		log := filepath.Join(directory, "commands-"+deleteStatus+".log")
		output, err := bashScript(t, script,
			"RUNNER="+runner, "FIXTURE="+directory, "COMMAND_LOG="+log, "DELETE_STATUS="+deleteStatus)
		if err == nil {
			t.Fatalf("failed Expect run reported success:\n%s", output)
		}
		commands, err := os.ReadFile(log)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSpace(string(commands)), "\n")
		if len(lines) != 6 ||
			!strings.HasSuffix(lines[0], "--check") || strings.Contains(lines[0], "--probe") ||
			!strings.Contains(lines[1], "--probe identity --probe-id stub-run --check") ||
			!strings.HasSuffix(lines[2], "--probe identity --probe-id stub-run") ||
			lines[3] != "EXPECT" ||
			!strings.Contains(lines[4], "--probe identity --probe-id stub-run --delete") ||
			!strings.HasSuffix(lines[5], "--check") || strings.Contains(lines[5], "--probe") {
			t.Fatalf("probe check/apply/failure/cleanup/restore ordering is incorrect:\n%s\n%s", commands, output)
		}
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
	append raw [format "\033\[2J\033\[3;1HEffective Applicability (Egress)\033\[4;1H%-50s %-8s %-10s %-14s %s\033\[5;1H%-50s %-8s %-10s %-14s %s\033\[6;1H%-50s %-8s %-10s %-14s %s" Primitive Peer Opposite State Ports {Pod scenario/server} Yes Yes Allowed TCP/8081 {Pod scenario/other} No Yes Disallowed {no ports}]
	set screen [render_screen $raw]
	if {[string first stale $screen] >= 0} { error "stale frame survived erase" }
	set row [exact_table_row $screen "Effective Applicability (Egress)" {Primitive Peer Opposite State Ports} "Pod scenario/server"]
	if {[dict get $row State] ne "Allowed" || [dict get $row Peer] ne "Yes" || [dict get $row Opposite] ne "Yes"} { error "mixed applicability columns: $row" }
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
	foreach rendered {{namespace/policy #0} {namespace/policy [spec 1] #0} {namespace/policy #1/0}} {
	  if {![rule_name_matches $rendered namespace/policy]} { error "policy identity did not match $rendered" }
	}
	if {[rule_name_matches {namespace/policy-other #0} namespace/policy]} { error "different policy shared a name prefix" }
	puts "fresh screen/row/port assertions passed"
	`
	command := exec.Command("expect", "-c", "if {[catch {\n"+script+"\n} message]} { puts stderr $message; exit 1 }")
	command.Env = append(os.Environ(), "SCREEN_HELPER="+helper)
	if output, err := command.CombinedOutput(); err != nil || !strings.Contains(string(output), "fresh screen/row/port assertions passed") {
		t.Fatalf("screen assertion helper: %v\n%s", err, output)
	}
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
	for _, kind := range []string{"complete", "missing", "duplicate", "unexpected"} {
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
