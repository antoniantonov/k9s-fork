// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package main

import (
	"encoding/json"
	"io"
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
NS_EDGE_OTHER=stub-demo-edge-other
EDGE_SCENARIO=stub-demo-edges
edge_policy() { printf '%s\000%s\000%s\000' "$2" "$5" "{$6}"; }
edge_policies`
	output, err := bashScript(t, script, "LIB="+edgeLibrary(t))
	if err != nil {
		t.Fatalf("render edge policies: %v\n%s", err, output)
	}
	fields := strings.Split(strings.TrimSuffix(string(output), "\x00"), "\x00")
	if len(fields) != 30*3 {
		t.Fatalf("expected 30 policy fixtures, got %d fields", len(fields))
	}
	names := map[string]bool{}
	for index := 0; index < len(fields); index += 3 {
		kind, name := fields[index], fields[index+1]
		names[name] = true
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
		if name == "cnp-l7" {
			rule := policy["spec"].(map[string]any)["ingress"].([]any)[0].(map[string]any)
			peer := rule["fromEndpoints"].([]any)[0].(map[string]any)["matchLabels"].(map[string]any)
			if peer["k8s:io.kubernetes.pod.namespace"] != "stub-demo-edge-other" || !strings.Contains(fields[index+2], `"http"`) {
				t.Fatalf("scoped L7 fixture must only match the control pod: %v", rule)
			}
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
	for _, name := range []string{"authz-unenrolled", "authz-unknown", "cnp-l7", "native-source", "native-target", "cnp-observe", "authz-default", "authz-denyonly", "authz-audit", "authz-dryrun", "authz-injection"} {
		if !names[name] {
			t.Fatalf("mesh enrollment or scoped uncertainty fixture %s disappeared", name)
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
	meshes := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 5 || seen[fields[0]+"/"+fields[1]] {
			t.Fatalf("invalid or duplicate pod fixture %q", line)
		}
		seen[fields[0]+"/"+fields[1]] = true
		counts[fields[0]]++
		meshes[fields[1]] = fields[4]
	}
	if len(seen) != 40 || counts["stub-demo-edge-src"] != 11 ||
		counts["stub-demo-edge-dst"] != 23 || counts["stub-demo-edge-other"] != 6 ||
		!seen["stub-demo-edge-other/control"] {
		t.Fatalf("isolated pod inventory changed: %#v", counts)
	}
	if meshes["authz-unenrolled"] != "opt-out" || meshes["authz-unknown"] != "stale-sidecar" || meshes["authz-server"] != "-" {
		t.Fatalf("mesh enrollment fixtures changed: %#v", meshes)
	}
	for pod, fixture := range map[string]string{
		"native-excluded": "selector-excluded", "authz-inject-annotation": "inject-annotation",
		"authz-inject-label": "inject-label", "authz-inject-optout": "inject-optout",
	} {
		if meshes[pod] != fixture {
			t.Fatalf("missing metadata specimen %s: %s", pod, meshes[pod])
		}
	}
	mesh, err := bashScript(t, `source "$LIB"
printf '%s,' "$(edge_namespace_mesh source)" "$(edge_namespace_mesh destination)" "$(edge_namespace_mesh other)"
printf '%s,' "$(edge_pod_mesh opt-out)" "$(edge_pod_mesh stale-sidecar)" "$(edge_pod_mesh -)"`, "LIB="+edgeLibrary(t))
	if err != nil || string(mesh) != `ambient,ambient,,none|,|{"containers":["istio-proxy"]},|,` {
		t.Fatalf("mesh fixture labels changed: %v %q", err, mesh)
	}
}

func TestExpandedFixtureMetadataAndPolicyContracts(t *testing.T) {
	script := `source "$LIB"
PREFIX=stub-demo
NS_EDGE_SRC=stub-demo-edge-src
NS_EDGE_DST=stub-demo-edge-dst
NS_EDGE_OTHER=stub-demo-edge-other
EDGE_SCENARIO=stub-demo-edges
IMAGE=stub-image
WAIT=0
fixture_kubectl() { if [[ "$1" == apply ]]; then cat; fi; }
KUBECTL=(fixture_kubectl)
edge_policy() { :; }
apply_edge_fixtures`
	output, err := bashScript(t, script, "LIB="+edgeLibrary(t))
	if err != nil {
		t.Fatalf("render fixture metadata: %v\n%s", err, output)
	}
	decoder := json.NewDecoder(strings.NewReader(string(output)))
	pods := map[string]map[string]any{}
	for {
		var object map[string]any
		if err := decoder.Decode(&object); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if object["kind"] == "Pod" {
			metadata := object["metadata"].(map[string]any)
			pods[metadata["name"].(string)] = metadata
		}
	}
	if len(pods) != 40 {
		t.Fatalf("population differs from inventory: %d pods", len(pods))
	}
	if _, exists := pods["native-target"]["labels"].(map[string]any)["netpol-role"]; exists {
		t.Fatal("native NotIn absence fixture acquired a role label")
	}
	if pods["native-excluded"]["labels"].(map[string]any)["netpol-excluded"] != "true" {
		t.Fatal("native DoesNotExist control lost its excluded label")
	}
	for _, specimen := range []struct {
		name, label, annotation string
	}{
		{"authz-inject-annotation", "", "true"},
		{"authz-inject-label", "true", "false"},
		{"authz-inject-optout", "false", "true"},
	} {
		pod := pods[specimen.name]
		label, _ := pod["labels"].(map[string]any)["sidecar.istio.io/inject"].(string)
		annotation := pod["annotations"].(map[string]any)["sidecar.istio.io/inject"]
		if label != specimen.label || annotation != specimen.annotation || pod["namespace"] != "stub-demo-edge-other" {
			t.Fatalf("wrong nonambient injection metadata for %s: %v", specimen.name, pod)
		}
	}
}

func TestDryRunAnnotationDriftIsRejected(t *testing.T) {
	script := `source "$LIB"
PREFIX=stub-demo
PROBE=""
PROBE_ID=""
EDGE_MODE=check
fixture_kubectl() {
  case "$1" in
    create)
      cat >/dev/null
      case "$*" in *metadata.annotations*) printf true ;; *) printf 'spec|' ;; esac ;;
    get)
      case "$*" in
        *metadata.labels*) printf 'stub-demo|true||' ;;
        *metadata.annotations*) printf '%s' "$ACTUAL" ;;
        *) printf 'spec|' ;;
      esac ;;
  esac
}
KUBECTL=(fixture_kubectl)
edge_policy authz AuthorizationPolicy security.istio.io/v1 example dryrun '"spec":{"action":"DENY","rules":[{}]}' '{"istio.io/dry-run":"true"}'`
	for _, actual := range []string{"true", "false", ""} {
		output, err := bashScript(t, script, "LIB="+edgeLibrary(t), "ACTUAL="+actual)
		if (err == nil) != (actual == "true") {
			t.Fatalf("dry-run drift %q: %v\n%s", actual, err, output)
		}
	}
}

func TestProbeInventoryAndMultiplePolicyOwnership(t *testing.T) {
	script := `source "$LIB"
PREFIX=stub-demo
PROBE_ID=run-123
NS_EDGE_SRC=stub-demo-edge-src
NS_EDGE_DST=stub-demo-edge-dst
NS_EDGE_OTHER=stub-demo-edge-other
edge_policy() { printf '%s\000%s\000%s\000%s\000' "$PROBE" "$4" "$5" "{$6}"; }
while read -r PROBE; do edge_probe_policy || exit; done < <(edge_probe_types)`
	output, err := bashScript(t, script, "LIB="+edgeLibrary(t))
	if err != nil {
		t.Fatalf("probe inventory: %v\n%s", err, output)
	}
	fields := strings.Split(strings.TrimSuffix(string(output), "\x00"), "\x00")
	if len(fields) != 11*4 {
		t.Fatalf("expected 11 owned policies across eight probe modes, got %d fields", len(fields))
	}
	counts := map[string]int{}
	for index := 0; index < len(fields); index += 4 {
		suite, namespace, name, body := fields[index], fields[index+1], fields[index+2], fields[index+3]
		counts[suite]++
		if !strings.HasSuffix(name, "-run-123") {
			t.Fatalf("probe is not run-qualified: %s", name)
		}
		var policy map[string]any
		if err := json.Unmarshal([]byte(body), &policy); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if suite == "istio-root" {
			selector := policy["spec"].(map[string]any)["selector"].(map[string]any)["matchLabels"].(map[string]any)
			if namespace != "istio-system" || selector["netpol-demo-prefix"] != "stub-demo" {
				t.Fatalf("root probe is not prefix-isolated: %s %v", namespace, selector)
			}
		}
	}
	if len(counts) != 8 || counts["istio-features"] != 4 {
		t.Fatalf("probe suite inventory changed: %v", counts)
	}

	ownership := `source "$LIB"
PREFIX=stub-demo
PROBE=istio-features
PROBE_ID=run-123
NS_EDGE_SRC=stub-demo-edge-src
NS_EDGE_DST=stub-demo-edge-dst
EDGE_MODE=delete
fixture_kubectl() {
  case "$1" in
    get) printf '%s|stub-demo|%s' "$3" "$OWNER_ID" ;;
    delete) printf 'DELETE %s\n' "$*" ;;
    *) return 90 ;;
  esac
}
KUBECTL=(fixture_kubectl)
edge_probe_policy`
	for _, owner := range []string{"run-123", "another-run"} {
		output, err := bashScript(t, ownership, "LIB="+edgeLibrary(t), "OWNER_ID="+owner)
		if owner == "run-123" {
			if err != nil || strings.Count(string(output), "DELETE ") != 4 {
				t.Fatalf("multi-policy owned cleanup failed: %v\n%s", err, output)
			}
		} else if err == nil || strings.Contains(string(output), "DELETE ") {
			t.Fatalf("multi-policy cleanup deleted an unowned policy: %v\n%s", err, output)
		}
	}
}

func TestMultiProbeCleanupContinuesAfterDeletionFailure(t *testing.T) {
	script := `source "$LIB"
PREFIX=stub-demo
PROBE=istio-features
PROBE_ID=run-123
NS_EDGE_SRC=stub-demo-edge-src
NS_EDGE_DST=stub-demo-edge-dst
EDGE_MODE=delete
fixture_kubectl() {
  case "$1" in
    get) printf '%s|stub-demo|run-123' "$3" ;;
    delete)
      printf 'DELETE %s\n' "$3"
      [[ "$3" != probe-istio-l7-allow-run-123 ]] ;;
    *) return 90 ;;
  esac
}
KUBECTL=(fixture_kubectl)
edge_probe_policy`
	output, err := bashScript(t, script, "LIB="+edgeLibrary(t))
	if err == nil || strings.Count(string(output), "DELETE ") != 4 {
		t.Fatalf("failed deletion skipped other owned policies or lost its error: %v\n%s", err, output)
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
    create)
      cat >/dev/null
      case "$*" in
        *metadata.annotations*) ;;
        *) printf '%s' '{"ingress":[{}]}|' ;;
      esac ;;
    get)
      case "$*" in
        *metadata.labels*) printf 'stub-demo|true||' ;;
        *metadata.annotations*) ;;
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
		{"cilium-features", "ciliumnetworkpolicies.cilium.io", "stub-demo-edge-src"},
		{"cilium-rejected", "ciliumnetworkpolicies.cilium.io", "stub-demo-edge-src"},
		{"istio-custom", "authorizationpolicies.security.istio.io", "stub-demo-edge-dst"},
		{"istio-targetrefs", "authorizationpolicies.security.istio.io", "stub-demo-edge-dst"},
		{"istio-root", "authorizationpolicies.security.istio.io", "istio-system"},
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
			for _, suite := range []string{"identity", "unsupported", "cilium-features", "cilium-rejected", "istio-features", "istio-custom", "istio-targetrefs", "istio-root"} {
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
	if strings.Contains(string(commands), "delete crd ") || strings.Contains(string(commands), "istio-system") {
		t.Fatalf("ordinary cleanup touched a shared CRD or root namespace:\n%s", commands)
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
	set rules "┌ Egress · Rules ┐\n│[format $columns {scenario/cnp-source specs[0] #0} CiliumNetworkPolicy {TCP/8080, TCP/8081}]│\n│subjects 1/1                       peer podSelector=app=cnp-server│\n│────────────                      ────────────│\n│[format $columns {scenario/cnp-source specs[1] deny #0} CiliumNetworkPolicy TCP/8081]│\n└"
	foreach {action ports spec index} {ALLOW {TCP/8080, TCP/8081} specs[0] 0 DENY TCP/8081 specs[1] 1} {
	  set screen "$rules\nRule Details\nPolicy: scenario/cnp-source\nPolicy type: CiliumNetworkPolicy\nPolicy API version: cilium.io/v2\nAction: [string tolower $action]\nRule index: 0 in $spec (spec index $index)\nApplicability (Egress)"
	  if {![assert_selected_edge_rule $screen Egress scenario/cnp-source CiliumNetworkPolicy cilium.io/v2 $action $ports $spec 1]} {
	    error "valid $action $spec rule was rejected"
	  }
	  set label [expected_rule_label scenario/cnp-source $action $spec 1]
	  foreach {from to} [list \
	    {Policy: scenario/cnp-source} {Policy: scenario/cnp-source-other} \
	    {Policy type: CiliumNetworkPolicy} {Policy type: CNP} \
	    {API version: cilium.io/v2} {API version: cilium.io/v1} \
	    $label [string map {{ #0} { #1}} $label] \
	    "in $spec (spec" "in specs\[9\] (spec" \
	    {Rule index: 0} {Rule index: 1} \
	  ] {
	    set changed [string map [list $from $to] $screen]
	    if {![catch {assert_selected_edge_rule $changed Egress scenario/cnp-source CiliumNetworkPolicy cilium.io/v2 $action $ports $spec 1}]} {
	      error "incorrect selected origin passed: $from => $to"
	    }
	  }
	  if {![catch {assert_selected_edge_rule "$screen\nSpec index: 1" Egress scenario/cnp-source CiliumNetworkPolicy cilium.io/v2 $action $ports $spec 1}]} {
	    error "invented spec-index detail label passed"
	  }
	  if {![catch {assert_selected_edge_rule $screen Egress scenario/cnp-source CiliumNetworkPolicy cilium.io/v2 $action $ports $spec 0}]} {
	    error "a single-spec label matched a multi-spec rule row"
	  }
	  set other_action DENY
	  if {$action eq "DENY"} { set other_action ALLOW }
	  if {![catch {assert_selected_edge_rule $screen Egress scenario/cnp-source CiliumNetworkPolicy cilium.io/v2 $other_action $ports $spec 1}]} {
	    error "the action suffix did not distinguish allow from deny"
	  }
	}
	foreach {reference action spec multi label} {
	  scenario/np ALLOW {} 0 {scenario/np #0}
	  scenario/cnp DENY spec 0 {scenario/cnp deny #0}
	  scenario-ccnp ALLOW specs[1] 1 {scenario-ccnp specs[1] #0}
	  scenario-ccnp DENY specs[1] 1 {scenario-ccnp specs[1] deny #0}
	} {
	  if {[expected_rule_label $reference $action $spec $multi] ne $label} { error "wrong expected label for $reference $action $spec" }
	}
	if {[rule_spec any Egress ALLOW] ne {{} 0}} { error "helper rule_spec must default to non-Cilium rules" }
	set screen "┌ Ingress · Rules ┐\n│[format $columns {scenario-edge-ccnp specs[1] #0} CiliumClusterwideNetworkPolicy {TCP/9091, TCP/9092}]│\n└\nRule Details\nPolicy: —/scenario-edge-ccnp\nPolicy type: CiliumClusterwideNetworkPolicy\nPolicy API version: cilium.io/v2\nAction: allow\nRule index: 0 in specs\[1\] (spec index 1)\nApplicability (Ingress)"
	set screen [string map {\\ {}} $screen]
	if {![assert_selected_edge_rule $screen Ingress scenario-edge-ccnp CiliumClusterwideNetworkPolicy cilium.io/v2 ALLOW {TCP/9091, TCP/9092} specs\[1\] 1]} {
	  error "cluster-scoped policy details did not match their namespace-free rule row"
	}
	if {![catch {assert_selected_edge_rule $screen Ingress scenario-edge-ccnp CiliumClusterwideNetworkPolicy cilium.io/v2 ALLOW TCP/9091-9092 specs\[1\] 1}]} {
	  error "raw declared ports were incorrectly accepted as a merged range"
	}
	set native [format "┌ Egress · Rules ┐\n│%-50s %-30s %s│\n└\nRule Details\nPolicy: scenario/authz-source-network\nPolicy type: NetworkPolicy\nPolicy API version: networking.k8s.io/v1\nAction: allow\nRule index: 0\n" {scenario/authz-source-network #0} NetworkPolicy {SCTP/9000, TCP/8080, TCP/8081, UDP/5353}]
	set rows [rule_rows $native "Egress · Rules"]
	if {[llength $rows] != 1 || [dict get [lindex $rows 0] Name] ne "scenario/authz-source-network #0" ||
	    [dict get [lindex $rows 0] Type] ne "NetworkPolicy" ||
	    [dict get [lindex $rows 0] Ports] ne "SCTP/9000, TCP/8080, TCP/8081, UDP/5353"} {
	  error "headerless native row lost its exact name/type/declared ports: $rows"
	}
	if {![assert_selected_edge_rule $native Egress scenario/authz-source-network NetworkPolicy networking.k8s.io/v1 ALLOW {SCTP/9000, TCP/8080, TCP/8081, UDP/5353}]} {
	  error "native rule without a spec entry was rejected"
	}
	if {![catch {assert_selected_edge_rule [string map {{Rule index: 0} {Rule index: 0 in spec (spec index 0)}} $native] Egress scenario/authz-source-network NetworkPolicy networking.k8s.io/v1 ALLOW {SCTP/9000, TCP/8080, TCP/8081, UDP/5353}]}]} {
	  error "a native rule accepted a Cilium spec entry"
	}
	if {[llength [rule_rows $native "Ingress · Rules"]] != 0} { error "rules came from the opposite direction" }
	set synthetic [format "┌ Ingress · Rules ┐\n│%-50s %-30s %s│\n└\n" {authorization default-deny (TCP) #-1} Synthetic {no ports}]
	set rows [rule_rows $synthetic "Ingress · Rules"]
	if {[llength $rows] != 1 || [dict get [lindex $rows 0] Name] ne "authorization default-deny (TCP) #-1" || [dict get [lindex $rows 0] Type] ne "Synthetic"} {
	  error "authorization default-deny row was not parsed: $rows"
	}
	puts "spec entries, action suffixes and full origin checks passed"
	`
	output, err := expectScript(t, script)
	if err != nil {
		t.Fatalf("selected rule identity contract: %v\n%s", err, output)
	}
	t.Log(strings.TrimSpace(string(output)))
}

func TestIdentityNoteScanScrollsRuleDetails(t *testing.T) {
	script := `
	proc fail_case {message} { lappend ::failed $message }
	proc send_key {key args} {
	  lappend ::keys $key
	  if {$key eq "\033\[B"} { incr ::offset }
	  if {$key eq "\033\[H"} { set ::offset 0 }
	}
	proc capture_screen {} {
	  set visible [lrange $::details $::offset [expr {$::offset + 2}]]
	  return "┌ Rule Details ┐\n│[join $visible "│\n│"]│\n└"
	}
	foreach {mutation details want} {
	  none {{Policy: d/probe} {State: Allowed (Allowed)} {Peers:} {Rule YAML:} {Notes:} {  - ... mesh mTLS ...}} 1
	  partial {{Policy: d/probe} {State: Partial Data (Partial Data)} {Notes:} {  - ... mesh mTLS ...}} 0
	  warning {{Policy: d/probe} {State: Allowed (Allowed)} {Warnings:} {  - uncertain} {  - ... mesh mTLS ...}} 0
	  missing {{Policy: d/probe} {State: Allowed (Allowed)} {Peers:} {Rule YAML:}} 0
	} {
	  set failed {}
	  set keys {}
	  set offset 0
	  set got [scan_rule_details {{State: Allowed (Allowed)} {mesh mTLS}} {{Partial Data} Warnings:}]
	  if {$got != $want || ($want == 1 && [llength $failed] != 0) || ($want == 0 && [llength $failed] == 0)} {
	    error "rule details scan mutation $mutation returned $got: $failed"
	  }
	  if {[lindex $keys 0] ne "\t" || [lindex $keys 1] ne "\033\[H"} { error "scan did not focus and rewind the details" }
	}
	puts "rule details are scanned from the top for required notes and forbidden partial state"
	`
	output, err := expectScript(t, script)
	if err != nil {
		t.Fatalf("rule details scan contract: %v\n%s", err, output)
	}
	t.Log(strings.TrimSpace(string(output)))
}

func TestAuthorizationDefaultDenyRowContract(t *testing.T) {
	script := `
	set ns_edge_dst scenario
	proc start_case {name args} { if {$name ne "istio-authorization-default-deny-row"} { error "unexpected case $name" } }
	proc pass_case {} { incr ::passed }
	proc fail_case {message} { lappend ::failed $message }
	proc open_edge_subject {args} { return 1 }
	proc capture_screen {} {
	  set columns "%-50s %-30s %s"
	  set screen "┌ Ingress · Rules ┐\n"
	  foreach {name type ports} $::rows { append screen "│[format $columns $name $type $ports]│\n" }
	  return "$screen└"
	}
	foreach {mutation rows} {
	  none {{authorization default-deny (TCP) #-1} Synthetic {no ports} {default-deny #-1} Synthetic {no ports}}
	  missing-authz {{default-deny #-1} Synthetic {no ports}}
	  missing-network {{authorization default-deny (TCP) #-1} Synthetic {no ports}}
	  unrestricted {{authorization default-deny (TCP) #-1} Synthetic {no ports} {default-deny #-1} Synthetic {no ports} {unrestricted #-1} Synthetic {SCTP/all, TCP/all, UDP/all}}
	  wrong-type {{authorization default-deny (TCP) #-1} AuthorizationPolicy {no ports} {default-deny #-1} Synthetic {no ports}}
	} {
	  set passed 0
	  set failed {}
	  verify_authorization_default_deny_row authz-no-tcp scenario
	  if {$mutation eq "none"} {
	    if {$passed != 1 || [llength $failed] != 0} { error "valid synthetic rows were rejected: $failed" }
	  } elseif {$passed != 0 || [llength $failed] == 0} {
	    error "synthetic row mutation escaped the assertions: $mutation"
	  }
	}
	puts "per-layer synthetic rows are asserted exactly"
	`
	output, err := expectScript(t, script)
	if err != nil {
		t.Fatalf("authorization default-deny row contract: %v\n%s", err, output)
	}
	t.Log(strings.TrimSpace(string(output)))
}

func TestHostNetworkPeerContract(t *testing.T) {
	script := `
	proc start_case {name args} { set ::case $name }
	proc pass_case {} { incr ::passed }
	proc fail_case {message} { lappend ::failed $message }
	proc open_edge_subject {args} { return 1 }
	proc send_key {args} {}
	proc filter_to {value} { set ::filter $value; return 1 }
	proc wait_for_frame {predicate args} {
	  set screen [screen_for_mutation]
	  if {[{*}$predicate $screen]} { return $screen }
	  set ::last_wait_screen $screen
	  return ""
	}
	proc screen_for_mutation {} {
	  set columns "%-60s %-8s %-10s %-14s %s"
	  set heading "Pod scenario/cnp-server · 1 pod\nIngress · Rules\nSelection: none\nEffective Details"
	  set state {Partial Data}
	  set name kube-proxy-x7k2p
	  switch -- $::mutation {
	    wrong-state { set state Disallowed }
	    other-pod { set name kindnet-abcde }
	  }
	  set rows [format $columns "Pod kube-system/$name" false true $state {no ports}]
	  if {$::mutation eq "two-rows"} { append rows "\n" [format $columns "Pod kube-system/kube-proxy-other" false true $state {no ports}] }
	  return "$heading\nEffective Applicability (Ingress)\n[format $columns Primitive Peer Opposite State Ports]\n$rows\n└"
	}
	foreach mutation {none wrong-state other-pod two-rows} {
	  set passed 0
	  set failed {}
	  verify_hostnetwork_peer cilium-hostnetwork-peer-partial-data cnp-server scenario Ingress {Partial Data} {no ports} 1
	  if {$mutation eq "none"} {
	    if {$passed != 1 || [llength $failed] != 0 || $filter ne "Pod kube-system/kube-proxy-"} { error "valid hostNetwork row rejected: $failed" }
	  } elseif {$passed != 0 || [llength $failed] == 0} {
	    error "hostNetwork mutation escaped the assertions: $mutation"
	  }
	}
	puts "hostNetwork peer rows are matched by DaemonSet prefix exactly once"
	`
	output, err := expectScript(t, script)
	if err != nil {
		t.Fatalf("hostNetwork peer contract: %v\n%s", err, output)
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
	set warning "Warning: CiliumNetworkPolicy $reference: egress allow rule 0: toFQDNs requires live DNS resolution"
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
	if {$passed != 1 || $keys ne [list "\t" "\033\[H"]} {
	  error "probe did not inspect effective diagnostics exactly once from the top: $passed / $keys"
	}
	foreach {from to} {
	  {CiliumNetworkPolicy netpol} {CiliumClusterwideNetworkPolicy netpol}
	  {probe-unsupported-20260912-200409-79177:} {probe-unsupported-another-run:}
	  {egress allow rule 0} {ingress allow rule 0}
	  {toFQDNs} {toEndpoints}
	  {Effective Details} {Rule Details}
	  {uncertain-client · 1 pod} {other-client · 1 pod}
	  {PARTIAL DATA (7 warning(s))} {}
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
	puts "exact per-rule policy diagnostic and partial-state surfaces replayed with negative controls"
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
	expected := map[string]int{"known": 101, "identity": 2, "unsupported": 2,
		"cilium-features": 3, "cilium-rejected": 2, "istio-features": 8,
		"istio-custom": 2, "istio-targetrefs": 2, "istio-root": 3}
	if len(seen) != 125 || len(counts) != len(expected) {
		t.Fatalf("smoke inventory changed without updating its contract: %#v", counts)
	}
	for suite, count := range expected {
		if counts[suite] != count {
			t.Fatalf("%s smoke count: got %d, want %d", suite, counts[suite], count)
		}
	}
	for _, name := range []string{
		"cnp-empty-rule-ingress", "cnp-empty-rule-egress",
		"ccnp-empty-rule-ingress", "ccnp-empty-rule-egress",
		"cilium-cidr-narrow-deny", "istio-source-ingress-deny-egress-control",
		"istio-unenrolled-ingress", "istio-unenrolled-egress",
		"istio-enrollment-unknown-ingress", "istio-enrollment-unknown-egress",
		"cilium-l7-scoped-ingress", "cilium-l7-scoped-egress",
		"cilium-l7-unmatched-peer-ingress", "cilium-l7-unmatched-peer-egress",
		"cilium-hostnetwork-peer-partial-data", "hostnetwork-peer-native-control",
		"istio-authorization-default-deny-row",
		"istio-identity-ingress-note", "istio-identity-egress-note",
		"unsupported-cilium-rule-details", "unsupported-scoped-egress-control",
		"native-range-protocol-ingress", "native-range-protocol-egress", "native-zero-pair-not-applicable",
		"native-notin-blocked", "native-doesnotexist-excluded", "native-namespace-and-control",
		"cilium-nonisolating-combined-spec-navigation", "cilium-cnp-namespace-scope-control-egress",
		"istio-inject-annotation", "istio-inject-label-precedence", "istio-inject-optout-precedence",
		"cilium-unsupported-fields-diagnostics", "cilium-rejected-sibling-diagnostics",
		"istio-root-policy-navigation", "istio-targetrefs-diagnostics", "istio-custom-diagnostics",
	} {
		if !seen[name] {
			t.Fatalf("required regression case %s disappeared", name)
		}
	}
}

func TestConsumedEOFStillFinishesSmokeAccounting(t *testing.T) {
	_, _, smoke := harnessPaths(t)
	source, err := os.ReadFile(smoke)
	if err != nil {
		t.Fatal(err)
	}
	_, summary, found := strings.Cut(string(source), "\nfinish_smoke_process\n")
	if !found {
		t.Fatal("smoke teardown/authoritative summary boundary is missing")
	}
	directory := t.TempDir()
	script := `
	set screen_eof 1
	set startup_screen ready
	set navigation_setup_error {process crashed}
	set container fixture-only
	set kills 0
	rename exec real_exec
	proc exec {args} {
	  if {$args ne {docker kill fixture-only}} { error "unexpected cleanup command $args" }
	  incr ::kills
	}
	proc expect {args} { error "a consumed EOF reopened the closed spawn" }
	proc send_key {args} { error "keys sent after EOF" }
	proc close_case {} {}
	set suite known
	set log_dir $env(VERDICT_DIR)
	set failures 1
	set case_manifest [dict create known {launch-npg-view crashed-case}]
	set verdicts [dict create launch-npg-view PASS crashed-case FAIL]
	finish_smoke_process
	if {$kills != 1} { error "crashed process cleanup was skipped" }
	` + summary
	output, err := expectScript(t, script, "VERDICT_DIR="+directory)
	if err == nil || !strings.Contains(string(output), "=== 2 case(s), 1 failure(s) ===") {
		t.Fatalf("consumed EOF failed to retain its authoritative summary/status: %v\n%s", err, output)
	}
	verdicts, err := os.ReadFile(filepath.Join(directory, "smoke-known.verdicts"))
	if err != nil || string(verdicts) != "PASS\tlaunch-npg-view\nFAIL\tcrashed-case\n" {
		t.Fatalf("crash erased earlier case verdicts: %v\n%s", err, verdicts)
	}
}

func TestEmptySubjectReadinessDoesNotAcceptLoading(t *testing.T) {
	script := `
	set subject {Deployment fixture/scaled-to-zero · 0 pods}
	set ready "┌ Subject ┐\n│$subject│\n│No workloads found for this subject.│\n└\nIngress · Rules\nEffective Details\nEffective Applicability (Ingress)\n<npg>"
	if {![empty_graph_ready $subject $ready]} { error "fully evaluated empty subject was rejected" }
	if {[empty_graph_ready $subject [string map {{No workloads found for this subject.} {No subject workloads match the active filter.}} $ready]]} { error "filter-empty was mistaken for an empty subject" }
	foreach marker {{Waiting for NetworkPolicy evaluation...} {workloads loading...} {> npg deployment scaled-to-zero fixture}} {
	  if {[empty_graph_ready $subject "$ready\n$marker"]} { error "unready empty frame passed: $marker" }
	}
	foreach value {{Deployment fixture/other · 0 pods} {Deployment fixture/scaled-to-zero · 1 pod}} {
	  if {[empty_graph_ready $subject [string map [list $subject $value] $ready]]} { error "wrong empty subject passed" }
	}
	set columns "%-8s %-16s %-25s %s"
	set populated "┌ Subject ┐\n│$subject│\n│[format $columns KIND NAMESPACE NAME STATUS]│\n│[format $columns Pod fixture unexpected {Running · 1/1 ready}]│\n└\nIngress · Rules\nEffective Details\nEffective Applicability (Ingress)\n<npg>"
	if {[empty_graph_ready $subject $populated]} { error "0-pod summary hid a real workload row" }
	puts "empty-subject readiness is separate from ready-pod admission"
	`
	output, err := expectScript(t, script)
	if err != nil {
		t.Fatalf("empty-subject readiness contract: %v\n%s", err, output)
	}
}

func TestNonisolatingRulesHideOnlyEmptyAliasRule(t *testing.T) {
	script := `
	proc fail_case {message} { error $message }
	set reference fixture/cnp-observe
	set format "%-60s %-30s %s"
	set deny [format $format {fixture/cnp-observe specs[0] deny #0} CiliumNetworkPolicy TCP/8081]
	set allow [format $format {fixture/cnp-observe spec #1} CiliumNetworkPolicy TCP/8080]
	set hidden [format $format {fixture/cnp-observe spec #0} CiliumNetworkPolicy TCP/80]
	set native [format $format {fixture/cnp-observe-network #0} NetworkPolicy {SCTP/9000, TCP/8080, TCP/8081, UDP/5353}]
	set valid "┌ Egress · Rules ┐\n│$deny│\n│$allow│\n│$native│\n└"
	if {![assert_nonisolating_rule_rows $valid $reference]} { error "exact visible rules rejected" }
	foreach changed [list \
	    [string map [list $allow $hidden] $valid] \
	    [string map [list $allow ""] $valid] \
	    [string map [list $deny "$deny\n$deny"] $valid] \
	    [string map [list $allow "$allow\n$hidden"] $valid] \
	    [string map {{specs[0]} {specs[1]}} $valid] \
	    [string map {CiliumNetworkPolicy NetworkPolicy} $valid] \
	    [string map {TCP/8080 TCP/80} $valid]] {
	  if {![catch {assert_nonisolating_rule_rows $changed $reference}]} {
	    error "incorrect visible rule set passed"
	  }
	}
	set body [info body verify_nonisolating_policy]
	if {[string first {ALLOW 0 spec 0 TCP/80} $body] >= 0 ||
	    [string first {assert_nonisolating_rule_rows} $body] < 0} {
	  error "live navigation still selects the hidden rule or skips its exact visibility assertion"
	}
	puts "hidden empty alias rule and complete visible rule set are asserted exactly"
	`
	output, err := expectScript(t, script)
	if err != nil {
		t.Fatalf("empty alias rule presentation: %v\n%s", err, output)
	}
}

func TestExpandedExactDiagnosticsAndSpecOrdinals(t *testing.T) {
	script := `
	proc fail_case {message} { error $message }
	set warning {Warning: AuthorizationPolicy fixture/probe: ingress allow rule 0: requestPrincipals depend on JWT request identity}
	set screen "┌ Effective Details ┐\n│Warning: AuthorizationPolicy fixture/probe: ingress allow rule 0:│\n│ requestPrincipals depend on JWT request identity│\n└\n$warning"
	if {[detail_text $screen "Effective Details"] ne $warning} { error "wrapped exact diagnostic was not reconstructed" }
	set wrong [string map {{fixture/probe:} {fixture/other:}} [join [panel_lines $screen "Effective Details"] "\n"]]
	if {[string first $warning [detail_text "┌ Effective Details ┐\n$wrong\n└\n$warning" "Effective Details"]] >= 0} {
	  error "warning outside the panel satisfied policy identity"
	}
	set columns "%-60s %-30s %s"
	set row [format $columns {fixture/cnp-observe specs[0] deny #0} CiliumNetworkPolicy TCP/8081]
	set screen "┌ Egress · Rules ┐\n│$row│\n└\nRule Details\nPolicy: fixture/cnp-observe\nPolicy type: CiliumNetworkPolicy\nPolicy API version: cilium.io/v2\nAction: deny\nRule index: 0 in specs\[0\] (spec index 1)\n"
	if {![assert_selected_edge_rule $screen Egress fixture/cnp-observe CiliumNetworkPolicy cilium.io/v2 DENY TCP/8081 {specs[0]} 1 0 1]} { error "correct ordinal rejected" }
	foreach changed [list [string map {{spec index 1} {spec index 0}} $screen] [string map {{Rule index: 0} {Rule index: 1}} $screen]] {
	  if {![catch {assert_selected_edge_rule $changed Egress fixture/cnp-observe CiliumNetworkPolicy cilium.io/v2 DENY TCP/8081 {specs[0]} 1 0 1}]} { error "wrong spec ordinal or rule index passed" }
	}
	set row [dict create State {Partial Data} Peer false Opposite false Ports {no ports}]
	assert_applicability_values $row {Partial Data} {no ports} false false
	if {![catch {assert_applicability_values $row {Partial Data} {no ports} true true}]} { error "partial state invented matching evidence" }
	set row [dict create State {Partial Data} Peer true Opposite true Ports {SCTP/all, TCP/all, UDP/all}]
	assert_applicability_values $row {Partial Data} {SCTP/all, TCP/all, UDP/all} true true
	if {![catch {assert_applicability_values $row {Partial Data} {all ports} true true}]} { error "wildcard text was weakened" }
	puts "wrapped diagnostics, combined spec ordinals and uncertainty flags are exact"
	`
	output, err := expectScript(t, script)
	if err != nil {
		t.Fatalf("expanded exact presentation contracts: %v\n%s", err, output)
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
