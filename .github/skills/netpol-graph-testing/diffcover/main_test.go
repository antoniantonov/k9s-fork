// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseChangedLinesAndCalculateCoverage(t *testing.T) {
	diff := `diff --git a/internal/netpol/policy.go b/internal/netpol/policy.go
--- a/internal/netpol/policy.go
+++ b/internal/netpol/policy.go
@@ -4,0 +5,2 @@
+first
+second
@@ -10 +12 @@
-old
+new
diff --git a/internal/netpol/deleted.go b/internal/netpol/deleted.go
--- a/internal/netpol/deleted.go
+++ /dev/null
@@ -1,2 +0,0 @@
-one
-two
`
	changed, err := parseChangedLines(strings.NewReader(diff))
	if err != nil {
		t.Fatalf("parse diff: %v", err)
	}
	if len(changed) != 1 {
		t.Fatalf("expected one changed file, got %#v", changed)
	}
	for _, line := range []int{5, 6, 12} {
		if _, ok := changed["internal/netpol/policy.go"][line]; !ok {
			t.Fatalf("missing changed line %d", line)
		}
	}

	profile := `mode: atomic
github.com/derailed/k9s/internal/netpol/policy.go:5.1,5.9 2 0
github.com/derailed/k9s/internal/netpol/policy.go:5.1,5.9 2 3
github.com/derailed/k9s/internal/netpol/policy.go:6.1,8.2 3 0
github.com/derailed/k9s/internal/netpol/policy.go:12.1,12.8 5 1
github.com/derailed/k9s/internal/netpol/policy.go:20.1,20.8 7 1
`
	blocks, err := parseCoverProfile(strings.NewReader(profile))
	if err != nil {
		t.Fatalf("parse profile: %v", err)
	}
	results := calculateCoverage(changed, blocks)
	if len(results) != 1 {
		t.Fatalf("expected one result, got %#v", results)
	}
	result := results[0]
	if result.covered != 7 || result.statements != 10 {
		t.Fatalf("expected 7/10 statements, got %d/%d", result.covered, result.statements)
	}
	if result.percent() != 70 {
		t.Fatalf("expected 70%%, got %.1f%%", result.percent())
	}
}

func TestParserErrorsAndThresholdValues(t *testing.T) {
	if _, err := parseChangedLines(strings.NewReader("@@ -1 +1 @@\n")); err == nil {
		t.Fatal("expected a hunk-without-file error")
	}
	if _, err := parseChangedLines(strings.NewReader("+++ b/file.go\n@@ invalid @@\n")); err == nil {
		t.Fatal("expected an invalid hunk error")
	}
	if _, err := parseCoverProfile(strings.NewReader("not-a-profile\n")); err == nil {
		t.Fatal("expected a missing mode error")
	}
	if _, err := parseCoverProfile(strings.NewReader("mode: set\ninvalid\n")); err == nil {
		t.Fatal("expected an invalid profile line error")
	}
	if _, err := parseCoverProfile(strings.NewReader("")); err == nil {
		t.Fatal("expected an empty profile error")
	}

	thresholds := fileThresholds{}
	if err := thresholds.Set("internal/netpol/policy.go=80"); err != nil {
		t.Fatalf("set threshold: %v", err)
	}
	if thresholds["internal/netpol/policy.go"] != 80 {
		t.Fatalf("unexpected threshold: %#v", thresholds)
	}
	if err := thresholds.Set("missing"); err == nil {
		t.Fatal("expected malformed threshold error")
	}
	if err := thresholds.Set("file.go=bad"); err == nil {
		t.Fatal("expected invalid percentage error")
	}
	if err := thresholds.Set("file.go=101"); err == nil {
		t.Fatal("expected out-of-range percentage error")
	}
	if thresholds.String() != "internal/netpol/policy.go=80.0" {
		t.Fatalf("unexpected threshold string: %s", thresholds.String())
	}
}

func TestCoverageHelpers(t *testing.T) {
	if got := (coverageResult{}).percent(); got != 100 {
		t.Fatalf("empty coverage should be 100%%, got %.1f", got)
	}
	if !profilePathMatches(
		"github.com/derailed/k9s/internal/netpol/policy.go",
		"internal/netpol/policy.go",
	) {
		t.Fatal("module profile path should match repository path")
	}
	if profilePathMatches("internal/netpol/other.go", "internal/netpol/policy.go") {
		t.Fatal("different paths must not match")
	}
	if !blockOverlapsLines(coverBlock{startLine: 2, endLine: 4}, lineSet{3: {}}) {
		t.Fatal("expected block overlap")
	}
	if blockOverlapsLines(coverBlock{startLine: 2, endLine: 4}, lineSet{5: {}}) {
		t.Fatal("unexpected block overlap")
	}
}

func TestRunIncludesTrackedAndUntrackedChanges(t *testing.T) {
	repository := t.TempDir()
	runGit(t, repository, "init", "-b", "master")
	runGit(t, repository, "config", "user.email", "test@example.com")
	runGit(t, repository, "config", "user.name", "Diff Cover Test")
	writeTestFile(t, repository, "covered.go", "package sample\n")
	runGit(t, repository, "add", "covered.go")
	runGit(t, repository, "commit", "-m", "base")

	writeTestFile(t, repository, "covered.go", "package sample\n\nfunc covered() int {\n\treturn 1\n}\n")
	writeTestFile(t, repository, "untracked.go", "package sample\n\nfunc untracked() int {\n\treturn 2\n}\n")
	profile := filepath.Join(repository, "coverage.out")
	writeTestFile(t, repository, "coverage.out", `mode: set
example/covered.go:3.1,5.2 2 1
example/untracked.go:3.1,5.2 2 1
`)

	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(repository); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(previous); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})

	var stdout, stderr bytes.Buffer
	err = run([]string{
		"--base", "master",
		"--profile", profile,
		"--threshold", "100",
		"--file-threshold", "covered.go=100",
		"--file-threshold", "untracked.go=100",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run diff coverage: %v\nstderr: %s", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "PASS") ||
		!strings.Contains(stdout.String(), "untracked.go") {
		t.Fatalf("unexpected output:\n%s", stdout.String())
	}
}

func TestAddUntrackedFilesErrors(t *testing.T) {
	if err := addUntrackedFiles(map[string]lineSet{}, "missing.go"); err == nil {
		t.Fatal("expected missing untracked file error")
	}
}

func runGit(t *testing.T, directory string, args ...string) {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = directory
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, output)
	}
}

func writeTestFile(t *testing.T, directory, name, contents string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, name), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}
