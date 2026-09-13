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
	normalizeProfilePaths(blocks, "github.com/derailed/k9s")
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
	if err := thresholds.Set("file.go=NaN"); err == nil {
		t.Fatal("expected non-finite percentage error")
	}
	if thresholds.String() != "internal/netpol/policy.go=80.0" {
		t.Fatalf("unexpected threshold string: %s", thresholds.String())
	}
}

func TestCoverageHelpers(t *testing.T) {
	if got := (coverageResult{}).percent(); got != 100 {
		t.Fatalf("empty coverage should be 100%%, got %.1f", got)
	}
	if profilePathMatches(
		"github.com/derailed/k9s/internal/netpol/policy.go",
		"internal/netpol/policy.go",
	) {
		t.Fatal("profile paths must be normalized before matching")
	}
	if !profilePathMatches("internal/netpol/policy.go", "internal/netpol/policy.go") {
		t.Fatal("normalized profile path should match repository path")
	}
	if profilePathMatches("internal/netpol/policy.go", "policy.go") {
		t.Fatal("a basename suffix must not match a different source file")
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
	writeTestFile(t, repository, "go.mod", "module example\n")
	writeTestFile(t, repository, "covered.go", "package sample\n")
	runGit(t, repository, "add", "covered.go", "go.mod")
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

func TestRunRejectsMissingProfileFiles(t *testing.T) {
	for _, tracked := range []bool{false, true} {
		t.Run(map[bool]string{false: "untracked", true: "tracked"}[tracked], func(t *testing.T) {
			repository := t.TempDir()
			runGit(t, repository, "init", "-b", "master")
			runGit(t, repository, "config", "user.email", "test@example.com")
			runGit(t, repository, "config", "user.name", "Diff Cover Test")
			writeTestFile(t, repository, "go.mod", "module example\n")
			writeTestFile(t, repository, "covered.go", "package sample\n")
			if tracked {
				writeTestFile(t, repository, "omitted.go", "package sample\n")
			}
			runGit(t, repository, "add", ".")
			runGit(t, repository, "commit", "-m", "base")
			writeTestFile(t, repository, "covered.go", "package sample\n\nfunc covered() int {\n\treturn 1\n}\n")
			writeTestFile(t, repository, "omitted.go", "package sample\n\nfunc omitted() int {\n\treturn 2\n}\n")
			writeTestFile(t, repository, "coverage.out", "mode: set\nexample/covered.go:3.20,5.2 1 1\n")

			t.Chdir(repository)
			var stdout, stderr bytes.Buffer
			err := run([]string{"--base", "master", "--profile", "coverage.out"}, &stdout, &stderr)
			if err == nil || !strings.Contains(err.Error(), "omitted.go") {
				t.Fatalf("missing executable source must fail coverage, got %v\n%s", err, stdout.String())
			}
		})
	}
}

func TestAddUntrackedFilesErrors(t *testing.T) {
	if err := addUntrackedFiles(map[string]lineSet{}, "missing.go"); err == nil {
		t.Fatal("expected missing untracked file error")
	}
}

func TestValidateChangedFunctions(t *testing.T) {
	for _, test := range []struct {
		name    string
		source  string
		lines   lineSet
		blocks  []coverBlock
		wantErr bool
	}{
		{
			name: "covered", source: "package p\nfunc one() int {\n return 1\n}\n",
			lines:  lineSet{3: {}},
			blocks: []coverBlock{{path: "source.go", startLine: 2, endLine: 4, statements: 1}},
		},
		{
			name: "missing-other-function", source: "package p\nfunc one() int { return 1 }\nfunc two() int { return 2 }\n",
			lines:   lineSet{3: {}},
			blocks:  []coverBlock{{path: "source.go", startLine: 2, endLine: 2, statements: 1}},
			wantErr: true,
		},
		{
			name: "missing-closure", source: "package p\nvar closure = func() int { return 1 }\n",
			lines: lineSet{2: {}}, wantErr: true,
		},
		{
			name: "declarations-only", source: "package p\ntype A struct{ Value int }\nfunc assembly()\nfunc empty() {}\n",
			lines: lineSet{2: {}, 3: {}, 4: {}},
		},
		{
			name: "outside-function", source: "package p\nfunc one() int { return 1 }\n",
			lines: lineSet{1: {}},
		},
		{
			name: "invalid-source", source: "package p\nfunc (\n",
			lines: lineSet{2: {}}, wantErr: true,
		},
		{
			name: "suffix-is-not-source", source: "package p\nfunc one() int { return 1 }\n",
			lines:   lineSet{2: {}},
			blocks:  []coverBlock{{path: "nested/source.go", startLine: 2, endLine: 2, statements: 1}},
			wantErr: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			writeTestFile(t, directory, "source.go", test.source)
			t.Chdir(directory)
			err := validateChangedFunctions(map[string]lineSet{"source.go": test.lines}, test.blocks)
			if (err != nil) != test.wantErr {
				t.Fatalf("validateChangedFunctions returned %v, want error %v", err, test.wantErr)
			}
		})
	}
}

func TestModuleAndUntrackedPaths(t *testing.T) {
	directory := t.TempDir()
	t.Chdir(directory)
	if _, err := readModulePath("missing.mod"); err == nil {
		t.Fatal("expected unreadable module error")
	}
	writeTestFile(t, directory, "go.mod", "go 1.25.8\n")
	if _, err := readModulePath("go.mod"); err == nil {
		t.Fatal("expected missing module directive error")
	}
	writeTestFile(t, directory, "go.mod", "// comment\nmodule \"example.org/project\"\n")
	module, err := readModulePath("go.mod")
	if err != nil || module != "example.org/project" {
		t.Fatalf("module path: %q, %v", module, err)
	}
	blocks := []coverBlock{{path: "example.org/project/main.go"}, {path: "other.org/main.go"}}
	normalizeProfilePaths(blocks, module)
	if blocks[0].path != "main.go" || blocks[1].path != "other.org/main.go" {
		t.Fatalf("incorrect profile normalization: %#v", blocks)
	}
	writeTestFile(t, directory, "file with spaces.go", "package p\n")
	changed := map[string]lineSet{}
	if err := addUntrackedFiles(changed, "file with spaces.go\x00"); err != nil {
		t.Fatal(err)
	}
	if len(changed["file with spaces.go"]) != 1 {
		t.Fatalf("untracked filename was not preserved: %#v", changed)
	}
}

func TestRunRejectsInvalidThresholds(t *testing.T) {
	for _, value := range []string{"NaN", "-1", "101"} {
		var stdout, stderr bytes.Buffer
		err := run([]string{"--profile", "unused", "--threshold", value}, &stdout, &stderr)
		if err == nil || !strings.Contains(err.Error(), "between 0 and 100") {
			t.Fatalf("invalid threshold %s was not rejected: %v", value, err)
		}
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
