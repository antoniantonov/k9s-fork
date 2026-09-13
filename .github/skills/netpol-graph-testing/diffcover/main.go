// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

type lineSet map[int]struct{}

type coverBlock struct {
	path       string
	startLine  int
	startCol   int
	endLine    int
	endCol     int
	statements int
	count      int
}

type coverageResult struct {
	path       string
	covered    int
	statements int
}

func (r coverageResult) percent() float64 {
	if r.statements == 0 {
		return 100
	}
	return float64(r.covered) * 100 / float64(r.statements)
}

type fileThresholds map[string]float64

func (t fileThresholds) String() string {
	var values []string
	for path, threshold := range t {
		values = append(values, fmt.Sprintf("%s=%.1f", path, threshold))
	}
	slices.Sort(values)
	return strings.Join(values, ",")
}

func (t fileThresholds) Set(value string) error {
	index := strings.LastIndex(value, "=")
	if index <= 0 || index == len(value)-1 {
		return fmt.Errorf("file threshold must be PATH=PERCENT: %q", value)
	}
	threshold, err := strconv.ParseFloat(value[index+1:], 64)
	if err != nil {
		return fmt.Errorf("parse file threshold %q: %w", value, err)
	}
	if math.IsNaN(threshold) || threshold < 0 || threshold > 100 {
		return fmt.Errorf("file threshold must be between 0 and 100: %.1f", threshold)
	}
	t[filepath.ToSlash(value[:index])] = threshold
	return nil
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "diff coverage failed:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("diffcover", flag.ContinueOnError)
	flags.SetOutput(stderr)
	base := flags.String("base", envOrDefault("DIFF_COVER_BASE", "master"), "base ref used to find the merge base")
	profile := flags.String("profile", "", "Go cover profile to evaluate")
	threshold := flags.Float64("threshold", 80, "minimum aggregate changed-statement coverage")
	required := fileThresholds{}
	flags.Var(required, "file-threshold", "required changed-statement coverage for PATH=PERCENT; repeatable")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *profile == "" {
		return errors.New("--profile is required")
	}
	if math.IsNaN(*threshold) || *threshold < 0 || *threshold > 100 {
		return fmt.Errorf("--threshold must be between 0 and 100: %.1f", *threshold)
	}

	mergeBase, err := gitOutput("merge-base", *base, "HEAD")
	if err != nil {
		return fmt.Errorf("resolve merge base for %s: %w", *base, err)
	}
	diff, err := gitOutput(
		"-c", "core.quotePath=false", "diff", "--unified=0", "--no-ext-diff", "--no-renames", mergeBase, "--",
		":(glob)**/*.go", ":(exclude,glob)**/*_test.go",
	)
	if err != nil {
		return fmt.Errorf("read changed Go lines: %w", err)
	}
	changed, err := parseChangedLines(strings.NewReader(diff))
	if err != nil {
		return err
	}
	untracked, err := gitOutput(
		"ls-files", "--others", "--exclude-standard", "-z", "--",
		":(glob)**/*.go", ":(exclude,glob)**/*_test.go",
	)
	if err != nil {
		return fmt.Errorf("list untracked Go files: %w", err)
	}
	if err := addUntrackedFiles(changed, untracked); err != nil {
		return err
	}
	if len(changed) == 0 {
		fmt.Fprintf(stdout, "Diff coverage base: %s (%s)\nNo changed production Go lines.\n", *base, mergeBase)
		return nil
	}

	file, err := os.Open(*profile)
	if err != nil {
		return fmt.Errorf("open cover profile: %w", err)
	}
	defer file.Close()
	blocks, err := parseCoverProfile(file)
	if err != nil {
		return err
	}
	modulePath, err := readModulePath("go.mod")
	if err != nil {
		return err
	}
	normalizeProfilePaths(blocks, modulePath)
	if err := validateChangedFunctions(changed, blocks); err != nil {
		return err
	}
	results := calculateCoverage(changed, blocks)
	if len(results) == 0 {
		return errors.New("cover profile contains no executable statements overlapping changed production Go lines")
	}

	fmt.Fprintf(stdout, "Diff coverage base: %s (%s)\n", *base, mergeBase)
	fmt.Fprintln(stdout, "Coverage includes committed branch changes and local working-tree changes.")
	fmt.Fprintf(stdout, "%-72s %9s %11s %9s\n", "File", "Covered", "Statements", "Coverage")
	fmt.Fprintf(stdout, "%-72s %9s %11s %9s\n", strings.Repeat("-", 72), "-------", "----------", "--------")
	total := coverageResult{path: "TOTAL"}
	byPath := make(map[string]coverageResult, len(results))
	for _, result := range results {
		byPath[result.path] = result
		total.covered += result.covered
		total.statements += result.statements
		fmt.Fprintf(stdout, "%-72s %9d %11d %8.1f%%\n",
			result.path, result.covered, result.statements, result.percent())
	}
	fmt.Fprintf(stdout, "%-72s %9d %11d %8.1f%%\n",
		total.path, total.covered, total.statements, total.percent())

	var failures []string
	if total.percent()+0.000_001 < *threshold {
		failures = append(failures, fmt.Sprintf(
			"aggregate changed-statement coverage %.1f%% is below %.1f%%",
			total.percent(), *threshold,
		))
	}
	for path, minimum := range required {
		result, ok := byPath[path]
		if !ok {
			failures = append(failures, fmt.Sprintf("%s has no changed executable statements in the profile", path))
			continue
		}
		if result.percent()+0.000_001 < minimum {
			failures = append(failures, fmt.Sprintf(
				"%s changed-statement coverage %.1f%% is below %.1f%%",
				path, result.percent(), minimum,
			))
		}
	}
	if len(failures) > 0 {
		slices.Sort(failures)
		return errors.New(strings.Join(failures, "; "))
	}
	fmt.Fprintf(stdout, "PASS: aggregate coverage is at least %.1f%%", *threshold)
	if len(required) > 0 {
		fmt.Fprint(stdout, " and all file thresholds passed")
	}
	fmt.Fprintln(stdout, ".")
	return nil
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func gitOutput(args ...string) (string, error) {
	command := exec.Command("git", args...)
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output)), nil
}

func addUntrackedFiles(changed map[string]lineSet, output string) error {
	for _, value := range strings.Split(output, "\x00") {
		path := filepath.ToSlash(value)
		if path == "" {
			continue
		}
		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open untracked Go file %s: %w", path, err)
		}
		lines := lineSet{}
		scanner := bufio.NewScanner(file)
		line := 0
		for scanner.Scan() {
			line++
			lines[line] = struct{}{}
		}
		closeErr := file.Close()
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("read untracked Go file %s: %w", path, err)
		}
		if closeErr != nil {
			return fmt.Errorf("close untracked Go file %s: %w", path, closeErr)
		}
		if len(lines) > 0 {
			changed[path] = lines
		}
	}
	return nil
}

func readModulePath(path string) (string, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read module path: %w", err)
	}
	for _, line := range strings.Split(string(contents), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "module" {
			continue
		}
		return strings.Trim(fields[1], `"`), nil
	}
	return "", fmt.Errorf("%s has no module directive", path)
}

func normalizeProfilePaths(blocks []coverBlock, modulePath string) {
	for index := range blocks {
		blocks[index].path = strings.TrimPrefix(blocks[index].path, modulePath+"/")
	}
}

// A profile is not evidence for a changed function that was never instrumented.
// Reject missing functions instead of silently dropping their statements from
// the denominator. Declaration-only files need no executable cover blocks.
func validateChangedFunctions(changed map[string]lineSet, blocks []coverBlock) error {
	var missing []string
	for path, lines := range changed {
		positions := token.NewFileSet()
		file, err := parser.ParseFile(positions, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return fmt.Errorf("inspect changed Go source %s: %w", path, err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			var body *ast.BlockStmt
			switch value := node.(type) {
			case *ast.FuncDecl:
				body = value.Body
			case *ast.FuncLit:
				body = value.Body
			}
			if body == nil || len(body.List) == 0 {
				return true
			}
			start, end := positions.Position(body.Lbrace).Line, positions.Position(body.Rbrace).Line
			if !blockOverlapsLines(coverBlock{startLine: start, endLine: end}, lines) {
				return true
			}
			for _, block := range blocks {
				if block.path == path && block.statements > 0 && block.startLine >= start && block.endLine <= end {
					return true
				}
			}
			missing = append(missing, fmt.Sprintf("%s:%d", path, start))
			return true
		})
	}
	if len(missing) == 0 {
		return nil
	}
	slices.Sort(missing)
	return fmt.Errorf("changed executable functions missing from cover profile: %s; include their packages/build constraints in coverage", strings.Join(missing, ", "))
}

var hunkPattern = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@`)

func parseChangedLines(reader io.Reader) (map[string]lineSet, error) {
	changed := map[string]lineSet{}
	var current string
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "+++ b/"):
			current = filepath.ToSlash(strings.TrimPrefix(line, "+++ b/"))
		case strings.HasPrefix(line, "@@ "):
			if current == "" {
				return nil, fmt.Errorf("diff hunk has no file: %q", line)
			}
			match := hunkPattern.FindStringSubmatch(line)
			if match == nil {
				return nil, fmt.Errorf("parse diff hunk: %q", line)
			}
			start, _ := strconv.Atoi(match[1])
			count := 1
			if match[2] != "" {
				count, _ = strconv.Atoi(match[2])
			}
			if count == 0 {
				continue
			}
			if changed[current] == nil {
				changed[current] = lineSet{}
			}
			for number := start; number < start+count; number++ {
				changed[current][number] = struct{}{}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read git diff: %w", err)
	}
	return changed, nil
}

var profilePattern = regexp.MustCompile(`^(.+):(\d+)\.(\d+),(\d+)\.(\d+)\s+(\d+)\s+(\d+)$`)

func parseCoverProfile(reader io.Reader) ([]coverBlock, error) {
	unique := map[string]coverBlock{}
	scanner := bufio.NewScanner(reader)
	first := true
	for scanner.Scan() {
		line := scanner.Text()
		if first {
			first = false
			if !strings.HasPrefix(line, "mode: ") {
				return nil, fmt.Errorf("cover profile is missing a mode header: %q", line)
			}
			continue
		}
		match := profilePattern.FindStringSubmatch(line)
		if match == nil {
			return nil, fmt.Errorf("parse cover profile line: %q", line)
		}
		values := make([]int, 6)
		for index := range values {
			values[index], _ = strconv.Atoi(match[index+2])
		}
		block := coverBlock{
			path:       filepath.ToSlash(match[1]),
			startLine:  values[0],
			startCol:   values[1],
			endLine:    values[2],
			endCol:     values[3],
			statements: values[4],
			count:      values[5],
		}
		key := fmt.Sprintf("%s:%d.%d,%d.%d:%d",
			block.path, block.startLine, block.startCol, block.endLine, block.endCol, block.statements)
		if existing, ok := unique[key]; !ok || block.count > existing.count {
			unique[key] = block
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read cover profile: %w", err)
	}
	if first {
		return nil, errors.New("cover profile is empty")
	}
	blocks := make([]coverBlock, 0, len(unique))
	for _, block := range unique {
		blocks = append(blocks, block)
	}
	return blocks, nil
}

func calculateCoverage(changed map[string]lineSet, blocks []coverBlock) []coverageResult {
	var results []coverageResult
	for path, lines := range changed {
		result := coverageResult{path: path}
		for _, block := range blocks {
			if !profilePathMatches(block.path, path) || !blockOverlapsLines(block, lines) {
				continue
			}
			result.statements += block.statements
			if block.count > 0 {
				result.covered += block.statements
			}
		}
		if result.statements > 0 {
			results = append(results, result)
		}
	}
	slices.SortFunc(results, func(left, right coverageResult) int {
		return strings.Compare(left.path, right.path)
	})
	return results
}

func profilePathMatches(profilePath, changedPath string) bool {
	return profilePath == changedPath
}

func blockOverlapsLines(block coverBlock, lines lineSet) bool {
	for line := block.startLine; line <= block.endLine; line++ {
		if _, ok := lines[line]; ok {
			return true
		}
	}
	return false
}
