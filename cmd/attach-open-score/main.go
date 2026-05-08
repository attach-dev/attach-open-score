package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/attach-dev/attach-open-score/internal/fixtures"
	"github.com/attach-dev/attach-open-score/pkg/schema"
	"github.com/attach-dev/attach-open-score/pkg/score"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if err := runE(args, stdin, stdout, stderr); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func runE(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if idx, subcommand := firstPositional(args); subcommand == "score" {
		return runScore(args[idx+1:], stdin, stdout, stderr)
	}
	return runFixtureValidation(args, stdout, stderr)
}

func runFixtureValidation(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("attach-open-score", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", ".", "repository root containing fixtures/v0")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() > 0 {
		return fmt.Errorf("unexpected arguments: %v", flags.Args())
	}

	reports, err := fixtures.ValidateRepository(*root)
	if err != nil {
		return err
	}
	for _, report := range reports {
		path, err := filepath.Rel(*root, report.Path)
		if err != nil {
			path = report.Path
		}
		fmt.Fprintf(stdout, "valid %s %s\n", path, report.Decision)
	}
	return nil
}

func runScore(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("attach-open-score score", flag.ContinueOnError)
	flags.SetOutput(stderr)
	input := flags.String("input", "", "JSON request path, or - for stdin")
	profile := flags.String("policy-profile", "default", "policy profile: default, local-dev-default, ci-strict, or audit-only")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() > 0 {
		return fmt.Errorf("score does not accept positional arguments: %v", flags.Args())
	}
	if *input == "" {
		return fmt.Errorf("score requires --input <path>, or --input - for stdin")
	}

	data, err := readScoreInput(*input, stdin)
	if err != nil {
		return err
	}

	var request schema.Request
	if err := json.Unmarshal(data, &request); err != nil {
		return fmt.Errorf("invalid JSON request: %w", err)
	}

	engineProfile := *profile
	if engineProfile == "default" {
		engineProfile = ""
	}
	engine, err := score.NewEngine(score.Options{PolicyProfile: engineProfile})
	if err != nil {
		return err
	}

	verdict, err := engine.Evaluate(request)
	if err != nil {
		return err
	}

	encoded, err := json.MarshalIndent(verdict, "", "  ")
	if err != nil {
		return err
	}
	if _, err := stdout.Write(encoded); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout)
	return err
}

func readScoreInput(path string, stdin io.Reader) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(stdin)
	}
	return os.ReadFile(path)
}

func firstPositional(args []string) (int, string) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			if i+1 < len(args) {
				return i + 1, args[i+1]
			}
			return -1, ""
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			if flagConsumesValue(arg) && !strings.Contains(arg, "=") && i+1 < len(args) {
				i++
			}
			continue
		}
		return i, arg
	}
	return -1, ""
}

func flagConsumesValue(arg string) bool {
	name := strings.TrimLeft(arg, "-")
	switch name {
	case "root", "input", "policy-profile":
		return true
	default:
		return false
	}
}
