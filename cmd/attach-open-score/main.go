package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/attach-dev/attach-open-score/internal/fixtures"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("attach-open-score", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
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
		fmt.Printf("valid %s %s\n", path, report.Decision)
	}
	return nil
}
