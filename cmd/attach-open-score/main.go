package main

import (
	"bytes"
	"encoding/json"
	"errors"
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
	if len(args) > 0 && args[0] == "score" {
		return runScore(args[1:], stdin, stdout, stderr)
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

	request, err := decodeScoreRequest(data)
	if err != nil {
		return err
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

func decodeScoreRequest(data []byte) (schema.Request, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	var request schema.Request
	if err := decoder.Decode(&request); err != nil {
		return schema.Request{}, fmt.Errorf("invalid JSON request: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return schema.Request{}, fmt.Errorf("invalid JSON request: trailing data after request object")
	}
	if err := validateRequiredJSONFields(data); err != nil {
		return schema.Request{}, err
	}
	if len(request.Evidence) == 0 {
		return schema.Request{}, fmt.Errorf("score request requires at least one evidence item")
	}
	for i, evidence := range request.Evidence {
		if strings.HasPrefix(evidence.Reason.Code, "X_") && evidence.Reason.DecisionEffect != schema.DecisionEffectNone {
			if len(evidence.Reason.SourceRefIDs) == 0 || (evidence.SourceRef == nil && len(evidence.SourceRefs) == 0) {
				return schema.Request{}, fmt.Errorf("score request evidence[%d] experimental reason %q with effect %s requires source_ref provenance", i, evidence.Reason.Code, evidence.Reason.DecisionEffect)
			}
		}
	}
	return request, nil
}

func validateRequiredJSONFields(data []byte) error {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return fmt.Errorf("invalid JSON request: %w", err)
	}
	if _, ok := top["mode"]; ok {
		return fmt.Errorf("score request field %q is not supported; use --policy-profile", "mode")
	}

	var pkg map[string]json.RawMessage
	if err := json.Unmarshal(top["package"], &pkg); err != nil {
		return fmt.Errorf("invalid JSON request package: %w", err)
	}
	if raw, ok := pkg["resolved"]; !ok {
		return fmt.Errorf("score request package.resolved is required")
	} else if err := requireJSONBool(raw, "package.resolved"); err != nil {
		return err
	}

	var evidenceItems []map[string]json.RawMessage
	if err := json.Unmarshal(top["evidence"], &evidenceItems); err != nil {
		return fmt.Errorf("invalid JSON request evidence: %w", err)
	}
	for i, evidence := range evidenceItems {
		if sourceRefRaw, ok := evidence["source_ref"]; ok {
			if err := validateSourceRefRequiredFields(sourceRefRaw, fmt.Sprintf("evidence[%d].source_ref", i)); err != nil {
				return err
			}
		}
		if sourceRefsRaw, ok := evidence["source_refs"]; ok {
			var sourceRefs []json.RawMessage
			if err := json.Unmarshal(sourceRefsRaw, &sourceRefs); err != nil {
				return fmt.Errorf("invalid JSON request evidence[%d].source_refs: %w", i, err)
			}
			for j, sourceRefRaw := range sourceRefs {
				if err := validateSourceRefRequiredFields(sourceRefRaw, fmt.Sprintf("evidence[%d].source_refs[%d]", i, j)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func validateSourceRefRequiredFields(sourceRefRaw json.RawMessage, path string) error {
	var sourceRef map[string]json.RawMessage
	if err := json.Unmarshal(sourceRefRaw, &sourceRef); err != nil {
		return fmt.Errorf("invalid JSON request %s: %w", path, err)
	}
	if raw, ok := sourceRef["ttl_seconds"]; !ok {
		return fmt.Errorf("score request %s.ttl_seconds is required", path)
	} else if err := requireJSONInt(raw, path+".ttl_seconds"); err != nil {
		return err
	}
	if raw, ok := sourceRef["attribution_required"]; !ok {
		return fmt.Errorf("score request %s.attribution_required is required", path)
	} else if err := requireJSONBool(raw, path+".attribution_required"); err != nil {
		return err
	}
	return nil
}

func requireJSONBool(raw json.RawMessage, path string) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return fmt.Errorf("score request %s must be a boolean", path)
	}
	var value bool
	if err := json.Unmarshal(raw, &value); err != nil {
		return fmt.Errorf("score request %s must be a boolean", path)
	}
	return nil
}

func requireJSONInt(raw json.RawMessage, path string) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return fmt.Errorf("score request %s must be an integer", path)
	}
	var value int
	if err := json.Unmarshal(raw, &value); err != nil {
		return fmt.Errorf("score request %s must be an integer", path)
	}
	return nil
}

func readScoreInput(path string, stdin io.Reader) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(stdin)
	}
	return os.ReadFile(path)
}
