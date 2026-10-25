package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/VardrSec/vardrgate/internal/coverage"
	"github.com/VardrSec/vardrgate/internal/discover"
	"github.com/VardrSec/vardrgate/internal/model"
	"github.com/VardrSec/vardrgate/internal/openapi"
	"github.com/VardrSec/vardrgate/internal/postman"
	"github.com/VardrSec/vardrgate/internal/scaffold"
)

// genTestCases reads an OpenAPI spec or Postman collection and writes starter
// authorization test cases as a JSON array (to --out or stdout). The output is
// a scaffold: fill in credential values before running it with `vardrgate run
// --cases`.
func genTestCases(args []string) error {
	fs := flag.NewFlagSet("gen", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: vardrgate gen (--spec <file> | --postman <file>) [flags]

Generates review-only authorization cases, one per operation. Confirm each TODO
permission and bind identities/resources before running "vardrgate run --cases".

Flags:
`)
		fs.PrintDefaults()
	}
	specPath := fs.String("spec", "", "path to an OpenAPI 3 JSON spec")
	postmanPath := fs.String("postman", "", "path to a Postman v2.1 collection JSON")
	baseURL := fs.String("base", "", "base URL to target instead of the spec/collection's own")
	outPath := fs.String("out", "", "path to write the generated cases (default: stdout)")
	harPath := fs.String("har", "", "optional HAR captured traffic to correlate with --spec, offline")
	hypothesesPath := fs.String("hypotheses", "", "write unconfirmed discovery hypotheses as JSON (requires --spec)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if (*specPath == "") == (*postmanPath == "") {
		return errors.New("exactly one of --spec or --postman is required")
	}
	if (*harPath != "" || *hypothesesPath != "") && *specPath == "" {
		return errors.New("--har and --hypotheses require --spec")
	}
	if *harPath != "" && *hypothesesPath == "" {
		return errors.New("--har requires --hypotheses to retain reviewable guidance")
	}
	if *outPath != "" && *hypothesesPath != "" {
		a, _ := filepath.Abs(*outPath)
		b, _ := filepath.Abs(*hypothesesPath)
		if a == b {
			return errors.New("--out and --hypotheses must be different files")
		}
	}

	var cases []model.AuthorizationTestCase
	var hypotheses []discover.Candidate
	if *specPath != "" {
		data, err := os.ReadFile(*specPath)
		if err != nil {
			return fmt.Errorf("read spec: %w", err)
		}
		spec, err := openapi.Parse(data)
		if err != nil {
			return err
		}
		cases = spec.GenerateTestCases(*baseURL)
		var har []byte
		if *harPath != "" {
			har, err = os.ReadFile(*harPath)
			if err != nil {
				return fmt.Errorf("read HAR: %w", err)
			}
		}
		hypotheses, err = discover.Candidates(spec, *baseURL, har)
		if err != nil {
			return err
		}
	} else {
		data, err := os.ReadFile(*postmanPath)
		if err != nil {
			return fmt.Errorf("read collection: %w", err)
		}
		coll, err := postman.Parse(data)
		if err != nil {
			return err
		}
		cases = coll.GenerateTestCases(*baseURL)
	}
	discover.ReviewCases(cases)

	out, err := scaffold.MarshalCases(cases)
	if err != nil {
		return err
	}
	if *hypothesesPath != "" {
		if err := writeJSON(*hypothesesPath, hypotheses); err != nil {
			return err
		}
	}
	if *outPath == "" {
		_, err = os.Stdout.Write(out)
		return err
	}
	if err := os.WriteFile(*outPath, out, 0o644); err != nil {
		return fmt.Errorf("write cases: %w", err)
	}
	return nil
}

// reportCoverage matches a set of test cases against an OpenAPI spec and writes
// a tested/untested coverage report as JSON (to --out or stdout).
func reportCoverage(args []string) error {
	fs := flag.NewFlagSet("coverage", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: vardrgate coverage --spec <file> --cases <file> [flags]

Reports which operations in a spec have an authorization test and which do not.

Flags:
`)
		fs.PrintDefaults()
	}
	specPath := fs.String("spec", "", "path to an OpenAPI 3 JSON spec (required)")
	casesPath := fs.String("cases", "", "path to a JSON array of test cases (required)")
	outPath := fs.String("out", "", "path to write the report (default: stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *specPath == "" || *casesPath == "" {
		return errors.New("--spec and --cases are required")
	}

	specData, err := os.ReadFile(*specPath)
	if err != nil {
		return fmt.Errorf("read spec: %w", err)
	}
	spec, err := openapi.Parse(specData)
	if err != nil {
		return err
	}

	casesData, err := os.ReadFile(*casesPath)
	if err != nil {
		return fmt.Errorf("read cases: %w", err)
	}
	var cases []model.AuthorizationTestCase
	if err := json.Unmarshal(casesData, &cases); err != nil {
		return fmt.Errorf("parse cases: %w", err)
	}

	return writeJSON(*outPath, coverage.Analyze(spec, cases))
}
