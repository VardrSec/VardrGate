package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/VardrSec/vardrgate/internal/discover"
	"github.com/VardrSec/vardrgate/internal/openapi"
)

// runDiscover proposes draft policies from a spec so the authoring cost of
// covering an API does not start from a blank file.
//
// Every draft it writes is inert by construction: expectations are the TODO
// marker, which the policy parser rejects. Discovery proposes structure; a
// human supplies intent.
func runDiscover(args []string) error {
	fs := flag.NewFlagSet("discover", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: vardrgate discover --spec <file> [flags]

Proposes a draft policy for every operation that addresses an object, inferring
the object identifier, resource type, and — with --sample — the tenant field and
sensitive properties.

Expectations are left as TODO and the policy parser rejects TODO, so a draft
cannot run until you have said who should be allowed to call the endpoint.

Flags:
`)
		fs.PrintDefaults()
	}
	specPath := fs.String("spec", "", "path to an OpenAPI 3 JSON spec (required)")
	samplePath := fs.String("sample", "", "path to a captured JSON response body, used to find the tenant field and sensitive properties")
	outDir := fs.String("out", "", "directory to write draft policies into (default: print to stdout)")
	rolesFlag := fs.String("roles", strings.Join(discover.DefaultRoles, ","), "comma-separated logical roles to write into each expect map")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *specPath == "" {
		return errors.New("--spec is required")
	}

	specData, err := os.ReadFile(*specPath)
	if err != nil {
		return fmt.Errorf("read spec: %w", err)
	}
	spec, err := openapi.Parse(specData)
	if err != nil {
		return err
	}

	opts := discover.Options{Roles: splitRoles(*rolesFlag)}
	if *samplePath != "" {
		sample, err := os.ReadFile(*samplePath)
		if err != nil {
			return fmt.Errorf("read sample: %w", err)
		}
		opts.Sample = sample
	}

	drafts := discover.FromSpec(spec, opts)
	if len(drafts) == 0 {
		return errors.New("no operation in the spec takes a path parameter, so there is no object-level control to draft")
	}

	if *outDir == "" {
		for i, d := range drafts {
			if i > 0 {
				fmt.Println("---")
			}
			fmt.Printf("# %s\n%s", d.Filename, d.YAML)
		}
		printDiscoverSummary(drafts, "")
		return nil
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	for _, d := range drafts {
		path := filepath.Join(*outDir, d.Filename)
		if err := os.WriteFile(path, []byte(d.YAML), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
	}
	printDiscoverSummary(drafts, *outDir)
	return nil
}

// printDiscoverSummary explains what was inferred and why, to stderr so it
// never contaminates piped YAML. A reviewer should be able to check the
// reasoning rather than take it on trust.
func printDiscoverSummary(drafts []discover.Draft, outDir string) {
	w := os.Stderr
	fmt.Fprintf(w, "\n%s drafted", plural(len(drafts), "policy", "policies"))
	if outDir != "" {
		fmt.Fprintf(w, " into %s", outDir)
	}
	fmt.Fprintln(w, ":")
	for _, d := range drafts {
		fmt.Fprintf(w, "\n  %s  (%s)\n", d.Endpoint, d.Filename)
		for _, note := range d.Notes {
			fmt.Fprintf(w, "      - %s\n", note)
		}
	}
	fmt.Fprintf(w, "\nEvery expectation is TODO and will not parse until you replace it.\n")
	fmt.Fprintf(w, "Discovery inferred the shape of these controls; only you know their intent.\n")
}

func splitRoles(s string) []string {
	var out []string
	for _, r := range strings.Split(s, ",") {
		if r = strings.TrimSpace(r); r != "" {
			out = append(out, r)
		}
	}
	return out
}
