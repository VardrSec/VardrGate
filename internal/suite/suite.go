// Package suite binds many declarative policies to one environment and compiles
// them into test cases that run, and gate, as a single invocation.
//
// One policy describes one endpoint. Testing an API's authorization on every
// commit means many endpoints, each with its own path parameters, and before
// this package that meant a shell loop around `vardrgate policy run` with no
// combined exit code. A suite file lists the policies once; the identities are
// shared, so credentials are declared in one place. See ADR 0013.
package suite

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/VardrSec/vardrgate/internal/model"
	"github.com/VardrSec/vardrgate/internal/policy"
	"github.com/VardrSec/vardrgate/internal/secretref"
	"gopkg.in/yaml.v3"
)

// Suite is the on-disk representation of a set of policies bound to one
// environment.
type Suite struct {
	DenialProfiles           map[string]policy.DenialProfile `yaml:"denial_profiles"`
	RequireIdentityPreflight bool                            `yaml:"require_identity_preflight"`
	FailOnInconclusive       bool                            `yaml:"fail_on_inconclusive"`
	// Base is the environment's base URL. A --base flag overrides it, so the
	// same suite runs against staging and production without editing.
	Base string `yaml:"base"`
	// Identities is the default identities file for every entry.
	Identities string  `yaml:"identities"`
	Policies   []Entry `yaml:"policies"`
}

// Entry binds one policy file. Paths are relative to the suite file.
type Entry struct {
	Policy string            `yaml:"policy"`
	Params map[string]string `yaml:"params"`
	Tenant string            `yaml:"tenant"`
	ID     string            `yaml:"id"`
	// Identities overrides the suite's identities file for this entry.
	Identities string `yaml:"identities"`
}

// Case is a compiled entry, ready to run.
type Case struct {
	// Source is the policy file path as the suite named it, joined to the
	// suite's directory. Reports use it to locate a finding.
	Source   string
	TestCase model.AuthorizationTestCase
}

// Options are the run-time values that are not part of the suite file.
type Options struct {
	DenialProfiles           map[string]policy.DenialProfile
	RequireIdentityPreflight *bool
	// BaseOverride replaces the suite's base URL when set.
	BaseOverride  string
	AllowMutating bool
}

// Load reads and parses a suite file. Unknown fields are rejected, matching the
// policy parser: a misspelled key must not silently drop a binding.
func Load(path string) (Suite, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Suite{}, fmt.Errorf("read suite: %w", err)
	}
	var s Suite
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&s); err != nil {
		return Suite{}, fmt.Errorf("parse suite: %w", err)
	}
	if len(s.Policies) == 0 {
		return Suite{}, errors.New("suite: policies must list at least one entry")
	}
	return s, nil
}

// Compile resolves every entry against the suite's directory and compiles it.
//
// Every entry is checked before any is returned and all problems are reported
// together, for the same reason `run --cases` validates the whole suite first:
// discovering authoring errors one partial run at a time is the wrong way to
// find out.
func (s Suite) Compile(dir string, opts Options) ([]Case, error) {
	opts.DenialProfiles = s.DenialProfiles
	if opts.RequireIdentityPreflight == nil {
		opts.RequireIdentityPreflight = &s.RequireIdentityPreflight
	}
	base := s.Base
	if opts.BaseOverride != "" {
		base = opts.BaseOverride
	}
	base, err := secretref.Expand(base)
	if err != nil {
		return nil, fmt.Errorf("suite: base: %w", err)
	}
	if strings.TrimSpace(base) == "" {
		return nil, errors.New("suite: no base URL; set base in the suite file or pass --base")
	}

	identityFiles := map[string][]model.Identity{}
	loadIdentities := func(rel string) ([]model.Identity, error) {
		if rel == "" {
			return nil, errors.New("no identities file; set identities in the suite or on the entry")
		}
		path := filepath.Join(dir, rel)
		if ids, ok := identityFiles[path]; ok {
			return ids, nil
		}
		ids, err := policy.LoadIdentities(path)
		if err != nil {
			return nil, err
		}
		identityFiles[path] = ids
		return ids, nil
	}

	var (
		cases    []Case
		problems []string
		seen     = map[string]int{}
	)
	for i, e := range s.Policies {
		label := fmt.Sprintf("policies[%d]", i)
		if e.Policy != "" {
			label += " (" + e.Policy + ")"
		}
		c, err := e.compile(dir, base, s.Identities, opts, loadIdentities)
		if err != nil {
			problems = append(problems, fmt.Sprintf("  %s: %s", label, err))
			continue
		}
		// Two entries with the same id would make the unreached list and SARIF
		// fingerprints ambiguous, so the collision is an authoring error.
		if prev, dup := seen[c.TestCase.ID]; dup {
			problems = append(problems, fmt.Sprintf("  %s: test case id %q is already used by policies[%d]; set a distinct id", label, c.TestCase.ID, prev))
			continue
		}
		seen[c.TestCase.ID] = i
		cases = append(cases, c)
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("suite could not be compiled:\n%s", strings.Join(problems, "\n"))
	}
	return cases, nil
}

func (e Entry) compile(dir, base, defaultIdentities string, opts Options, loadIdentities func(string) ([]model.Identity, error)) (Case, error) {
	if e.Policy == "" {
		return Case{}, errors.New("policy is required")
	}
	source := filepath.Join(dir, e.Policy)
	p, err := policy.Load(source)
	if err != nil {
		return Case{}, err
	}

	params := make(map[string]string, len(e.Params))
	for name, val := range e.Params {
		expanded, err := secretref.Expand(val)
		if err != nil {
			return Case{}, fmt.Errorf("params.%s: %w", name, err)
		}
		params[name] = expanded
	}
	tenant, err := secretref.Expand(e.Tenant)
	if err != nil {
		return Case{}, fmt.Errorf("tenant: %w", err)
	}

	all, err := loadIdentities(firstNonEmpty(e.Identities, defaultIdentities))
	if err != nil {
		return Case{}, err
	}
	ids, err := bindRoles(p, all)
	if err != nil {
		return Case{}, err
	}

	tc, err := p.Compile(policy.Bindings{
		DenialProfiles:           opts.DenialProfiles,
		RequireIdentityPreflight: opts.RequireIdentityPreflight != nil && *opts.RequireIdentityPreflight,
		TestCaseID:               e.ID,
		BaseURL:                  base,
		PathParams:               params,
		Identities:               ids,
		ResourceTenantID:         tenant,
		AllowMutating:            opts.AllowMutating,
	})
	if err != nil {
		return Case{}, err
	}
	return Case{Source: source, TestCase: tc}, nil
}

// bindRoles selects the identities a policy names and requires that every role
// it names has one.
//
// A shared identities file is the point of a suite, so an identity whose role a
// policy does not mention is left out rather than rejected. The converse is an
// error: a role in expect with no identity is a control that silently goes
// untested while the run reports clean.
func bindRoles(p policy.Policy, all []model.Identity) ([]model.Identity, error) {
	have := map[string]bool{}
	var ids []model.Identity
	verifier := p.VerifierRole()
	for _, id := range all {
		if _, ok := p.Expect[id.Role]; ok || (verifier != "" && id.Role == verifier) {
			ids = append(ids, id)
			have[id.Role] = true
		}
	}
	if verifier != "" && !have[verifier] {
		return nil, fmt.Errorf("no identity has role %q, which the policy's verify.as requires", verifier)
	}
	var missing []string
	for role := range p.Expect {
		if !have[role] {
			missing = append(missing, role)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("no identity has role %s, which the policy's expect map requires", strings.Join(quote(missing), ", "))
	}
	return ids, nil
}

func quote(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = fmt.Sprintf("%q", s)
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
