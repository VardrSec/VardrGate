package suite

import "testing"

func TestStrictSuiteSettingsAndOverride(t *testing.T) {
	dir := writeTree(t, map[string]string{"p.yaml": adminPolicy, "identities.json": identities, "suite.yaml": "base: https://api.example.com\nidentities: identities.json\nrequire_identity_preflight: true\nfail_on_inconclusive: true\npolicies:\n  - policy: p.yaml\n"})
	s := load(t, dir)
	if !s.RequireIdentityPreflight || !s.FailOnInconclusive {
		t.Fatal("strict settings dropped")
	}
	cases, err := s.Compile(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !cases[0].TestCase.RequireIdentityPreflight {
		t.Fatal("strict setting not bound")
	}
	disabled := false
	cases, err = s.Compile(dir, Options{RequireIdentityPreflight: &disabled})
	if err != nil {
		t.Fatal(err)
	}
	if cases[0].TestCase.RequireIdentityPreflight {
		t.Fatal("explicit false did not override")
	}
}
