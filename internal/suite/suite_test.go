package suite

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const profilePolicy = `api:
  endpoint: GET /users/{user_id}/profile
  owner: identity:owner
  resource:
    type: user_profile
    id_param: user_id
expect:
  owner: allow
  other_user: deny
  anonymous: deny
`

// adminPolicy names a role the profile policy does not, so a shared identities
// file holds an identity one policy uses and the other must leave out.
const adminPolicy = `api:
  endpoint: GET /admin/users
expect:
  admin: allow
  owner: deny
`

const identities = `[
  {"id": "owner", "role": "owner", "tenant_id": "tenant-a", "credential": {"type": "bearer", "value": "owner-token"}},
  {"id": "other_user", "role": "other_user", "tenant_id": "tenant-b", "credential": {"type": "bearer", "value": "other-token"}},
  {"id": "anonymous", "role": "anonymous", "credential": {"type": "static_header"}},
  {"id": "admin", "role": "admin", "credential": {"type": "bearer", "value": "admin-token"}}
]`

// writeTree lays out files under a temp dir and returns the dir.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func load(t *testing.T, dir string) Suite {
	t.Helper()
	s, err := Load(filepath.Join(dir, "suite.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return s
}

func TestCompile_BindsEachPolicyToTheSharedIdentities(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"policies/profile.yaml": profilePolicy,
		"policies/admin.yaml":   adminPolicy,
		"identities.json":       identities,
		"suite.yaml": `base: https://api.example.com
identities: identities.json
policies:
  - policy: policies/profile.yaml
    params: {user_id: "42"}
  - policy: policies/admin.yaml
`,
	})
	cases, err := load(t, dir).Compile(dir, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(cases) != 2 {
		t.Fatalf("got %d cases, want 2", len(cases))
	}

	profile := cases[0].TestCase
	if got := profile.Request.URL; got != "https://api.example.com/users/42/profile" {
		t.Errorf("profile URL = %q", got)
	}
	if n := len(profile.Identities); n != 3 {
		t.Errorf("profile policy bound %d identities, want 3 (admin is not in its expect map)", n)
	}
	if n := len(cases[1].TestCase.Identities); n != 2 {
		t.Errorf("admin policy bound %d identities, want 2", n)
	}
	if want := filepath.Join(dir, "policies/profile.yaml"); cases[0].Source != want {
		t.Errorf("Source = %q, want %q", cases[0].Source, want)
	}
}

func TestCompileSharedDenialProfile(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"profile.yaml":    profilePolicy + "response:\n  denial_profiles: [hidden]\n",
		"identities.json": identities,
		"suite.yaml": `base: https://api.example.com
identities: identities.json
denial_profiles:
  hidden:
    confirmed: true
    endpoints: ["GET /users/{user_id}/profile"]
    rules:
      - status_codes: [404]
        json_pointer: /error
        equals: hidden
policies:
  - policy: profile.yaml
    params: {user_id: "42"}
`,
	})
	cases, err := load(t, dir).Compile(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, ea := range cases[0].TestCase.ExpectedAccess {
		if len(ea.ResponseAssertions) != 1 || ea.ResponseAssertions[0].StatusCodes[0] != 404 {
			t.Fatal("shared profile was dropped")
		}
	}
}

func TestCompile_BaseOverrideWins(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"p.yaml":          adminPolicy,
		"identities.json": identities,
		"suite.yaml":      "base: https://staging.example.com\nidentities: identities.json\npolicies:\n  - policy: p.yaml\n",
	})
	cases, err := load(t, dir).Compile(dir, Options{BaseOverride: "https://prod.example.com/"})
	if err != nil {
		t.Fatal(err)
	}
	if got := cases[0].TestCase.Request.URL; got != "https://prod.example.com/admin/users" {
		t.Errorf("URL = %q, want the --base override", got)
	}
}

func TestCompile_ExpandsEnvironmentReferences(t *testing.T) {
	t.Setenv("VG_TEST_BASE", "https://env.example.com")
	t.Setenv("VG_TEST_USER", "77")
	t.Setenv("VG_TEST_TENANT", "tenant-a")
	dir := writeTree(t, map[string]string{
		"p.yaml":          profilePolicy,
		"identities.json": identities,
		"suite.yaml": `base: ${VG_TEST_BASE}
identities: identities.json
policies:
  - policy: p.yaml
    params: {user_id: "${VG_TEST_USER}"}
    tenant: ${VG_TEST_TENANT}
`,
	})
	cases, err := load(t, dir).Compile(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	tc := cases[0].TestCase
	if tc.Request.URL != "https://env.example.com/users/77/profile" {
		t.Errorf("URL = %q", tc.Request.URL)
	}
	if tc.Resource == nil || tc.Resource.TenantID != "tenant-a" {
		t.Errorf("tenant not bound: %+v", tc.Resource)
	}
}

// An unset variable must fail rather than become an empty path segment, which
// would silently test a different endpoint.
func TestCompile_UnsetVariableIsAnError(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"p.yaml":          profilePolicy,
		"identities.json": identities,
		"suite.yaml":      "base: https://api.example.com\nidentities: identities.json\npolicies:\n  - policy: p.yaml\n    params: {user_id: \"${VG_TEST_DEFINITELY_UNSET}\"}\n",
	})
	_, err := load(t, dir).Compile(dir, Options{})
	if err == nil || !strings.Contains(err.Error(), "VG_TEST_DEFINITELY_UNSET") {
		t.Fatalf("err = %v, want it to name the unset variable", err)
	}
}

// The converse of leaving unused identities out: a role the policy expects but
// nobody holds would be a control that goes untested while the run looks clean.
func TestCompile_ExpectedRoleWithoutIdentityIsAnError(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"p.yaml":          profilePolicy,
		"identities.json": `[{"id": "owner", "role": "owner", "credential": {"type": "bearer", "value": "t"}}]`,
		"suite.yaml":      "base: https://api.example.com\nidentities: identities.json\npolicies:\n  - policy: p.yaml\n    params: {user_id: \"1\"}\n",
	})
	_, err := load(t, dir).Compile(dir, Options{})
	if err == nil {
		t.Fatal("expected an error for roles with no identity")
	}
	for _, role := range []string{`"anonymous"`, `"other_user"`} {
		if !strings.Contains(err.Error(), role) {
			t.Errorf("error %q does not name missing role %s", err, role)
		}
	}
}

func TestCompile_EntryIdentitiesOverrideTheSuiteDefault(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"p.yaml":          adminPolicy,
		"identities.json": `[{"id": "x", "role": "nobody", "credential": {"type": "static_header"}}]`,
		"admins.json":     identities,
		"suite.yaml":      "base: https://api.example.com\nidentities: identities.json\npolicies:\n  - policy: p.yaml\n    identities: admins.json\n",
	})
	if _, err := load(t, dir).Compile(dir, Options{}); err != nil {
		t.Fatalf("entry-level identities should satisfy the policy: %v", err)
	}
}

func TestCompile_DuplicateIDsAreRejected(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"p.yaml":          adminPolicy,
		"identities.json": identities,
		"suite.yaml":      "base: https://api.example.com\nidentities: identities.json\npolicies:\n  - policy: p.yaml\n  - policy: p.yaml\n",
	})
	_, err := load(t, dir).Compile(dir, Options{})
	if err == nil || !strings.Contains(err.Error(), "already used by policies[0]") {
		t.Fatalf("err = %v, want a duplicate id error", err)
	}
}

func TestCompile_DistinctIDsAllowTheSamePolicyTwice(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"p.yaml":          adminPolicy,
		"identities.json": identities,
		"suite.yaml":      "base: https://api.example.com\nidentities: identities.json\npolicies:\n  - policy: p.yaml\n    id: first\n  - policy: p.yaml\n    id: second\n",
	})
	cases, err := load(t, dir).Compile(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if cases[0].TestCase.ID != "first" || cases[1].TestCase.ID != "second" {
		t.Errorf("ids = %q, %q", cases[0].TestCase.ID, cases[1].TestCase.ID)
	}
}

func TestCompile_ReportsEveryProblemTogether(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"p.yaml":          profilePolicy,
		"identities.json": identities,
		"suite.yaml": `base: https://api.example.com
identities: identities.json
policies:
  - policy: missing.yaml
  - policy: p.yaml
  - {}
`,
	})
	_, err := load(t, dir).Compile(dir, Options{})
	if err == nil {
		t.Fatal("expected errors")
	}
	msg := err.Error()
	for _, want := range []string{"policies[0] (missing.yaml)", "policies[1] (p.yaml)", "policies[2]: policy is required"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error does not mention %q:\n%s", want, msg)
		}
	}
}

func TestCompile_MutatingPolicyNeedsConfirmation(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"p.yaml":          "api:\n  endpoint: DELETE /users/{user_id}\nexpect:\n  admin: allow\n  owner: deny\n",
		"identities.json": identities,
		"suite.yaml":      "base: https://api.example.com\nidentities: identities.json\npolicies:\n  - policy: p.yaml\n    params: {user_id: \"1\"}\n",
	})
	s := load(t, dir)
	cases, err := s.Compile(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if cases[0].TestCase.Mutating {
		t.Error("an unsafe method must not be marked mutating without confirmation")
	}
	cases, err = s.Compile(dir, Options{AllowMutating: true})
	if err != nil {
		t.Fatal(err)
	}
	if !cases[0].TestCase.Mutating {
		t.Error("--allow-mutating must reach every compiled case")
	}
}

func TestCompile_RequiresABase(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"p.yaml":          adminPolicy,
		"identities.json": identities,
		"suite.yaml":      "identities: identities.json\npolicies:\n  - policy: p.yaml\n",
	})
	if _, err := load(t, dir).Compile(dir, Options{}); err == nil || !strings.Contains(err.Error(), "--base") {
		t.Fatalf("err = %v, want a missing-base error that mentions --base", err)
	}
}

func TestLoad_RejectsUnknownFieldsAndEmptySuites(t *testing.T) {
	for name, content := range map[string]string{
		"unknown field": "base: x\npolices:\n  - policy: p.yaml\n",
		"no policies":   "base: x\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeTree(t, map[string]string{"suite.yaml": content})
			if _, err := Load(filepath.Join(dir, "suite.yaml")); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

// The shipped example must keep compiling, or the README's first suite command
// breaks without any test noticing.
func TestExampleSuiteCompiles(t *testing.T) {
	t.Setenv("VARDRGATE_BASE_URL", "https://api.example.com")
	t.Setenv("VARDRGATE_OWNER_USER_ID", "42")
	t.Setenv("VARDRGATE_OWNER_TOKEN", "owner")
	t.Setenv("VARDRGATE_OTHER_USER_TOKEN", "other")
	path := filepath.Join("..", "..", "examples", "suite.yaml")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	cases, err := s.Compile(filepath.Dir(path), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 2 {
		t.Fatalf("got %d cases, want 2", len(cases))
	}
}
