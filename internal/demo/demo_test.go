package demo

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/VardrSec/vardrgate/internal/model"
	"github.com/VardrSec/vardrgate/internal/policy"
)

// The demo policy is inlined so the binary is self-contained. This test is what
// keeps the copy honest: the README and the website both show the example file,
// and a reader who runs the demo must be watching that same policy execute.
// The comparison is on the parsed policy, so the example file stays free to
// carry explanatory comments the inlined copy does not need.
func TestPolicyMatchesExampleFile(t *testing.T) {
	onDisk, err := policy.Load("../../examples/profile_ownership.policy.yaml")
	if err != nil {
		t.Fatalf("load example policy: %v", err)
	}
	inlined, err := policy.Parse([]byte(Policy))
	if err != nil {
		t.Fatalf("parse inlined policy: %v", err)
	}
	if !reflect.DeepEqual(onDisk, inlined) {
		t.Errorf("demo.Policy has drifted from examples/profile_ownership.policy.yaml\nfile:    %+v\ninlined: %+v", onDisk, inlined)
	}
}

func TestRun_FindsTheVulnerabilitiesTheFixtureHas(t *testing.T) {
	res, err := Run(context.Background())
	if err != nil {
		t.Fatalf("demo run: %v", err)
	}

	if len(res.Executions) != 3 {
		t.Fatalf("expected 3 executions, got %d", len(res.Executions))
	}
	for _, ex := range res.Executions {
		if ex.Error != "" {
			t.Fatalf("identity %q failed to reach the fixture: %s", ex.IdentityID, ex.Error)
		}
	}

	got := map[model.FindingCategory]int{}
	for _, f := range res.Findings {
		got[f.Category]++
	}
	want := map[model.FindingCategory]int{
		model.CategoryMissingAuthentication: 1, // anonymous reached a protected object
		model.CategoryCrossTenantAccess:     1, // tenant-b caller received a tenant-a object
		model.CategorySensitiveDataExposure: 2, // other_user and anonymous both saw api_key
	}
	for category, count := range want {
		if got[category] != count {
			t.Errorf("category %q: got %d findings, want %d (all: %v)", category, got[category], count, got)
		}
	}
}

func TestRun_OwnerProducesNoFinding(t *testing.T) {
	res, err := Run(context.Background())
	if err != nil {
		t.Fatalf("demo run: %v", err)
	}
	for _, f := range res.Findings {
		if f.IdentityID == "owner" {
			t.Errorf("owner is allowed and must produce no finding, got %q: %s", f.Category, f.Message)
		}
	}
}

// The cross-tenant finding must come from the response body, not from a bound
// tenant: nothing in the demo bindings supplies one.
func TestRun_CrossTenantEvidenceComesFromTheResponseBody(t *testing.T) {
	res, err := Run(context.Background())
	if err != nil {
		t.Fatalf("demo run: %v", err)
	}
	for _, f := range res.Findings {
		if f.Category != model.CategoryCrossTenantAccess {
			continue
		}
		for _, ev := range f.Evidence {
			if strings.Contains(ev, "resource_tenant=tenant-a") {
				return
			}
		}
		t.Fatalf("cross_tenant_access finding lacks the tenant read from the body: %v", f.Evidence)
	}
	t.Fatal("no cross_tenant_access finding")
}

func TestStartFixture_ServesImmediately(t *testing.T) {
	base, stop, err := StartFixture()
	if err != nil {
		t.Fatalf("start fixture: %v", err)
	}
	defer stop()
	if !strings.HasPrefix(base, "http://127.0.0.1:") {
		t.Errorf("fixture must bind loopback only, got %q", base)
	}
}
