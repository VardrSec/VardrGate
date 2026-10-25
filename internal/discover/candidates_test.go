package discover

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/VardrSec/vardrgate/internal/openapi"
)

func TestCandidatesCorrelateWithoutRetainingCapturedValues(t *testing.T) {
	spec, err := openapi.Parse([]byte(`{"servers":[{"url":"https://api.example/v1"}],"paths":{"/books/{book_id}":{"get":{}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	entry := func(host, token, tenant string) map[string]any {
		return map[string]any{"request": map[string]any{"method": "GET", "url": host + "/v1/books/private-object?secret=query-secret", "headers": []any{map[string]any{"name": "Authorization", "value": token}}}, "response": map[string]any{"status": 200, "content": map[string]any{"text": `{"owner_id":"private-owner","tenant_id":"` + tenant + `"}`}}}
	}
	har, _ := json.Marshal(map[string]any{"log": map[string]any{"entries": []any{entry("https://api.example", "token-one", "tenant-one"), entry("https://api.example", "token-two", "tenant-two"), entry("https://other.example", "token-three", "tenant-three")}}})
	candidates, err := Candidates(spec, "", har)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(candidates)
	for _, secret := range []string{"private-object", "private-owner", "token-one", "token-two", "tenant-one", "tenant-two", "query-secret", "other.example"} {
		if strings.Contains(string(out), secret) {
			t.Fatalf("captured value retained: %s", secret)
		}
	}
	kinds := map[string]int{}
	for _, h := range candidates[0].Hypotheses {
		if h.State != "unconfirmed" {
			t.Fatal("hypothesis marked as fact")
		}
		kinds[h.Kind]++
	}
	if kinds["candidate_owner"] != 2 || kinds["cross_tenant"] != 1 || kinds["object_identifier"] != 1 {
		t.Fatalf("unexpected hypotheses: %s", out)
	}
}

func TestCandidatesRequireOriginAndValidHAR(t *testing.T) {
	s, _ := openapi.Parse([]byte(`{"paths":{"/x/{id}":{"get":{}}}}`))
	for _, har := range []string{`{`, `{}`, `{"log":{"entries":[]}}`} {
		if _, err := Candidates(s, "", []byte(har)); err == nil {
			t.Fatalf("accepted invalid/missing scope: %s", har)
		}
	}
}

func TestCandidatesDoNotTreatTokenRotationAsProvenIdentity(t *testing.T) {
	s, _ := openapi.Parse([]byte(`{"paths":{"/x/{id}":{"get":{}}}}`))
	c, err := Candidates(s, "", nil)
	if err != nil || len(c) != 1 {
		t.Fatalf("spec-only discovery failed: %v", err)
	}
	for _, h := range c[0].Hypotheses {
		if h.Kind == "candidate_owner" || h.Kind == "cross_tenant" {
			t.Fatal("invented traffic evidence")
		}
	}
}
