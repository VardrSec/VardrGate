package engine

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/VardrSec/vardrgate/internal/model"
)

// recordingExecutor answers per URL and records every request it saw, so a test
// can assert what the engine actually sent after substitution.
type recordingExecutor struct {
	byURL    map[string]model.ExecutionResult
	fallback model.ExecutionResult
	seen     []seenRequest
}

type seenRequest struct {
	identityID string
	credential string
	method     string
	url        string
	body       string
}

func (r *recordingExecutor) Execute(_ context.Context, identity model.Identity, tmpl model.RequestTemplate) model.ExecutionResult {
	r.seen = append(r.seen, seenRequest{
		identityID: identity.ID,
		credential: identity.Credential.Value,
		method:     tmpl.Method,
		url:        tmpl.URL,
		body:       string(tmpl.Body),
	})
	if res, ok := r.byURL[tmpl.URL]; ok {
		res.IdentityID = identity.ID
		return res
	}
	res := r.fallback
	res.IdentityID = identity.ID
	return res
}

func setupTC() model.AuthorizationTestCase {
	return model.AuthorizationTestCase{
		ID: "tc-setup",
		Identities: []model.Identity{
			{ID: "owner", Role: "owner", Credential: model.Credential{Type: model.CredentialTypeBearer, Value: "placeholder"}},
			{ID: "other", Role: "other", Credential: model.Credential{Type: model.CredentialTypeBearer, Value: "other-token"}},
		},
		Request: model.RequestTemplate{Method: http.MethodGet, URL: "https://api.example.com/objects/{{object_id}}"},
		ExpectedAccess: []model.ExpectedAccess{
			{IdentityID: "owner", Decision: model.AccessDecisionAllow},
			{IdentityID: "other", Decision: model.AccessDecisionDeny},
		},
	}
}

// Creating an object as one identity and reading it as another is the class of
// bug a single stateless request cannot reach.
func TestRunSetup_CapturedIDReachesTheRequestURL(t *testing.T) {
	tc := setupTC()
	tc.Mutating = true
	tc.Setup = []model.SetupStep{{
		Name:    "create",
		As:      "owner",
		Request: model.RequestTemplate{Method: http.MethodPost, URL: "https://api.example.com/objects"},
		Capture: map[string]string{"object_id": "id"},
	}}

	exec := &recordingExecutor{
		byURL: map[string]model.ExecutionResult{
			"https://api.example.com/objects": {StatusCode: 201, Body: []byte(`{"id":"obj-99"}`)},
		},
		fallback: model.ExecutionResult{StatusCode: 200, Body: []byte(`{"ok":true}`)},
	}

	if _, err := New(exec).Run(context.Background(), tc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, req := range exec.seen[1:] {
		if req.url != "https://api.example.com/objects/obj-99" {
			t.Errorf("captured id did not reach the request: %q", req.url)
		}
	}
}

// A login handshake is the other half of the same mechanism.
func TestRunSetup_CapturedTokenBecomesTheCredential(t *testing.T) {
	tc := setupTC()
	tc.Request.URL = "https://api.example.com/objects/1"
	tc.Identities[0].Credential.Value = "{{token}}"
	tc.Setup = []model.SetupStep{{
		Name:    "login",
		Request: model.RequestTemplate{Method: http.MethodGet, URL: "https://api.example.com/login"},
		Capture: map[string]string{"token": "data.access_token"},
	}}

	exec := &recordingExecutor{
		byURL: map[string]model.ExecutionResult{
			"https://api.example.com/login": {StatusCode: 200, Body: []byte(`{"data":{"access_token":"tok-abc"}}`)},
		},
		fallback: model.ExecutionResult{StatusCode: 200, Body: []byte(`{"ok":true}`)},
	}

	if _, err := New(exec).Run(context.Background(), tc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var sawOwner bool
	for _, req := range exec.seen {
		if req.identityID != "owner" {
			continue
		}
		sawOwner = true
		if req.credential != "tok-abc" {
			t.Errorf("owner credential = %q, want the captured token", req.credential)
		}
	}
	if !sawOwner {
		t.Fatal("owner never executed")
	}
}

// The login step itself must not present a credential it does not have yet.
func TestRunSetup_StepWithoutAsSendsNoCredential(t *testing.T) {
	tc := setupTC()
	tc.Request.URL = "https://api.example.com/objects/1"
	tc.Setup = []model.SetupStep{{
		Name:    "login",
		Request: model.RequestTemplate{Method: http.MethodGet, URL: "https://api.example.com/login"},
	}}
	exec := &recordingExecutor{fallback: model.ExecutionResult{StatusCode: 200, Body: []byte(`{}`)}}

	if _, err := New(exec).Run(context.Background(), tc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exec.seen[0].credential != "" {
		t.Errorf("setup step sent credential %q, want none", exec.seen[0].credential)
	}
}

func TestRunSetup_FailedStepAbortsTheRun(t *testing.T) {
	tests := []struct {
		name string
		exec *recordingExecutor
		want string
	}{
		{
			name: "network error",
			exec: &recordingExecutor{byURL: map[string]model.ExecutionResult{
				"https://api.example.com/login": {Error: "connection refused"},
			}},
			want: "connection refused",
		},
		{
			name: "error status",
			exec: &recordingExecutor{byURL: map[string]model.ExecutionResult{
				"https://api.example.com/login": {StatusCode: 500},
			}},
			want: "returned 500",
		},
		{
			name: "capture path missing",
			exec: &recordingExecutor{byURL: map[string]model.ExecutionResult{
				"https://api.example.com/login": {StatusCode: 200, Body: []byte(`{"nope":1}`)},
			}},
			want: "no value at",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := setupTC()
			tc.Request.URL = "https://api.example.com/objects/1"
			tc.Setup = []model.SetupStep{{
				Name:    "login",
				Request: model.RequestTemplate{Method: http.MethodGet, URL: "https://api.example.com/login"},
				Capture: map[string]string{"token": "data.access_token"},
			}}
			_, err := New(tt.exec).Run(context.Background(), tc)
			if err == nil {
				t.Fatal("expected the run to abort")
			}
			// A test that proceeds without its precondition reports a clean
			// result for something it never checked.
			if !errors.Is(err, ErrSetupFailed) {
				t.Errorf("error should wrap ErrSetupFailed: %v", err)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not mention %q", err, tt.want)
			}
		})
	}
}

func TestValidateSetup_RejectsBadSteps(t *testing.T) {
	tests := []struct {
		name  string
		steps []model.SetupStep
		want  string
	}{
		{"missing request", []model.SetupStep{{Name: "a"}}, "method and url"},
		{
			"unknown identity",
			[]model.SetupStep{{Name: "a", As: "ghost", Request: model.RequestTemplate{Method: "GET", URL: "https://x.test/"}}},
			"unknown identity",
		},
		{
			"duplicate name",
			[]model.SetupStep{
				{Name: "a", Request: model.RequestTemplate{Method: "GET", URL: "https://x.test/"}},
				{Name: "a", Request: model.RequestTemplate{Method: "GET", URL: "https://x.test/"}},
			},
			"duplicate name",
		},
		{
			"empty capture path",
			[]model.SetupStep{{Name: "a", Request: model.RequestTemplate{Method: "GET", URL: "https://x.test/"}, Capture: map[string]string{"v": ""}}},
			"variable name and a response path",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := setupTC()
			tc.Request.URL = "https://api.example.com/objects/1"
			tc.Setup = tt.steps
			_, err := New(&recordingExecutor{}).Run(context.Background(), tc)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got %v, want an error mentioning %q", err, tt.want)
			}
		})
	}
}

// A setup step that mutates is still a mutation.
func TestValidateSetup_UnsafeStepNeedsTheSameOptIn(t *testing.T) {
	tc := setupTC()
	tc.Request.URL = "https://api.example.com/objects/1"
	tc.Setup = []model.SetupStep{{
		Name:    "create",
		Request: model.RequestTemplate{Method: http.MethodPost, URL: "https://api.example.com/objects"},
	}}
	_, err := New(&recordingExecutor{}).Run(context.Background(), tc)
	if err == nil || !strings.Contains(err.Error(), "changes server state") {
		t.Fatalf("got %v, want a mutation-safety error", err)
	}
}

func TestSubstitute(t *testing.T) {
	vars := map[string]string{"id": "42", "tok": "abc"}
	tests := []struct {
		in      string
		want    string
		wantErr string
	}{
		{in: "no vars", want: "no vars"},
		{in: "/objects/{{id}}", want: "/objects/42"},
		{in: "{{id}}-{{tok}}", want: "42-abc"},
		{in: "{{ id }}", want: "42"},
		{in: "{{missing}}", wantErr: "no setup step captured"},
		{in: "{{unterminated", wantErr: "unterminated"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := substitute(tt.in, vars)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("got %v, want error containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSubstituteJSON_StaysValidJSON(t *testing.T) {
	// A captured value containing a quote would break the document if inserted
	// raw, so values are escaped and the result re-validated.
	body := json.RawMessage(`{"name":"{{v}}"}`)
	got, err := substituteJSON(body, map[string]string{"v": `he said "hi"`})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !json.Valid(got) {
		t.Fatalf("substitution produced invalid JSON: %s", got)
	}
	var parsed struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.Name != `he said "hi"` {
		t.Errorf("name = %q, want the original value", parsed.Name)
	}
}

func TestRunSetup_StepsRunInOrderAndSeeEarlierVars(t *testing.T) {
	tc := setupTC()
	tc.Request.URL = "https://api.example.com/objects/{{second}}"
	tc.Setup = []model.SetupStep{
		{
			Name:    "first",
			Request: model.RequestTemplate{Method: http.MethodGet, URL: "https://api.example.com/one"},
			Capture: map[string]string{"first": "id"},
		},
		{
			Name:    "second",
			Request: model.RequestTemplate{Method: http.MethodGet, URL: "https://api.example.com/two/{{first}}"},
			Capture: map[string]string{"second": "id"},
		},
	}
	exec := &recordingExecutor{
		byURL: map[string]model.ExecutionResult{
			"https://api.example.com/one":     {StatusCode: 200, Body: []byte(`{"id":"A"}`)},
			"https://api.example.com/two/A":   {StatusCode: 200, Body: []byte(`{"id":"B"}`)},
			"https://api.example.com/objects": {StatusCode: 200, Body: []byte(`{}`)},
		},
		fallback: model.ExecutionResult{StatusCode: 200, Body: []byte(`{}`)},
	}
	if _, err := New(exec).Run(context.Background(), tc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exec.seen[1].url != "https://api.example.com/two/A" {
		t.Errorf("second step did not see the first step's variable: %q", exec.seen[1].url)
	}
	if exec.seen[2].url != "https://api.example.com/objects/B" {
		t.Errorf("request under test = %q, want the second capture", exec.seen[2].url)
	}
}

func TestRun_NoSetupIsUnchanged(t *testing.T) {
	tc := setupTC()
	tc.Request.URL = "https://api.example.com/objects/1"
	exec := &recordingExecutor{fallback: model.ExecutionResult{StatusCode: 200, Body: []byte(`{}`)}}
	if _, err := New(exec).Run(context.Background(), tc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(exec.seen) != 2 {
		t.Errorf("expected only the two identity executions, got %d", len(exec.seen))
	}
}
