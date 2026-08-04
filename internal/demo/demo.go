// Package demo runs VardrGate end to end against a deliberately broken local
// API, with no setup and no credentials.
//
// It exists because the first command in the README used to point at a service
// the reader does not have running: every identity failed to connect and the
// command still exited 0. A first run should prove the tool works, so this one
// ships its own target.
//
// The fixture is a fake profile API that enforces nothing: it answers every
// caller, authenticated or not, from any tenant, and includes a live-looking
// API key in the body. Running the bundled policy against it produces the
// missing_authentication, cross_tenant_access, and sensitive_data_exposure
// findings the policy is written to catch.
package demo

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/VardrSec/vardrgate/internal/client"
	"github.com/VardrSec/vardrgate/internal/engine"
	"github.com/VardrSec/vardrgate/internal/model"
	"github.com/VardrSec/vardrgate/internal/policy"
)

// Policy mirrors examples/profile_ownership.policy.yaml. It is inlined so the
// binary is self-contained; policy_sync_test.go fails if the two drift.
const Policy = `api:
  endpoint: GET /users/{user_id}/profile
  owner: identity:owner
  resource:
    type: user_profile
    id_param: user_id
    tenant_field: tenant_id

expect:
  owner: allow
  other_user: deny
  anonymous: deny

response:
  deny_status: [401, 403, 404]
  sensitive_fields:
    forbidden_for:
      - other_user
      - anonymous
`

// vulnerableProfile is what the fixture returns to anyone who asks. The
// tenant_id belongs to the owner's tenant, so a caller from another tenant
// receiving this body is a self-evidencing isolation break; api_key is the
// sensitive field that must never reach a non-owner.
const vulnerableProfile = `{
  "user_id": "42",
  "tenant_id": "tenant-a",
  "email": "owner@example.com",
  "display_name": "Resource Owner",
  "api_key": "sk_live_demo_this_should_never_be_returned"
}`

// Identities are the callers the demo binds to the policy. Roles match the
// policy's expect keys. The tokens are fake — the fixture ignores them.
func Identities() []model.Identity {
	return []model.Identity{
		{
			ID:         "owner",
			Name:       "Resource Owner",
			Role:       "owner",
			TenantID:   "tenant-a",
			Credential: model.Credential{Type: model.CredentialTypeBearer, Value: "demo-owner-token"},
		},
		{
			ID:         "other_user",
			Name:       "Authenticated User In Another Tenant",
			Role:       "other_user",
			TenantID:   "tenant-b",
			Credential: model.Credential{Type: model.CredentialTypeBearer, Value: "demo-other-token"},
		},
		{
			ID:         "anonymous",
			Name:       "Unauthenticated Caller",
			Role:       "anonymous",
			Credential: model.Credential{Type: model.CredentialTypeStaticHeader},
		},
	}
}

// StartFixture starts the vulnerable API on a loopback port and returns its
// base URL together with a shutdown func. The listener is bound before
// returning, so the caller can issue a request immediately without polling.
func StartFixture() (baseURL string, stop func(), err error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, fmt.Errorf("start demo fixture: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /users/{user_id}/profile", func(w http.ResponseWriter, r *http.Request) {
		// No authentication check, no ownership check, no tenant check.
		// That is the point.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(vulnerableProfile))
	})

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()

	return "http://" + ln.Addr().String(), func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}, nil
}

// Run starts the fixture, compiles the bundled policy against it, executes it,
// and returns the result. The engine is configured to allow private targets
// because the fixture is on loopback; this is scoped to the demo and does not
// affect any other execution path.
func Run(ctx context.Context) (engine.Result, error) {
	baseURL, stop, err := StartFixture()
	if err != nil {
		return engine.Result{}, err
	}
	defer stop()

	p, err := policy.Parse([]byte(Policy))
	if err != nil {
		return engine.Result{}, fmt.Errorf("demo policy: %w", err)
	}

	tc, err := p.Compile(policy.Bindings{
		TestCaseID: "demo-profile-ownership",
		BaseURL:    baseURL,
		PathParams: map[string]string{"user_id": "42"},
		Identities: Identities(),
	})
	if err != nil {
		return engine.Result{}, fmt.Errorf("demo policy: %w", err)
	}

	eng := engine.New(client.NewWithConfig(nil, client.Config{AllowPrivateTargets: true}))
	return eng.Run(ctx, tc)
}
