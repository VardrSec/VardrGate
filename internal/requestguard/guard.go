// Package requestguard enforces Runner's validated fixed-request projection.
// It does not issue permission, resolve credentials, or replace engine validation.
package requestguard

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"

	"github.com/VardrSec/vardrgate/internal/model"
)

const Profile = "gate-fixed-http/1"
const maxPlanBytes = 1 << 20

var errDenied = errors.New("authorization request projection denied")

type phaseKey struct{}

func WithPhase(ctx context.Context, phase string) context.Context {
	return context.WithValue(ctx, phaseKey{}, phase)
}

type Request struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Query   map[string]string `json:"query_params"`
	Body    json.RawMessage   `json:"body"`
}

type Dispatch struct {
	Phase      string  `json:"phase"`
	IdentityID string  `json:"identity_id"`
	Request    Request `json:"request"`
	Max        int     `json:"max_dispatches"`
}

type Plan struct {
	Schema    string `json:"schema"`
	Profile   string `json:"profile"`
	ToolHash  string `json:"tool_sha256"`
	CaseHash  string `json:"case_hash"`
	Execution struct {
		Timeout      int   `json:"timeout_seconds"`
		MaxBytes     int64 `json:"max_response_bytes"`
		AllowPrivate bool  `json:"allow_private_targets"`
	} `json:"execution"`
	CredentialReferences []struct {
		IdentityID string `json:"identity_id"`
		Source     string `json:"source"`
		Name       string `json:"name"`
	} `json:"credential_references"`
	Dispatches []Dispatch `json:"dispatches"`
	Max        int        `json:"max_http_dispatches"`
}

type Guard struct {
	mu     sync.Mutex
	plan   Plan
	counts []int
	total  int
	stage  int
}

func hashValid(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && strings.ToLower(value) == value
}

// Parse rejects duplicate fields before decoding the strict projection schema.
func Parse(data []byte) (Plan, error) {
	var plan Plan
	if len(data) == 0 || len(data) > maxPlanBytes {
		return plan, errDenied
	}
	d := json.NewDecoder(bytes.NewReader(data))
	if err := unique(d, 0, 32); err != nil {
		return plan, errDenied
	}
	if _, err := d.Token(); err != io.EOF {
		return plan, errDenied
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&plan); err != nil {
		return Plan{}, errDenied
	}
	if _, err := New(plan); err != nil {
		return Plan{}, err
	}
	return plan, nil
}

func Load(path string) (Plan, error) {
	f, err := os.Open(path)
	if err != nil {
		return Plan{}, errDenied
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxPlanBytes+1))
	if err != nil {
		return Plan{}, errDenied
	}
	return Parse(data)
}

func unique(d *json.Decoder, depth, maxDepth int) error {
	if maxDepth >= 0 && depth > maxDepth {
		return errDenied
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return errDenied
			}
			seen[name] = true
			if err := unique(d, depth+1, maxDepth); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := unique(d, depth+1, maxDepth); err != nil {
				return err
			}
		}
	default:
		return errDenied
	}
	_, err = d.Token()
	return err
}

func stage(phase string) int {
	switch phase {
	case "setup":
		return 0
	case "preflight":
		return 1
	case "resource", "verification", "reset":
		return 2
	default:
		return -1
	}
}

func New(plan Plan) (*Guard, error) {
	if plan.Schema != "vardr.execution-plan/1" || plan.Profile != Profile || !hashValid(plan.ToolHash) || !hashValid(plan.CaseHash) || plan.Max < 1 || plan.Max > 100000 || len(plan.Dispatches) == 0 || len(plan.Dispatches) > 4096 || plan.Execution.Timeout < 1 || plan.Execution.Timeout > 600 || plan.Execution.MaxBytes < 1 || plan.Execution.MaxBytes > 5<<20 {
		return nil, errDenied
	}
	total := 0
	for _, d := range plan.Dispatches {
		u, err := url.Parse(d.Request.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Fragment != "" || strings.ContainsAny(d.Request.URL, "{}\\") || stage(d.Phase) < 0 || d.IdentityID == "" || d.Max < 1 || d.Max > 100000 {
			return nil, errDenied
		}
		switch d.Request.Method {
		case "GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE":
		default:
			return nil, errDenied
		}
		if _, ok := lower(d.Request.Headers); !ok {
			return nil, errDenied
		}
		if _, err := body(d.Request.Body); err != nil {
			return nil, errDenied
		}
		total += d.Max
	}
	if total != plan.Max {
		return nil, errDenied
	}
	// Callers cannot mutate the approved projection after construction.
	cloned := make([]Dispatch, len(plan.Dispatches))
	for i, dispatch := range plan.Dispatches {
		cloned[i] = dispatch
		cloned[i].Request.Headers, _ = lower(dispatch.Request.Headers)
		cloned[i].Request.Query = map[string]string{}
		for key, value := range dispatch.Request.Query {
			cloned[i].Request.Query[key] = value
		}
		cloned[i].Request.Body = append(json.RawMessage(nil), dispatch.Request.Body...)
	}
	plan.Dispatches = cloned
	return &Guard{plan: plan, counts: make([]int, len(plan.Dispatches)), stage: -1}, nil
}

func (p Plan) CheckBinary(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return errDenied
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return errDenied
	}
	if hex.EncodeToString(h.Sum(nil)) != p.ToolHash {
		return errDenied
	}
	return nil
}

func lower(headers map[string]string) (map[string]string, bool) {
	result := map[string]string{}
	for key, value := range headers {
		name := strings.ToLower(key)
		if _, exists := result[name]; exists {
			return nil, false
		}
		result[name] = value
	}
	return result, true
}

func body(raw json.RawMessage) (any, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var value any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&value); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errDenied
	}
	// Decode above retains the JSON decoder's syntax and nesting limits. Check
	// decoded key names before map equality can hide duplicates in the raw bytes
	// sent by the client. UseNumber also accepts numbers outside float64 range.
	d = json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := unique(d, 0, -1); err != nil {
		return nil, err
	}
	return value, nil
}

// Allow reserves one logical dispatch before DNS, TLS or target traffic.
// The trusted Runner separately validates signature, scope, approval and grants.
func (g *Guard) Allow(ctx context.Context, actor model.Identity, request model.RequestTemplate) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	phase, _ := ctx.Value(phaseKey{}).(string)
	current := stage(phase)
	if current < g.stage || current < 0 || g.total >= g.plan.Max || ctx.Err() != nil {
		return errDenied
	}
	headers, ok := lower(request.Headers)
	if !ok {
		return errDenied
	}
	actualBody, err := body(request.Body)
	if err != nil {
		return errDenied
	}
	method := request.Method
	if method == "" {
		method = "GET"
	}
	query := request.QueryParams
	if query == nil {
		query = map[string]string{}
	}
	for i, d := range g.plan.Dispatches {
		expectedHeaders, _ := lower(d.Request.Headers)
		expectedBody, _ := body(d.Request.Body)
		expectedQuery := d.Request.Query
		if expectedQuery == nil {
			expectedQuery = map[string]string{}
		}
		if d.Phase == phase && d.IdentityID == actor.ID && d.Request.Method == method && d.Request.URL == request.URL && reflect.DeepEqual(expectedHeaders, headers) && reflect.DeepEqual(expectedQuery, query) && reflect.DeepEqual(expectedBody, actualBody) && g.counts[i] < d.Max {
			g.counts[i]++
			g.total++
			g.stage = current
			return nil
		}
	}
	return errDenied
}
