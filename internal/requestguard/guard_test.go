package requestguard

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/VardrSec/vardrgate/internal/model"
)

func fixturePlan() Plan {
	p := Plan{Schema: "vardr.execution-plan/1", Profile: Profile, ToolHash: strings.Repeat("a", 64), CaseHash: strings.Repeat("b", 64), Max: 1,
		Dispatches: []Dispatch{{Phase: "resource", IdentityID: "owner", Max: 1, Request: Request{Method: "GET", URL: "https://api.example.test/object", Headers: map[string]string{}, Query: map[string]string{}}}}}
	p.Execution.Timeout, p.Execution.MaxBytes = 30, 1000
	return p
}

func TestExactDispatchAndOneShotCount(t *testing.T) {
	g, err := New(fixturePlan())
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithPhase(context.Background(), "resource")
	actor := model.Identity{ID: "owner"}
	req := model.RequestTemplate{Method: "GET", URL: "https://api.example.test/object"}
	if g.Allow(ctx, actor, req) != nil {
		t.Fatal("approved request refused")
	}
	if g.Allow(ctx, actor, req) == nil {
		t.Fatal("duplicate dispatch admitted")
	}
}

func TestMismatchNeverSpendsPermission(t *testing.T) {
	for _, name := range []string{"phase", "identity", "method", "url", "headers", "query", "body", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			g, _ := New(fixturePlan())
			ctx := WithPhase(context.Background(), "resource")
			actor := model.Identity{ID: "owner"}
			req := model.RequestTemplate{Method: "GET", URL: "https://api.example.test/object"}
			switch name {
			case "phase":
				ctx = context.Background()
			case "identity":
				actor.ID = "peer"
			case "method":
				req.Method = "DELETE"
			case "url":
				req.URL = "https://outside.invalid/object"
			case "headers":
				req.Headers = map[string]string{"X-Changed": "yes"}
			case "query":
				req.QueryParams = map[string]string{"other": "yes"}
			case "body":
				req.Body = json.RawMessage(`{"changed":true}`)
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if g.Allow(ctx, actor, req) == nil || g.total != 0 {
				t.Fatal("unapproved request admitted or count spent")
			}
		})
	}
}

func TestPhaseCannotReturnToSetup(t *testing.T) {
	p := fixturePlan()
	p.Dispatches = append(p.Dispatches, Dispatch{Phase: "setup", IdentityID: "owner", Max: 1, Request: p.Dispatches[0].Request})
	p.Max++
	g, _ := New(p)
	req := model.RequestTemplate{URL: p.Dispatches[0].Request.URL, Method: "GET"}
	if g.Allow(WithPhase(context.Background(), "resource"), model.Identity{ID: "owner"}, req) != nil {
		t.Fatal("resource refused")
	}
	if g.Allow(WithPhase(context.Background(), "setup"), model.Identity{ID: "owner"}, req) == nil {
		t.Fatal("late setup admitted")
	}
}

func TestConcurrentCountReservation(t *testing.T) {
	g, _ := New(fixturePlan())
	var wins atomic.Int32
	var group sync.WaitGroup
	for i := 0; i < 8; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if g.Allow(WithPhase(context.Background(), "resource"), model.Identity{ID: "owner"}, model.RequestTemplate{Method: "GET", URL: "https://api.example.test/object"}) == nil {
				wins.Add(1)
			}
		}()
	}
	group.Wait()
	if wins.Load() != 1 {
		t.Fatalf("count reservation winners=%d", wins.Load())
	}
}

func TestStrictProjectionParsing(t *testing.T) {
	valid, _ := json.Marshal(fixturePlan())
	if _, err := Parse(valid); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"", `{}`, `{"schema":1,"schema":2}`, `{"x":{"a":1,"a":2}}`, `[]`, string(valid) + `{}`, strings.Replace(string(valid), `"schema":`, `"unknown":1,"schema":`, 1), strings.Repeat("[", 40) + strings.Repeat("]", 40)} {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Fatal("malformed projection accepted")
		}
	}
	if _, err := Parse(make([]byte, maxPlanBytes+1)); err == nil {
		t.Fatal("oversize accepted")
	}
}

func TestInvalidProfileAndRequest(t *testing.T) {
	for _, name := range []string{"schema", "profile", "tool", "count", "sum", "timeout", "body", "method", "url", "phase", "actor", "headers"} {
		t.Run(name, func(t *testing.T) {
			p := fixturePlan()
			switch name {
			case "schema":
				p.Schema = "future"
			case "profile":
				p.Profile = "crawler"
			case "tool":
				p.ToolHash = "not-a-digest"
			case "count":
				p.Max = 0
			case "sum":
				p.Max = 2
			case "timeout":
				p.Execution.Timeout = 0
			case "body":
				p.Dispatches[0].Request.Body = json.RawMessage(`{`)
			case "method":
				p.Dispatches[0].Request.Method = "CONNECT"
			case "url":
				p.Dispatches[0].Request.URL = "file:///etc/passwd"
			case "phase":
				p.Dispatches[0].Phase = "autonomous"
			case "actor":
				p.Dispatches[0].IdentityID = ""
			case "headers":
				p.Dispatches[0].Request.Headers = map[string]string{"X-Test": "1", "x-test": "2"}
			}
			if _, err := New(p); err == nil {
				t.Fatal("invalid projection admitted")
			}
		})
	}
}

func TestBinaryBinding(t *testing.T) {
	p := fixturePlan()
	path := filepath.Join(t.TempDir(), "fixture")
	if err := os.WriteFile(path, []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	if p.CheckBinary(path) == nil || p.CheckBinary(path+"missing") == nil {
		t.Fatal("wrong binary accepted")
	}
}

func TestProjectionIsImmutableAndFileReadBounded(t *testing.T) {
	p := fixturePlan()
	g, err := New(p)
	if err != nil {
		t.Fatal(err)
	}
	p.Dispatches[0].Request.URL = "https://outside.invalid"
	p.Dispatches[0].Request.Headers["x-extra"] = "changed"
	if g.Allow(WithPhase(context.Background(), "resource"), model.Identity{ID: "owner"}, model.RequestTemplate{Method: "GET", URL: "https://api.example.test/object"}) != nil {
		t.Fatal("caller mutated projection")
	}
	path := filepath.Join(t.TempDir(), "projection.json")
	data, _ := json.Marshal(fixturePlan())
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path + "missing"); err == nil {
		t.Fatal("missing file accepted")
	}
	if err := os.WriteFile(path, make([]byte, maxPlanBytes+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("oversize file accepted")
	}
}

func TestDuplicateBodyKeysDenied(t *testing.T) {
	for _, tc := range []struct{ name, approved, duplicate string }{
		{"root", `{"role":"reader"}`, `{"role":"admin","role":"reader"}`},
		{"identical", `{"role":"reader"}`, `{"role":"reader","role":"reader"}`},
		{"nested", `{"user":{"role":"reader"}}`, `{"user":{"role":"admin","role":"reader"}}`},
		{"array", `[{"role":"reader"}]`, `[{"role":"admin","role":"reader"}]`},
		{"escaped", `{"role":"reader"}`, `{"role":"admin","\u0072ole":"reader"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := fixturePlan()
			p.Dispatches[0].Request.Body = json.RawMessage(tc.duplicate)
			if _, err := New(p); err == nil {
				t.Error("duplicate projected body accepted by New")
			}
			data, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Parse(data); err == nil {
				t.Error("duplicate projected body accepted by Parse")
			}
			p.Dispatches[0].Request.Body = json.RawMessage(tc.approved)
			g, err := New(p)
			if err != nil {
				t.Fatal(err)
			}
			ctx := WithPhase(context.Background(), "resource")
			actor := model.Identity{ID: "owner"}
			req := model.RequestTemplate{Method: "GET", URL: p.Dispatches[0].Request.URL, Body: json.RawMessage(tc.duplicate)}
			if g.Allow(ctx, actor, req) == nil {
				t.Error("duplicate actual body accepted")
			}
			if g.total != 0 || g.counts[0] != 0 || g.stage != -1 {
				t.Error("denial changed guard state")
			}
			req.Body = json.RawMessage(tc.approved)
			if err := g.Allow(ctx, actor, req); err != nil {
				t.Fatal("subsequent valid request denied")
			}
		})
	}
}

func TestBodyComparisonSemantics(t *testing.T) {
	deep := strings.Repeat("[", 64) + "1" + strings.Repeat("]", 64)
	for _, tc := range []struct {
		name, approved, actual string
		allowed                bool
	}{
		{"formatting and key order", `{"a":1,"b":true}`, " {\"b\":true, \"a\":1} \n", true},
		{"escaped key", `{"role":"reader"}`, `{"\u0072ole":"reader"}`, true},
		{"separate objects", `[{"a":1},{"a":2}]`, `[{"a":1},{"a":2}]`, true},
		{"case distinct", `{"a":1,"A":2}`, `{"A":2,"a":1}`, true},
		{"deep body", deep, deep, true},
		{"large number", `1e400`, `1e400`, true},
		{"precise integer", `9007199254740993`, `9007199254740992`, false},
		{"number spelling", `1`, `1.0`, false},
		{"number exponent", `1`, `1e0`, false},
		{"string", `"hello"`, `"hello"`, true},
		{"null", `null`, `null`, true},
		{"empty", ``, ``, true},
		{"absent and null", ``, `null`, true},
		{"array order", `[1,2]`, `[2,1]`, false},
		{"trailing value", `{}`, `{} {}`, false},
		{"trailing junk", `{}`, `{} x`, false},
		{"malformed", `{}`, `{"a":}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := fixturePlan()
			p.Dispatches[0].Request.Body = json.RawMessage(tc.approved)
			g, err := New(p)
			if err != nil {
				t.Fatal(err)
			}
			err = g.Allow(WithPhase(context.Background(), "resource"), model.Identity{ID: "owner"}, model.RequestTemplate{Method: "GET", URL: p.Dispatches[0].Request.URL, Body: json.RawMessage(tc.actual)})
			if (err == nil) != tc.allowed {
				t.Fatalf("allowed=%v, want %v", err == nil, tc.allowed)
			}
		})
	}
}
