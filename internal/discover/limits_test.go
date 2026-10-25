package discover

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/VardrSec/vardrgate/internal/openapi"
)

func TestHARLimits(t *testing.T) {
	s, _ := openapi.Parse([]byte(`{"paths":{"/x/{id}":{"get":{}}}}`))
	entry := func(text, encoding string) map[string]any {
		return map[string]any{"response": map[string]any{"content": map[string]any{"text": text, "encoding": encoding}}}
	}
	for _, tt := range []struct {
		name    string
		entries []any
	}{
		{"entry count", make([]any, MaxHAREntries+1)},
		{"plain response", []any{entry(strings.Repeat("x", MaxHARResponseBytes+1), "")}},
		{"encoded response", []any{entry(strings.Repeat("x", base64.StdEncoding.EncodedLen(MaxHARResponseBytes)+1), "base64")}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			har, _ := json.Marshal(map[string]any{"log": map[string]any{"entries": tt.entries}})
			if _, err := Candidates(s, "https://example.test", har); err == nil {
				t.Fatal("oversized input accepted")
			}
		})
	}
	entries := make([]any, 9)
	for i := range entries {
		entries[i] = entry(strings.Repeat("x", MaxHARResponseBytes), "")
	}
	har, _ := json.Marshal(map[string]any{"log": map[string]any{"entries": entries}})
	if _, err := Candidates(s, "https://example.test", har); err == nil {
		t.Fatal("aggregate response budget ignored")
	}
	entries = make([]any, 2001)
	har, _ = json.Marshal(map[string]any{"log": map[string]any{"entries": entries}})
	s.Paths = make(map[string]openapi.PathItem)
	for i := 0; i < 1000; i++ {
		s.Paths[strings.Repeat("x", i+1)] = openapi.PathItem{Get: &openapi.Operation{}}
	}
	if _, err := Candidates(s, "https://example.test", har); err == nil {
		t.Fatal("correlation budget ignored")
	}
}

func TestHARDecodedAndRepeatedAnalysisBudgets(t *testing.T) {
	spec := openapi.Spec{Paths: map[string]openapi.PathItem{}}
	for i := 0; i < 65; i++ {
		spec.Paths[fmt.Sprintf("/x/{id%d}", i)] = openapi.PathItem{Get: &openapi.Operation{}}
	}
	entry := capture{}
	entry.Request.URL, entry.Request.Method, entry.Response.Status = "https://example.test/x/1", "GET", 200
	entry.Response.Content.Text = strings.Repeat("x", MaxHARResponseBytes)
	har, _ := json.Marshal(map[string]any{"log": map[string]any{"entries": []capture{entry}}})
	if _, err := Candidates(spec, "https://example.test", har); err == nil || !strings.Contains(err.Error(), "64 MiB") {
		t.Fatalf("repeated analysis unbounded: %v", err)
	}
	spec.Paths = map[string]openapi.PathItem{"/x/{id}": {Get: &openapi.Operation{}}}
	entry.Response.Content.Text = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", MaxHARResponseBytes+1)))
	entry.Response.Content.Encoding = "base64"
	har, _ = json.Marshal(map[string]any{"log": map[string]any{"entries": []capture{entry}}})
	if _, err := Candidates(spec, "https://example.test", har); err == nil || !strings.Contains(err.Error(), "decoded") {
		t.Fatalf("decoded response bound missed: %v", err)
	}
}

func TestHARHypothesisOutputIsBounded(t *testing.T) {
	spec := openapi.Spec{Paths: map[string]openapi.PathItem{}}
	for i := 0; i < 11; i++ {
		spec.Paths[fmt.Sprintf("/x/{id%d}", i)] = openapi.PathItem{Get: &openapi.Operation{}}
	}
	var entry capture
	if err := json.Unmarshal([]byte(`{"request":{"method":"GET","url":"https://example.test/x/1","headers":[{"name":"Authorization","value":"fixture-only"}]},"response":{"status":200}}`), &entry); err != nil {
		t.Fatal(err)
	}
	entries := make([]capture, MaxHAREntries)
	for i := range entries {
		entries[i] = entry
	}
	har, _ := json.Marshal(map[string]any{"log": map[string]any{"entries": entries}})
	if _, err := Candidates(spec, "https://example.test", har); err == nil || !strings.Contains(err.Error(), "hypotheses") {
		t.Fatalf("unbounded output: %v", err)
	}
}

func TestHARFileReadIsBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large.har")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(MaxHARBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := ReadHAR(path); err == nil {
		t.Fatal("read beyond file budget accepted")
	}
}
