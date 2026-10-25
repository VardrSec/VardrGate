package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
)

// This deliberately vulnerable app is only started on loopback by the harness.
// Alice owns document 1 in tenant A; Bob is her tenant peer, Mallory belongs
// to tenant B, and only Admin may export. Tokens are synthetic actor names.
type lab struct {
	mu       sync.Mutex
	audit    map[string][]observation
	document string
}

type observation struct {
	Actor          string `json:"actor"`
	Accessed       bool   `json:"accessed"`
	Writes         int    `json:"writes"`
	Status         int    `json:"status"`
	Body           string `json:"body"`
	DocumentBefore string `json:"document_before,omitempty"`
	DocumentAfter  string `json:"document_after,omitempty"`
}

func (l *lab) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	actor := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer lab-")
	if actor == "" {
		actor = "anonymous"
	}
	o := observation{Actor: actor, Status: http.StatusForbidden, Body: `{"error":"forbidden"}`}
	read := func() {
		o.Accessed = true
		o.Status = 200
		o.Body = `{"document_id":1,"secret":"synthetic-tenant-A-data"}`
	}
	write := func() {
		l.mu.Lock()
		o.DocumentBefore = l.document
		l.document += "|modified-by-" + actor
		o.DocumentAfter = l.document
		l.mu.Unlock()
		o.Accessed = true
		o.Writes++
		o.Status = 204
		o.Body = ""
	}
	switch r.URL.Path {
	case "/vulnerable/documents/1", "/vulnerable/admin/export":
		read() // Deliberately omits ownership, tenant, role, and authentication checks.
	case "/secure/documents/1":
		if actor == "alice" {
			read()
		} else if actor == "anonymous" {
			o.Status = 401
		}
	case "/vulnerable/documents/1/update":
		if r.Method == http.MethodPost {
			write()
		} else {
			o.Status = 405
		}
	case "/secure/documents/1/update":
		if r.Method != http.MethodPost {
			o.Status = 405
		} else if actor == "alice" {
			write()
		}
	case "/secure/documents/1/content":
		// The owner's view of the document's current state, used by write
		// verification. It reads through the lab API, never the audit.
		if actor == "alice" {
			l.mu.Lock()
			content, _ := json.Marshal(map[string]string{"content": l.document})
			l.mu.Unlock()
			o.Status, o.Body = 200, string(content)
		}
	case "/edge/soft-denial":
		o.Status = 200
	case "/edge/empty":
		o.Status = 200
		o.Body = `{"data":[]}`
	case "/edge/leak-403":
		read()
		o.Status = 403
	case "/edge/leak-404":
		read()
		o.Status = 404
	case "/edge/write-500":
		if r.Method == http.MethodPost {
			write()
			o.Status = 500
			o.Body = `{"error":"failed after mutation"}`
		} else {
			o.Status = 405
		}
	case "/edge/masked":
		o.Status = 404
	case "/edge/redirect":
		o.Status = 302
		w.Header().Set("Location", "/secure/documents/1")
	case "/edge/rate-limit":
		o.Status = 429
	case "/edge/unavailable":
		o.Status = 503
	case "/edge/disconnect":
		o.Status = 0
		o.Body = ""
	case "/edge/over-denial":
		// Incorrectly denies even Alice, the resource owner.
	default:
		http.NotFound(w, r)
		return
	}
	l.mu.Lock()
	l.audit[r.Header.Get("X-Benchmark-Case")] = append(l.audit[r.Header.Get("X-Benchmark-Case")], o)
	l.mu.Unlock()
	if o.Status == 0 {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = conn.Close()
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(o.Status)
	_, _ = fmt.Fprint(w, o.Body)
}

func (l *lab) observations(id string) []observation {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]observation(nil), l.audit[id]...)
}
