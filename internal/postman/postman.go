// Package postman parses a Postman Collection (v2.1) and generates starter
// authorization test cases from its requests — one per request, folders
// flattened. Like the OpenAPI importer, the output is a runnable scaffold once
// real credential values are added.
package postman

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/VardrSec/vardrgate/internal/model"
	"github.com/VardrSec/vardrgate/internal/scaffold"
)

// Collection is the parsed subset of a Postman v2.1 collection.
type Collection struct {
	Info  Info   `json:"info"`
	Items []Item `json:"item"`
}

// Info carries collection metadata.
type Info struct {
	Name string `json:"name"`
}

// Item is either a request or a folder containing nested items.
type Item struct {
	Name    string   `json:"name"`
	Request *Request `json:"request"`
	Items   []Item   `json:"item"`
}

// Request is a single HTTP request.
type Request struct {
	Method string `json:"method"`
	URL    URL    `json:"url"`
}

// URL is a Postman URL, which may be a raw string or an object with a "raw" field.
type URL struct {
	Raw string
}

// UnmarshalJSON accepts both the string and object forms of a Postman URL.
func (u *URL) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		u.Raw = s
		return nil
	}
	var o struct {
		Raw string `json:"raw"`
	}
	if err := json.Unmarshal(data, &o); err != nil {
		return fmt.Errorf("parse url: %w", err)
	}
	u.Raw = o.Raw
	return nil
}

// Parse decodes a Postman collection.
func Parse(data []byte) (Collection, error) {
	var c Collection
	if err := json.Unmarshal(data, &c); err != nil {
		return Collection{}, fmt.Errorf("parse postman collection: %w", err)
	}
	if len(c.Items) == 0 {
		return Collection{}, fmt.Errorf("parse postman collection: no items")
	}
	return c, nil
}

// GenerateTestCases produces one starter test case per request, folders
// flattened in document order. When baseURL is set, each request's origin is
// replaced with it (so a collection can be retargeted at another environment).
func (c Collection) GenerateTestCases(baseURL string) []model.AuthorizationTestCase {
	base := strings.TrimRight(baseURL, "/")
	var cases []model.AuthorizationTestCase
	var walk func(items []Item)
	walk = func(items []Item) {
		for _, it := range items {
			if it.Request != nil && it.Request.URL.Raw != "" {
				cases = append(cases, caseFromItem(base, it))
			}
			if len(it.Items) > 0 {
				walk(it.Items)
			}
		}
	}
	walk(c.Items)
	return cases
}

func caseFromItem(base string, it Item) model.AuthorizationTestCase {
	url := it.Request.URL.Raw
	if base != "" {
		url = base + requestPath(url)
	}
	method := it.Request.Method
	id := scaffold.Slug(strings.ToLower(strings.TrimSpace(it.Name)))
	id = strings.Trim(strings.ReplaceAll(id, " ", "-"), "-")
	if id == "" {
		id = strings.ToLower(method) + scaffold.Slug(requestPath(it.Request.URL.Raw))
	}
	return scaffold.StarterCase(id, it.Name, method, url)
}

// requestPath extracts the path (and query) from a URL, tolerating a bare path.
func requestPath(rawURL string) string {
	s := rawURL
	if i := strings.Index(s, "://"); i != -1 {
		s = s[i+3:]
		if j := strings.IndexByte(s, '/'); j != -1 {
			s = s[j:]
		} else {
			return "/"
		}
	}
	if !strings.HasPrefix(s, "/") {
		s = "/" + s
	}
	return s
}
