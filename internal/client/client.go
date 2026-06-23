package client

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/VardrSec/vardrgate/internal/model"
)

const defaultTimeout = 30 * time.Second

// Client executes HTTP requests on behalf of an identity.
// It never logs or exposes raw credential values.
type Client struct {
	http    *http.Client
	timeout time.Duration
}

// New returns a Client using the provided http.Client.
// Pass a custom http.Client to control TLS, redirect policy, and transport.
func New(httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{
			// Do not follow redirects by default; authorization tests must
			// observe the raw decision, not the post-redirect destination.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return &Client{http: httpClient, timeout: defaultTimeout}
}

// Execute performs the request described by tmpl for the given identity and
// returns a populated ExecutionResult. Errors during execution are captured
// inside the result, not returned as Go errors, so the engine can continue
// with remaining identities.
func (c *Client) Execute(ctx context.Context, identity model.Identity, tmpl model.RequestTemplate) model.ExecutionResult {
	result := model.ExecutionResult{IdentityID: identity.ID}

	req, err := c.buildRequest(ctx, identity, tmpl)
	if err != nil {
		result.Error = fmt.Sprintf("build request: %s", err)
		return result
	}

	start := time.Now()
	resp, err := c.http.Do(req)
	result.DurationMS = time.Since(start).Milliseconds()

	if err != nil {
		result.Error = fmt.Sprintf("execute request: %s", err)
		return result
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Error = fmt.Sprintf("read body: %s", err)
		return result
	}

	result.StatusCode = resp.StatusCode
	result.Body = body
	result.Headers = selectedHeaders(resp.Header)
	return result
}

// buildRequest constructs an *http.Request with credentials applied.
func (c *Client) buildRequest(ctx context.Context, identity model.Identity, tmpl model.RequestTemplate) (*http.Request, error) {
	var body io.Reader
	if len(tmpl.Body) > 0 {
		body = bytes.NewReader(tmpl.Body)
	}

	reqCtx, cancel := context.WithTimeout(ctx, c.timeout)
	_ = cancel // caller's context controls overall lifetime; timeout provides a ceiling

	req, err := http.NewRequestWithContext(reqCtx, tmpl.Method, tmpl.URL, body)
	if err != nil {
		cancel()
		return nil, err
	}

	// Copy template headers first so credential application can override.
	for k, v := range tmpl.Headers {
		req.Header.Set(k, v)
	}

	// Apply query parameters.
	if len(tmpl.QueryParams) > 0 {
		q := req.URL.Query()
		for k, v := range tmpl.QueryParams {
			q.Set(k, v)
		}
		req.URL.RawQuery = q.Encode()
	}

	applyCredential(req, identity.Credential)

	if body != nil && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}

	return req, nil
}

// applyCredential attaches the credential to the request without logging its value.
func applyCredential(req *http.Request, cred model.Credential) {
	switch cred.Type {
	case model.CredentialTypeBearer:
		req.Header.Set("Authorization", "Bearer "+cred.Value)
	case model.CredentialTypeAPIKeyHeader:
		header := cred.Header
		if header == "" {
			header = "X-API-Key"
		}
		req.Header.Set(header, cred.Value)
	case model.CredentialTypeStaticHeader:
		if cred.Header != "" {
			req.Header.Set(cred.Header, cred.Value)
		}
	}
}

// selectedHeaders captures a small set of security-relevant response headers.
func selectedHeaders(h http.Header) map[string]string {
	keys := []string{
		"Content-Type",
		"WWW-Authenticate",
		"X-Request-Id",
		"X-RateLimit-Remaining",
	}
	out := make(map[string]string, len(keys))
	for _, k := range keys {
		if v := h.Get(k); v != "" {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Redact returns a copy of the credential with its value replaced by a
// placeholder. Use this when the credential must appear in logs or errors.
func Redact(cred model.Credential) model.Credential {
	c := cred
	if c.Value != "" {
		c.Value = "[REDACTED]"
	}
	return c
}
