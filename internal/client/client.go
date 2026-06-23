package client

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/VardrSec/vardrgate/internal/model"
	"github.com/VardrSec/vardrgate/internal/urlcheck"
)

const (
	defaultTimeout      = 30 * time.Second
	defaultMaxBodyBytes = 5 * 1024 * 1024 // 5 MB
)

// Config controls client behaviour. Zero values use safe defaults.
type Config struct {
	Timeout             time.Duration
	MaxBodyBytes        int64
	AllowPrivateTargets bool // permit loopback and private-network targets
}

// Client executes HTTP requests on behalf of an identity.
// It never logs or exposes raw credential values.
type Client struct {
	http *http.Client
	cfg  Config
}

// New returns a Client with safe defaults:
// private and loopback targets blocked, 30 s timeout, 5 MB body limit.
func New(httpClient *http.Client) *Client {
	return NewWithConfig(httpClient, Config{})
}

// NewWithConfig returns a Client with the provided config.
// Zero-value fields use safe defaults.
//
// When httpClient is nil a default http.Client is constructed with a custom
// DialContext that resolves hostnames and validates every candidate address
// against the blocking policy at connect time. This prevents DNS rebinding:
// the IP used for the connection is the same one that was validated, with no
// second resolution between check and dial.
func NewWithConfig(httpClient *http.Client, cfg Config) *Client {
	if cfg.Timeout == 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.MaxBodyBytes == 0 {
		cfg.MaxBodyBytes = defaultMaxBodyBytes
	}
	if httpClient == nil {
		httpClient = buildHTTPClient(cfg.AllowPrivateTargets)
	}
	return &Client{http: httpClient, cfg: cfg}
}

// buildHTTPClient constructs an http.Client whose DialContext resolves
// hostnames and validates every candidate IP before opening a connection.
// Dialing uses the pre-validated IP directly so no second DNS resolution occurs.
func buildHTTPClient(allowPrivate bool) *http.Client {
	dialer := &net.Dialer{}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("split host/port %q: %w", addr, err)
			}

			addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, fmt.Errorf("cannot resolve %q: %w", host, err)
			}
			if len(addrs) == 0 {
				return nil, fmt.Errorf("host %q resolved to no addresses", host)
			}

			for _, a := range addrs {
				if err := urlcheck.CheckIP(a.IP, allowPrivate); err != nil {
					return nil, fmt.Errorf("target address blocked: %w", err)
				}
			}

			// Dial the first validated address directly — no re-resolution.
			return dialer.DialContext(ctx, network, net.JoinHostPort(addrs[0].IP.String(), port))
		},
	}
	return &http.Client{
		// Do not follow redirects; authorization tests must observe the
		// raw decision, not the post-redirect destination.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: transport,
	}
}

// Execute performs the request described by tmpl for the given identity.
// All errors are captured inside the result so the engine can continue
// with remaining identities.
func (c *Client) Execute(ctx context.Context, identity model.Identity, tmpl model.RequestTemplate) model.ExecutionResult {
	result := model.ExecutionResult{IdentityID: identity.ID}

	// Pre-flight: validate scheme and literal IPs before spending the timeout budget.
	// Hostname-based targets are validated at connect time by the DialContext.
	if err := urlcheck.Check(ctx, tmpl.URL, c.cfg.AllowPrivateTargets); err != nil {
		result.Error = err.Error()
		result.ErrorKind = model.ErrorKindURLValidation
		result.ObservedOutcome = model.OutcomeError
		return result
	}

	reqCtx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()

	req, err := c.buildRequest(reqCtx, identity, tmpl)
	if err != nil {
		result.Error = fmt.Sprintf("build request: %s", err)
		result.ErrorKind = model.ErrorKindBuildRequest
		result.ObservedOutcome = model.OutcomeError
		return result
	}

	start := time.Now()
	resp, err := c.http.Do(req)
	result.DurationMS = time.Since(start).Milliseconds()

	if err != nil {
		result.Error = fmt.Sprintf("execute request: %s", err)
		result.ErrorKind = model.ErrorKindNetwork
		result.ObservedOutcome = model.OutcomeError
		return result
	}
	defer resp.Body.Close()

	lr := io.LimitReader(resp.Body, c.cfg.MaxBodyBytes+1)
	body, err := io.ReadAll(lr)
	if err != nil {
		result.Error = fmt.Sprintf("read body: %s", err)
		result.ErrorKind = model.ErrorKindBodyRead
		result.ObservedOutcome = model.OutcomeError
		return result
	}
	if int64(len(body)) > c.cfg.MaxBodyBytes {
		result.Error = fmt.Sprintf("response body exceeded maximum of %d bytes", c.cfg.MaxBodyBytes)
		result.ErrorKind = model.ErrorKindBodySizeExceeded
		result.ObservedOutcome = model.OutcomeError
		return result
	}

	result.StatusCode = resp.StatusCode
	result.ObservedOutcome = model.ClassifyOutcome(resp.StatusCode, false)
	result.Body = body
	result.Headers = selectedHeaders(resp.Header)
	return result
}

// buildRequest constructs an *http.Request with credentials applied.
// ctx must already carry the per-request timeout.
func (c *Client) buildRequest(ctx context.Context, identity model.Identity, tmpl model.RequestTemplate) (*http.Request, error) {
	var body io.Reader
	if len(tmpl.Body) > 0 {
		body = bytes.NewReader(tmpl.Body)
	}

	req, err := http.NewRequestWithContext(ctx, tmpl.Method, tmpl.URL, body)
	if err != nil {
		return nil, err
	}

	for k, v := range tmpl.Headers {
		req.Header.Set(k, v)
	}

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
