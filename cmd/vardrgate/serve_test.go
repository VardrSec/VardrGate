package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestResolvePort(t *testing.T) {
	tests := []struct {
		name    string
		env     string
		want    int
		wantErr bool
	}{
		{name: "unset defaults to 8080", env: "", want: 8080},
		{name: "valid port", env: "3000", want: 3000},
		{name: "lower bound", env: "1", want: 1},
		{name: "upper bound", env: "65535", want: 65535},
		{name: "zero is rejected", env: "0", wantErr: true},
		{name: "above range is rejected", env: "65536", wantErr: true},
		{name: "negative is rejected", env: "-1", wantErr: true},
		{name: "non-numeric is rejected", env: "http", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("PORT", tt.env)
			got, err := resolvePort()
			if (err != nil) != tt.wantErr {
				t.Fatalf("resolvePort() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Errorf("resolvePort() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestResolveHost(t *testing.T) {
	tests := []struct {
		env     string
		want    string
		wantErr bool
	}{
		{env: "", want: "127.0.0.1"},
		{env: "0.0.0.0", want: "0.0.0.0"},
		{env: "::1", want: "::1"},
		{env: "localhost", want: "localhost"},
		{env: "example.com", wantErr: true},
		{env: "127.0.0.1:8080", wantErr: true},
	}
	for _, tt := range tests {
		t.Run("env="+tt.env, func(t *testing.T) {
			t.Setenv("VARDRGATE_HOST", tt.env)
			got, err := resolveHost()
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIsLoopback(t *testing.T) {
	for host, want := range map[string]bool{"127.0.0.1": true, "::1": true, "localhost": true, "0.0.0.0": false, "10.0.0.5": false} {
		if got := isLoopback(host); got != want {
			t.Errorf("isLoopback(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestResolveAllowPrivateTargets(t *testing.T) {
	tests := []struct {
		env     string
		want    bool
		wantErr bool
	}{
		{env: "", want: false},
		{env: "true", want: true},
		{env: "false", want: false},
		{env: "1", want: true},
		{env: "yes", wantErr: true},
	}
	for _, tt := range tests {
		t.Run("env="+tt.env, func(t *testing.T) {
			t.Setenv("ALLOW_PRIVATE_TARGETS", tt.env)
			got, err := resolveAllowPrivateTargets()
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResolveAPIKeys_MultiTenantTakesPrecedence(t *testing.T) {
	t.Setenv("VARDRGATE_API_KEYS", "tenant-a:key1, tenant-b:key2")
	t.Setenv("VARDRGATE_API_KEY", "single")

	keys, err := resolveAPIKeys()
	if err != nil {
		t.Fatal(err)
	}
	if keys["key1"] != "tenant-a" || keys["key2"] != "tenant-b" {
		t.Error("per-tenant keys mapped incorrectly")
	}
	if _, ok := keys["single"]; ok {
		t.Error("VARDRGATE_API_KEY must be ignored when VARDRGATE_API_KEYS is set")
	}
}

func TestResolveAPIKeys_SingleKeyMapsToDefaultTenant(t *testing.T) {
	t.Setenv("VARDRGATE_API_KEYS", "")
	t.Setenv("VARDRGATE_API_KEY", "solo")

	keys, err := resolveAPIKeys()
	if err != nil {
		t.Fatal(err)
	}
	if keys["solo"] != "default" {
		t.Error("single key must map to default tenant")
	}
}

func TestResolveAPIKeys_UnsetIsEmpty(t *testing.T) {
	t.Setenv("VARDRGATE_API_KEYS", "")
	t.Setenv("VARDRGATE_API_KEY", "")

	// An empty map is dev mode. It must be empty rather than partially
	// populated, because a stray entry would silently enforce auth.
	if keys, err := resolveAPIKeys(); err != nil || len(keys) != 0 {
		t.Error("expected no keys and no error")
	}
}

func TestResolveAPIKeys_RejectsMalformedPairs(t *testing.T) {
	t.Setenv("VARDRGATE_API_KEY", "fallback")
	for name, multi := range map[string]string{
		"missing separator": "broken",
		"missing tenant":    " :value",
		"missing key":       "tenant: ",
		"whitespace list":   "   ",
		"trailing comma":    "tenant:key,",
		"mixed list":        "a:first,broken,b:last",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("VARDRGATE_API_KEYS", multi)
			if keys, err := resolveAPIKeys(); err == nil || len(keys) != 0 {
				t.Error("malformed list must return an error and no usable keys")
			}
		})
	}
}

func TestServeAPIKeyStartup(t *testing.T) {
	if os.Args[len(os.Args)-1] == "--serve-test-child" {
		serve()
		return
	}

	// A directory cannot be opened as a SQLite database. Reaching this error
	// proves startup accepted the configuration without needing a live port.
	db := t.TempDir()
	const storeError = "failed to open job store"
	const malformed = "invalid VARDRGATE_API_KEYS"
	const required = "non-loopback bind requires"
	for _, tt := range []struct{ name, host, multi, single, want string }{
		{"malformed on loopback", "localhost", "secret-broken", "", malformed},
		{"mixed with fallback", "0.0.0.0", "a:secret-valid,secret-broken", "secret-single", malformed},
		{"default loopback", "", "", "", storeError},
		{"IPv4 loopback", "127.0.0.2", "", "", storeError},
		{"IPv6 loopback", "::1", "", "", storeError},
		{"localhost", "localhost", "", "", storeError},
		{"IPv4 wildcard", "0.0.0.0", "", "", required},
		{"IPv6 wildcard", "::", "", "", required},
		{"specific non-loopback", "192.0.2.1", "", "", required},
		{"single key", "0.0.0.0", "", "secret-single", storeError},
		{"multi-tenant keys", "::", "a:secret-first,b:secret-second", "secret-single", storeError},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("PORT", "")
			t.Setenv("ALLOW_PRIVATE_TARGETS", "")
			t.Setenv("VARDRGATE_HOST", tt.host)
			t.Setenv("VARDRGATE_API_KEYS", tt.multi)
			t.Setenv("VARDRGATE_API_KEY", tt.single)
			t.Setenv("VARDRGATE_DB", db)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestServeAPIKeyStartup$", "--", "--serve-test-child")
			out, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != exitUsage {
				t.Fatalf("expected configuration exit %d, got %v", exitUsage, err)
			}
			logs := string(out)
			if strings.Contains(logs, "secret-") {
				t.Fatal("startup logs exposed key material")
			}
			if !strings.Contains(logs, tt.want) || (tt.want != storeError && strings.Contains(logs, storeError)) {
				t.Fatalf("expected startup to stop at %q, got %s", tt.want, logs)
			}
		})
	}
}

func TestDistinctTenants(t *testing.T) {
	keys := map[string]string{"k1": "tenant-a", "k2": "tenant-a", "k3": "tenant-b"}
	if got := distinctTenants(keys); len(got) != 2 {
		t.Errorf("distinctTenants() = %v, want 2 entries", got)
	}
}
