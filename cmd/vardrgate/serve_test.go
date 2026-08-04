package main

import (
	"testing"
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

	keys := resolveAPIKeys()
	if keys["key1"] != "tenant-a" || keys["key2"] != "tenant-b" {
		t.Errorf("per-tenant keys not parsed: %v", keys)
	}
	if _, ok := keys["single"]; ok {
		t.Error("VARDRGATE_API_KEY must be ignored when VARDRGATE_API_KEYS is set")
	}
}

func TestResolveAPIKeys_SingleKeyMapsToDefaultTenant(t *testing.T) {
	t.Setenv("VARDRGATE_API_KEYS", "")
	t.Setenv("VARDRGATE_API_KEY", "solo")

	keys := resolveAPIKeys()
	if keys["solo"] != "default" {
		t.Errorf("single key = %v, want tenant %q", keys, "default")
	}
}

func TestResolveAPIKeys_UnsetIsEmpty(t *testing.T) {
	t.Setenv("VARDRGATE_API_KEYS", "")
	t.Setenv("VARDRGATE_API_KEY", "")

	// An empty map is dev mode. It must be empty rather than partially
	// populated, because a stray entry would silently enforce auth.
	if keys := resolveAPIKeys(); len(keys) != 0 {
		t.Errorf("expected no keys, got %v", keys)
	}
}

func TestResolveAPIKeys_SkipsMalformedPairs(t *testing.T) {
	t.Setenv("VARDRGATE_API_KEYS", "tenant-a:key1,garbage,:novalue,notenant:,tenant-b:key2")
	t.Setenv("VARDRGATE_API_KEY", "")

	keys := resolveAPIKeys()
	if len(keys) != 2 {
		t.Fatalf("expected only the two well-formed pairs, got %v", keys)
	}
	if keys["key1"] != "tenant-a" || keys["key2"] != "tenant-b" {
		t.Errorf("unexpected keys: %v", keys)
	}
}

func TestDistinctTenants(t *testing.T) {
	keys := map[string]string{"k1": "tenant-a", "k2": "tenant-a", "k3": "tenant-b"}
	if got := distinctTenants(keys); len(got) != 2 {
		t.Errorf("distinctTenants() = %v, want 2 entries", got)
	}
}
