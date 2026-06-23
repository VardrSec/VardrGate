package urlcheck

import (
	"context"
	"strings"
	"testing"
)

// All tests use literal IPs so no DNS resolution is required.

func TestCheck_SchemeValidation(t *testing.T) {
	cases := []struct {
		url     string
		wantErr string
	}{
		{"ftp://8.8.8.8/path", "scheme"},
		{"file:///etc/passwd", "scheme"},
		{"javascript://x", "scheme"},
		{"", "scheme"},
		{"://no-scheme", "scheme"},
	}
	for _, c := range cases {
		err := Check(context.Background(), c.url, false)
		if err == nil {
			t.Errorf("Check(%q): expected error containing %q, got nil", c.url, c.wantErr)
			continue
		}
		if !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("Check(%q): error %q does not contain %q", c.url, err.Error(), c.wantErr)
		}
	}
}

func TestCheck_AllowsHTTPAndHTTPS(t *testing.T) {
	for _, u := range []string{"http://8.8.8.8/", "https://8.8.8.8/"} {
		if err := Check(context.Background(), u, false); err != nil {
			t.Errorf("Check(%q): unexpected error: %v", u, err)
		}
	}
}

func TestCheck_BlocksLoopbackByDefault(t *testing.T) {
	loopbacks := []string{
		"http://127.0.0.1/",
		"http://127.1.2.3/",
		"http://[::1]/",
	}
	for _, u := range loopbacks {
		err := Check(context.Background(), u, false)
		if err == nil {
			t.Errorf("Check(%q): expected loopback to be blocked", u)
			continue
		}
		if !strings.Contains(err.Error(), "loopback") {
			t.Errorf("Check(%q): error %q does not mention loopback", u, err.Error())
		}
	}
}

func TestCheck_AllowsLoopbackWhenPrivateEnabled(t *testing.T) {
	for _, u := range []string{"http://127.0.0.1/", "http://[::1]/"} {
		if err := Check(context.Background(), u, true); err != nil {
			t.Errorf("Check(%q, allowPrivate=true): unexpected error: %v", u, err)
		}
	}
}

func TestCheck_BlocksPrivateByDefault(t *testing.T) {
	private := []string{
		"http://10.0.0.1/",
		"http://172.16.0.1/",
		"http://172.31.255.255/",
		"http://192.168.1.1/",
	}
	for _, u := range private {
		err := Check(context.Background(), u, false)
		if err == nil {
			t.Errorf("Check(%q): expected private address to be blocked", u)
		}
	}
}

func TestCheck_AllowsPrivateWhenEnabled(t *testing.T) {
	for _, u := range []string{"http://10.0.0.1/", "http://192.168.1.1/"} {
		if err := Check(context.Background(), u, true); err != nil {
			t.Errorf("Check(%q, allowPrivate=true): unexpected error: %v", u, err)
		}
	}
}

func TestCheck_BlocksLinkLocal(t *testing.T) {
	linkLocal := []string{
		"http://169.254.0.1/",
		"http://169.254.169.254/", // AWS metadata
		"http://[fe80::1]/",
	}
	for _, u := range linkLocal {
		err := Check(context.Background(), u, true) // even with allowPrivate
		if err == nil {
			t.Errorf("Check(%q): expected link-local to be blocked even with allowPrivate", u)
			continue
		}
		if !strings.Contains(err.Error(), "link-local") {
			t.Errorf("Check(%q): error %q does not mention link-local", u, err.Error())
		}
	}
}

func TestCheck_BlocksUnspecified(t *testing.T) {
	unspecified := []string{"http://0.0.0.0/", "http://[::]/"}
	for _, u := range unspecified {
		err := Check(context.Background(), u, true) // even with allowPrivate
		if err == nil {
			t.Errorf("Check(%q): expected unspecified to be blocked", u)
		}
	}
}

func TestCheck_BlocksMulticast(t *testing.T) {
	multicast := []string{"http://224.0.0.1/", "http://239.255.255.255/"}
	for _, u := range multicast {
		err := Check(context.Background(), u, true) // even with allowPrivate
		if err == nil {
			t.Errorf("Check(%q): expected multicast to be blocked", u)
		}
	}
}

func TestCheck_NoHost(t *testing.T) {
	err := Check(context.Background(), "http:///path", false)
	if err == nil || !strings.Contains(err.Error(), "no host") {
		t.Errorf("expected no-host error, got %v", err)
	}
}

func TestCheck_AllowsPublicIP(t *testing.T) {
	// 8.8.8.8 is a well-known public IP — not loopback, private, link-local, or multicast.
	if err := Check(context.Background(), "https://8.8.8.8/dns-query", false); err != nil {
		t.Errorf("unexpected error for public IP: %v", err)
	}
}
