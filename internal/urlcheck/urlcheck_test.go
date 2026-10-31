package urlcheck

import (
	"context"
	"net"
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

// TestCheck_AllowsHostname verifies that hostname-based URLs pass the pre-flight
// check without DNS resolution. IP validation for hostnames happens at dial time
// via CheckIP in the transport's DialContext to prevent DNS rebinding.
func TestCheck_AllowsHostname(t *testing.T) {
	hosts := []string{
		"https://example.com/path",
		"http://api.internal.example.com/v1/resource",
	}
	for _, u := range hosts {
		if err := Check(context.Background(), u, false); err != nil {
			t.Errorf("Check(%q): hostname should pass pre-flight, got: %v", u, err)
		}
	}
}

func TestCheckIP_BlocksAlways(t *testing.T) {
	// These are blocked regardless of allowPrivate.
	cases := []struct {
		ip      string
		wantErr string
	}{
		{"0.0.0.0", "unspecified"},
		{"::", "unspecified"},
		{"169.254.1.1", "link-local"},
		// 239.0.0.1 is administratively-scoped multicast (not link-local),
		// so IsMulticast fires rather than IsLinkLocalMulticast.
		{"239.0.0.1", "multicast"},
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("bad test IP: %s", c.ip)
		}
		err := CheckIP(ip, true) // even with allowPrivate
		if err == nil {
			t.Errorf("CheckIP(%s, allowPrivate=true): expected error containing %q, got nil", c.ip, c.wantErr)
			continue
		}
		if !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("CheckIP(%s): error %q does not contain %q", c.ip, err.Error(), c.wantErr)
		}
	}
}

func TestCheckIP_NonPublicRangesFollowThePrivateOptIn(t *testing.T) {
	for _, ip := range []string{
		"100.64.0.1",      // shared address space (carrier-grade NAT, Tailscale)
		"100.127.255.254", // top of 100.64.0.0/10
		"198.18.0.1",      // benchmarking
		"198.19.255.254",
	} {
		if err := CheckIP(net.ParseIP(ip), false); err == nil || !strings.Contains(err.Error(), "private-network") {
			t.Errorf("CheckIP(%s, false) = %v, want a private-network refusal", ip, err)
		}
		if err := CheckIP(net.ParseIP(ip), true); err != nil {
			t.Errorf("CheckIP(%s, true) = %v, want it allowed by the explicit opt-in", ip, err)
		}
	}
}

func TestCheckIP_AlwaysBlocksThisNetworkAndMetadata(t *testing.T) {
	for _, c := range []struct{ ip, wantErr string }{
		{"0.1.2.3", "unspecified"},
		{"0.255.255.255", "unspecified"},
		{"100.100.100.200", "metadata"}, // Alibaba Cloud metadata, inside 100.64.0.0/10
	} {
		for _, allowPrivate := range []bool{false, true} {
			err := CheckIP(net.ParseIP(c.ip), allowPrivate)
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("CheckIP(%s, %v) = %v, want error containing %q", c.ip, allowPrivate, err, c.wantErr)
			}
		}
	}
}

func TestCheckIP_JudgesTheIPv4InsideNAT64And6to4(t *testing.T) {
	for _, c := range []struct {
		ip             string
		blockedDefault bool
		blockedAlways  bool
	}{
		{"64:ff9b::7f00:1", true, false},       // NAT64 of 127.0.0.1
		{"64:ff9b::a00:1", true, false},        // NAT64 of 10.0.0.1
		{"64:ff9b::a9fe:a9fe", true, true},     // NAT64 of 169.254.169.254
		{"2002:7f00:1::1", true, false},        // 6to4 of 127.0.0.1
		{"2002:a9fe:a9fe::1", true, true},      // 6to4 of 169.254.169.254
		{"64:ff9b::808:808", false, false},     // NAT64 of public 8.8.8.8
		{"2001:4860:4860::8888", false, false}, // ordinary public IPv6
	} {
		err := CheckIP(net.ParseIP(c.ip), false)
		if (err != nil) != c.blockedDefault {
			t.Errorf("CheckIP(%s, false) = %v, want blocked=%v", c.ip, err, c.blockedDefault)
		}
		err = CheckIP(net.ParseIP(c.ip), true)
		if (err != nil) != c.blockedAlways {
			t.Errorf("CheckIP(%s, true) = %v, want blocked=%v", c.ip, err, c.blockedAlways)
		}
	}
}

func TestCheck_LiteralNonPublicHostsUseTheSameRules(t *testing.T) {
	if err := Check(context.Background(), "http://100.64.1.1/", false); err == nil {
		t.Error("expected a shared-address-space literal to be refused by default")
	}
	if err := Check(context.Background(), "http://[64:ff9b::7f00:1]/", true); err != nil {
		t.Errorf("NAT64 loopback with the private opt-in: %v", err)
	}
}
