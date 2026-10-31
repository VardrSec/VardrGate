package urlcheck

import (
	"context"
	"fmt"
	"net"
	"net/url"
)

// Address ranges net.IP's classifiers do not cover.
var (
	// "This network" (RFC 1122). 0.0.0.0 itself is the unspecified address;
	// connecting to any of these can reach the local host.
	thisNetwork = mustCIDR("0.0.0.0/8")

	// Not public, but outside RFC 1918: shared address space (RFC 6598, also used
	// by carrier-grade NAT and overlay networks such as Tailscale) and the
	// benchmarking range (RFC 2544). Treated like private ranges.
	nonPublic = []*net.IPNet{mustCIDR("100.64.0.0/10"), mustCIDR("198.18.0.0/15")}

	// Cloud instance-metadata endpoints outside link-local, which net.IP does not
	// already classify. Always blocked, like the link-local metadata address.
	metadata = []net.IP{
		net.ParseIP("100.100.100.200"), // Alibaba Cloud
	}

	// IPv6 forms that carry an IPv4 destination: NAT64 (RFC 6052) and 6to4 (RFC 3056).
	nat64     = mustCIDR("64:ff9b::/96")
	sixToFour = mustCIDR("2002::/16")
)

func mustCIDR(cidr string) *net.IPNet {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	return network
}

// Check validates rawURL before a network request is made.
//
// Allowed schemes: http, https.
// Always blocked: unspecified and 0.0.0.0/8, link-local (169.254.x.x/fe80::),
// cloud metadata addresses, multicast.
// Blocked by default, allowed when allowPrivate is true: loopback (127.x.x.x/::1),
// private ranges (RFC-1918: 10.x, 172.16-31.x, 192.168.x; RFC-4193: fc00::/7),
// shared address space (100.64.0.0/10) and benchmarking (198.18.0.0/15).
// NAT64 and 6to4 addresses are judged by the IPv4 address they embed as well.
//
// Literal IP hosts are validated immediately. Hostname targets are not resolved
// here to avoid a time-of-check/time-of-use race; callers must validate the
// resolved address at dial time using CheckIP inside their DialContext.
func Check(_ context.Context, rawURL string, allowPrivate bool) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid url: %w", err)
	}
	switch u.Scheme {
	case "http", "https":
	default:
		return fmt.Errorf("scheme %q not allowed; use http or https", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("url has no host")
	}

	// Literal IPs are validated immediately.
	// Hostname-based targets are validated at dial time via CheckIP in DialContext.
	if ip := net.ParseIP(host); ip != nil {
		return CheckIP(ip, allowPrivate)
	}
	return nil
}

// CheckIP validates a single resolved IP address against the blocking policy.
// It is exported so that transport DialContext implementations can reuse the
// same rules when validating addresses at connect time.
func CheckIP(ip net.IP, allowPrivate bool) error {
	if embedded := embeddedIPv4(ip); embedded != nil {
		if err := CheckIP(embedded, allowPrivate); err != nil {
			return fmt.Errorf("%s carries %s: %w", ip, embedded, err)
		}
	}
	switch {
	case ip.IsUnspecified(), thisNetwork.Contains(ip):
		return fmt.Errorf("unspecified address %s is not allowed", ip)
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return fmt.Errorf("link-local address %s is not allowed", ip)
	case isMetadata(ip):
		return fmt.Errorf("cloud metadata address %s is not allowed", ip)
	case ip.IsMulticast():
		return fmt.Errorf("multicast address %s is not allowed", ip)
	case ip.IsLoopback():
		if allowPrivate {
			return nil
		}
		return fmt.Errorf("loopback address %s is not allowed", ip)
	case ip.IsPrivate(), inAny(ip, nonPublic):
		if allowPrivate {
			return nil
		}
		return fmt.Errorf("private-network address %s is not allowed; set AllowPrivateTargets to enable", ip)
	}
	return nil
}

// embeddedIPv4 returns the IPv4 destination a NAT64 or 6to4 address carries, or nil.
func embeddedIPv4(ip net.IP) net.IP {
	if ip.To4() != nil {
		return nil
	}
	ip16 := ip.To16()
	switch {
	case ip16 == nil:
		return nil
	case nat64.Contains(ip16):
		return net.IPv4(ip16[12], ip16[13], ip16[14], ip16[15])
	case sixToFour.Contains(ip16):
		return net.IPv4(ip16[2], ip16[3], ip16[4], ip16[5])
	}
	return nil
}

func isMetadata(ip net.IP) bool {
	for _, m := range metadata {
		if m.Equal(ip) {
			return true
		}
	}
	return false
}

func inAny(ip net.IP, networks []*net.IPNet) bool {
	for _, n := range networks {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
