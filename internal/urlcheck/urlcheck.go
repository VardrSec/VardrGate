package urlcheck

import (
	"context"
	"fmt"
	"net"
	"net/url"
)

// Check validates rawURL before a network request is made.
//
// Allowed schemes: http, https.
// Always blocked: unspecified (0.0.0.0/::), link-local (169.254.x.x/fe80::), multicast.
// Blocked by default, allowed when allowPrivate is true: loopback (127.x.x.x/::1)
// and private ranges (RFC-1918: 10.x, 172.16-31.x, 192.168.x; RFC-4193: fc00::/7).
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
	switch {
	case ip.IsUnspecified():
		return fmt.Errorf("unspecified address %s is not allowed", ip)
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return fmt.Errorf("link-local address %s is not allowed", ip)
	case ip.IsMulticast():
		return fmt.Errorf("multicast address %s is not allowed", ip)
	case ip.IsLoopback():
		if allowPrivate {
			return nil
		}
		return fmt.Errorf("loopback address %s is not allowed", ip)
	case ip.IsPrivate():
		if allowPrivate {
			return nil
		}
		return fmt.Errorf("private-network address %s is not allowed; set AllowPrivateTargets to enable", ip)
	}
	return nil
}
