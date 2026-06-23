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
func Check(ctx context.Context, rawURL string, allowPrivate bool) error {
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

	// Literal IP — validate without DNS resolution.
	if ip := net.ParseIP(host); ip != nil {
		return checkIP(ip, allowPrivate)
	}

	// Hostname — resolve and check every returned address.
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("cannot resolve host %q: %w", host, err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("host %q resolved to no addresses", host)
	}
	for _, a := range addrs {
		if err := checkIP(a.IP, allowPrivate); err != nil {
			return fmt.Errorf("host %q: %w", host, err)
		}
	}
	return nil
}

func checkIP(ip net.IP, allowPrivate bool) error {
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
