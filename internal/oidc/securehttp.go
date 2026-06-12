package oidc

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"
)

// SecureHTTPClient returns an *http.Client hardened against SSRF. Its dialer
// re-resolves the target host and rejects any connection whose resolved IP is
// loopback, private (RFC1918 / ULA), link-local, unspecified, or a
// cloud-metadata address. The IP is checked at dial time (after DNS
// resolution) so a hostname that resolves to a blocked address — including via
// DNS-rebinding — is refused.
//
// allowLoopback relaxes the loopback ban only. It is set when the operator has
// explicitly configured a localhost issuer (mirroring validateIssuerURL, which
// permits http://localhost). Private/link-local/metadata ranges stay blocked
// regardless.
func SecureHTTPClient(allowLoopback bool) *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	control := func(network, address string, allow bool) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			host = address
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return fmt.Errorf("blocked: unresolved address %q", address)
		}
		if isBlockedIP(ip, allow) {
			return fmt.Errorf("blocked: address %s resolves to a disallowed range", ip)
		}
		return nil
	}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dr := *dialer
			dr.Control = func(network, address string, _ syscall.RawConn) error {
				return control(network, address, allowLoopback)
			}
			return dr.DialContext(ctx, network, addr)
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &http.Client{Transport: transport, Timeout: 30 * time.Second}
}

// metadataIP is the cloud instance-metadata link-local address (AWS/GCP/Azure
// and others). It is already covered by the link-local check, but is called
// out explicitly for clarity and defense in depth.
var metadataIP = net.IPv4(169, 254, 169, 254)

// isBlockedIP reports whether ip falls in a range that must not be reachable
// from server-side fetches. When allowLoopback is true, loopback addresses are
// permitted (explicit localhost issuer); everything else stays blocked.
func isBlockedIP(ip net.IP, allowLoopback bool) bool {
	if ip.IsUnspecified() {
		return true
	}
	if ip.IsLoopback() {
		return !allowLoopback
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	if ip.IsPrivate() {
		return true
	}
	if ip.Equal(metadataIP) {
		return true
	}
	return false
}
