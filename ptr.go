package udig

import (
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

/////////////////////////////////////////
// PTR RESOLVER
/////////////////////////////////////////

// NewPTRResolver creates a new PTRResolver with sensible defaults.
func NewPTRResolver(timeout time.Duration) *PTRResolver {
	return &PTRResolver{
		Client: &dns.Client{ReadTimeout: timeout},
	}
}

// ResolveIP performs a PTR lookup for the given IP.
func (r *PTRResolver) ResolveIP(ip string) Resolution {
	resolution := &PTRResolution{
		ResolutionBase: &ResolutionBase{query: ip},
	}

	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		LogErr("%s: IP %s is invalid.", TypePTR, ip)
		return resolution
	}

	var ptrDomain string
	if ipAddr.To4() != nil {
		ptrDomain = reverseIPv4(ipAddr.To16()) + ".in-addr.arpa"
	} else {
		ptrDomain = reverseIPv6(ipAddr) + ".ip6.arpa"
	}

	msg, err := queryOneCallback(ptrDomain, dns.TypePTR, localNameServer, r.Client)
	if err != nil {
		if err.Error() == "NXDOMAIN" {
			LogDebug("%s: No PTR record for %s.", TypePTR, ip)
		} else {
			LogErr("%s: PTR query %s failed: %s", TypePTR, ptrDomain, err.Error())
		}
		return resolution
	}

	for _, rr := range msg.Answer {
		if rr.Header().Rrtype != dns.TypePTR {
			continue
		}
		hostname := CleanDomain((rr).(*dns.PTR).Ptr)
		if hostname != "" {
			resolution.Hostnames = append(resolution.Hostnames, hostname)
		}
	}

	return resolution
}

// Type returns "PTR".
func (r *PTRResolver) Type() ResolutionType {
	return TypePTR
}

/////////////////////////////////////////
// PTR RESOLUTION
/////////////////////////////////////////

// Type returns "PTR".
func (r *PTRResolution) Type() ResolutionType {
	return TypePTR
}

// Domains returns hostnames discovered via reverse DNS (informational only).
func (r *PTRResolution) Domains() []string {
	return r.Hostnames
}

func (r *PTRResolution) String() string {
	return fmt.Sprintf("PTR -> %v", r.Hostnames)
}
