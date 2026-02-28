package udig

import (
	"github.com/miekg/dns"
	"net"
	"time"
)

/////////////////////////////////////////
// PTR RESOLVER
/////////////////////////////////////////

// PTRResolver performs reverse DNS (PTR) lookups on discovered IPs.
type PTRResolver struct {
	Client *dns.Client
}

// NewPTRResolver creates a new PTRResolver with sensible defaults.
func NewPTRResolver(timeout time.Duration) *PTRResolver {
	return &PTRResolver{
		Client: &dns.Client{ReadTimeout: timeout},
	}
}

// ResolveIP performs a PTR lookup for the given IP (one resolution per hostname).
func (r *PTRResolver) ResolveIP(ip string) []Resolution {
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		LogErr("%s: IP %s is invalid.", TypePTR, ip)
		return nil
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
		return nil
	}

	var results []Resolution
	for _, rr := range msg.Answer {
		if rr.Header().Rrtype != dns.TypePTR {
			continue
		}
		hostname := CleanDomain((rr).(*dns.PTR).Ptr)
		if hostname != "" {
			results = append(results, &PTRResolution{
				ResolutionBase: &ResolutionBase{query: ip},
				Record:         PTRRecord{Hostname: hostname},
			})
		}
	}
	return results
}

// Type returns "PTR".
func (r *PTRResolver) Type() ResolutionType {
	return TypePTR
}
