package udig

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var defaultDNSBLZones = []string{
	"b.barracudacentral.org",
	"dnsbl-2.uceprotect.net",
	"dnsbl-3.uceprotect.net",
	"dnsbl.dronebl.org",
}

/////////////////////////////////////////
// DNSBL RESOLVER
/////////////////////////////////////////

// DNSBLResolver checks IPs against DNS-based blocklists.
type DNSBLResolver struct {
	Client *dns.Client
	Zones  []string
}

// NewDNSBLResolver creates a new DNSBLResolver with sensible defaults.
func NewDNSBLResolver(timeout time.Duration) *DNSBLResolver {
	return &DNSBLResolver{
		Client: &dns.Client{ReadTimeout: timeout},
		Zones:  defaultDNSBLZones,
	}
}

// ResolveIP checks an IP against all configured DNSBL zones in parallel.
// Returns one Resolution per zone that lists the IP.
func (r *DNSBLResolver) ResolveIP(ip string) []Resolution {
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		LogErr("%s: IP %s is invalid.", TypeDNSBL, ip)
		return nil
	}

	var reverseIP string
	if ipAddr.To4() != nil {
		reverseIP = reverseIPv4(ipAddr)
	} else {
		reverseIP = reverseIPv6(ipAddr)
	}

	var mux sync.Mutex
	var wg sync.WaitGroup
	var results []Resolution
	wg.Add(len(r.Zones))

	for _, zone := range r.Zones {
		go func(zone string) {
			defer wg.Done()

			query := fmt.Sprintf("%s.%s", reverseIP, zone)
			msg, err := queryOneCallback(query, dns.TypeA, localNameServer, r.Client)
			if err != nil {
				if err.Error() != "NXDOMAIN" {
					LogErr("%s: DNSBL query %s failed: %s", TypeDNSBL, query, err.Error())
				}
				return
			}

			for _, rr := range msg.Answer {
				if rr.Header().Rrtype != dns.TypeA {
					continue
				}

				returnCode := rr.(*dns.A).A.String()
				if isDNSBLMetaCode(returnCode) {
					LogWarn("%s: %s returned meta code %s for %s — query limit exceeded or service error", TypeDNSBL, zone, returnCode, ip)
					continue
				}

				mux.Lock()
				results = append(results, &DNSBLResolution{
					ResolutionBase: &ResolutionBase{query: ip},
					Record: DNSBLRecord{
						Zone:       zone,
						ReturnCode: returnCode,
						Listed:     true,
						Meaning:    decodeDNSBLMeaning(zone, returnCode),
					},
				})
				mux.Unlock()
			}
		}(zone)
	}

	wg.Wait()
	return results
}

// Type returns "DNSBL".
func (r *DNSBLResolver) Type() ResolutionType {
	return TypeDNSBL
}

// isDNSBLMetaCode reports whether a DNSBL return code is a service meta/error
// response rather than a real listing. DNSBL services use the 127.255.255.0/24
// range for operational signals (must NOT be interpreted as reputation data).
func isDNSBLMetaCode(returnCode string) bool {
	ip := net.ParseIP(returnCode)
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	return ip4 != nil && ip4[1] == 255 && ip4[2] == 255
}

// decodeDNSBLMeaning decodes the meaning of a DNSBL return code for known zones.
func decodeDNSBLMeaning(zone, returnCode string) string {
	switch zone {
	case "b.barracudacentral.org":
		if returnCode == "127.0.0.2" {
			return "listed"
		}
	case "dnsbl-2.uceprotect.net":
		if returnCode == "127.0.0.2" {
			return "spam subnet"
		}
	case "dnsbl-3.uceprotect.net":
		if returnCode == "127.0.0.2" {
			return "spam ASN"
		}
	case "dnsbl.dronebl.org":
		switch returnCode {
		case "127.0.0.3":
			return "IRC drone"
		case "127.0.0.5":
			return "bottler"
		case "127.0.0.6":
			return "unknown spambot"
		case "127.0.0.7":
			return "DDoS drone"
		case "127.0.0.8":
			return "SOCKS proxy"
		case "127.0.0.9":
			return "HTTP proxy"
		case "127.0.0.10":
			return "proxy chain"
		case "127.0.0.11":
			return "web page proxy"
		case "127.0.0.13":
			return "brute force"
		case "127.0.0.14":
			return "open Wingate proxy"
		case "127.0.0.15":
			return "compromised router"
		case "127.0.0.16":
			return "autorooting worm"
		case "127.0.0.17":
			return "botnet"
		case "127.0.0.18":
			return "open resolver"
		}
	}
	return returnCode
}
