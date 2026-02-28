package udig

import (
	"fmt"
	"github.com/miekg/dns"
	"net"
	"regexp"
	"strconv"
	"time"
)

var (
	// For parsing ASN records, eg. "13335 | 104.28.16.0/20 | US | arin | 2014-03-28"
	asnRecordPattern = regexp.MustCompile(`([0-9]+) \| (.+) \| ([A-Z]+) \| (.+) \| (.+)`)
	// For parsing AS records e.g. "13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"
	asRecordPattern = regexp.MustCompile(`([0-9]+) \| ([A-Z]+) \| (.+) \| (.+) \| (.+)`)
)

// lookupASN uses Team Cymru's IP->ASN lookup via DNS, returns matching ASN records.
func lookupASN(ip string, client *dns.Client) (asnRecords []string) {
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		LogErr("%s: IP %s is invalid.", TypeBGP, ip)
		return asnRecords
	}

	var query string
	if ipAddr.To4() != nil {
		query = fmt.Sprintf("%s.origin.asn.cymru.com", reverseIPv4(ipAddr))
	} else {
		query = fmt.Sprintf("%s.origin6.asn.cymru.com", reverseIPv6(ipAddr))
	}

	msg, err := queryOneCallback(query, dns.TypeTXT, localNameServer, client)
	if err != nil {
		if err.Error() == "NXDOMAIN" {
			LogDebug("%s: No ASN record found for IP %s (query %s).", TypeBGP, ip, query)
		} else {
			LogErr("%s: Could not query BGP endpoint (TXT %s). The cause was: %s", TypeBGP, query, err.Error())
		}
		return asnRecords
	}

	for _, record := range msg.Answer {
		if record.Header().Rrtype != dns.TypeTXT {
			LogDebug("%s: TXT query %s returned non-TXT record %s. Skipping.", TypeBGP, query, dns.TypeToString[record.Header().Rrtype])
			continue
		}

		txt := (record).(*dns.TXT).Txt
		asnRecords = append(asnRecords, txt...)
	}

	return asnRecords
}

// lookupAS uses Team Cymru's ASN->AS lookup via DNS, returns a matching ASN record or "".
func lookupAS(asn uint32, client *dns.Client) string {
	query := fmt.Sprintf("AS%d.asn.cymru.com", asn)

	msg, err := queryOneCallback(query, dns.TypeTXT, localNameServer, client)
	if err != nil {
		if err.Error() == "NXDOMAIN" {
			LogDebug("%s: No AS record found for AS%d (query %s).", TypeBGP, asn, query)
		} else {
			LogErr("%s: Could not query BGP endpoint (TXT %s). The cause was: %s", TypeBGP, query, err.Error())
		}
		return ""
	}

	var asRecord string
	for _, record := range msg.Answer {
		if record.Header().Rrtype != dns.TypeTXT {
			LogDebug("%s: TXT query %s returned non-TXT record %s. Skipping.", TypeBGP, query, dns.TypeToString[record.Header().Rrtype])
			continue
		}

		txt := (record).(*dns.TXT).Txt
		for _, val := range txt {
			asRecord = val
			break
		}
		break
	}

	return asRecord
}

// parseASNRecord parses a given ASN record string to ASRecord structure.
// The string is expected to match following form:
// "13335 | 104.28.16.0/20 | US | arin | 2014-03-28"
func parseASNRecord(asnRecord string) *ASRecord {
	groups := asnRecordPattern.FindStringSubmatch(asnRecord)
	if groups == nil {
		LogErr("%s: Invalid ASN record '%s'.", TypeBGP, asnRecord)
		return nil
	}

	asn, err := strconv.ParseInt(groups[1], 10, 32)
	if err != nil {
		LogErr("%s: Invalid ASN '%s'.", TypeBGP, groups[1])
		return nil
	}

	return &ASRecord{
		ASN:       uint32(asn),
		BGPPrefix: groups[2],
		Registry:  groups[4],
		Allocated: groups[5],
	}
}

// parseASNRecord parses a given AS record string and returns AS name.
// The string is expected to match following form:
// "13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"
func parseASName(asRecord string) string {
	groups := asRecordPattern.FindStringSubmatch(asRecord)
	if groups == nil {
		LogErr("%s: Invalid AS record '%s'.", TypeBGP, asRecord)
		return ""
	}

	return groups[5]
}

/////////////////////////////////////////
// BGP RESOLVER
/////////////////////////////////////////

// BGPResolver is a Resolver which is able to resolve an IP
// to AS name and ASN.
//
// Internally this resolver is leveraging a DNS interface of
// IP-to-ASN lookup service by Team Cymru.
type BGPResolver struct {
	Client        *dns.Client
	cachedResults map[string][]Resolution
}

// NewBGPResolver creates a new BGPResolver with sensible defaults.
func NewBGPResolver(timeout time.Duration) *BGPResolver {
	return &BGPResolver{
		Client:        &dns.Client{ReadTimeout: timeout},
		cachedResults: map[string][]Resolution{},
	}
}

// ResolveIP resolves a given IP address to AS records (one resolution per AS record).
func (r *BGPResolver) ResolveIP(ip string) []Resolution {
	if cached, ok := r.cachedResults[ip]; ok {
		return cached
	}

	asnResults := lookupASN(ip, r.Client)

	var results []Resolution
	for _, result := range asnResults {
		asRecord := parseASNRecord(result)
		if asRecord == nil {
			continue
		}

		asRecord.Name = parseASName(lookupAS(asRecord.ASN, r.Client))
		results = append(results, &BGPResolution{
			ResolutionBase: &ResolutionBase{query: ip},
			Record:         *asRecord,
		})
	}

	r.cachedResults[ip] = results
	return results
}

// Type returns "BGP".
func (r *BGPResolver) Type() ResolutionType {
	return TypeBGP
}
