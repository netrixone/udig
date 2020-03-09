package udig

import (
	"fmt"
	"github.com/miekg/dns"
	"net"
	"regexp"
	"strconv"
)

var (
	// For parsing ASN records, eg. "13335 | 104.28.16.0/20 | US | arin | 2014-03-28"
	asnRecordPattern = regexp.MustCompile(`([0-9]+) \| (.+) \| ([A-Z]+) \| (.+) \| (.+)`)
	// For parsing AS records e.g. "13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"
	asRecordPattern  = regexp.MustCompile(`([0-9]+) \| ([A-Z]+) \| (.+) \| (.+) \| (.+)`)
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
		for _, val := range txt {
			asnRecords = append(asnRecords, val)
		}
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

// NewBGPResolver creates a new BGPResolver with sensible defaults.
func NewBGPResolver() *BGPResolver {
	return &BGPResolver{
		Client:        &dns.Client{ReadTimeout: DefaultTimeout},
		cachedResults: map[string]*BGPResolution{},
	}
}

// ResolveIP resolves a given IP address to a list of corresponding AS records.
func (resolver *BGPResolver) ResolveIP(ip string) Resolution {
	resolution := resolver.cachedResults[ip]
	if resolution != nil {
		return resolution
	}
	resolution = &BGPResolution{ResolutionBase: &ResolutionBase{query: ip}}
	resolver.cachedResults[ip] = resolution

	results := lookupASN(ip, resolver.Client)
	for _, result := range results {
		asRecord := parseASNRecord(result)
		if asRecord == nil {
			continue
		}

		asRecord.Name = parseASName(lookupAS(asRecord.ASN, resolver.Client))
		resolution.Records = append(resolution.Records, *asRecord)
	}

	return resolution
}

// Type returns "BGP".
func (resolver *BGPResolver) Type() ResolutionType {
	return TypeBGP
}

/////////////////////////////////////////
// BGP RESOLUTION
/////////////////////////////////////////

// Type returns "BGP".
func (res *BGPResolution) Type() ResolutionType {
	return TypeBGP
}

/////////////////////////////////////////
// AS RECORD
/////////////////////////////////////////

func (record *ASRecord) String() string {
	return fmt.Sprintf(
		"ASN: %d, AS: %s, prefix: %s, registry: %s, allocated: %s",
		record.ASN, record.Name, record.BGPPrefix, record.Registry, record.Allocated,
	)
}
