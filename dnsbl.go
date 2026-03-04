package udig

import "fmt"

/////////////////////////////////////////
// DNSBL RESOLUTION
/////////////////////////////////////////

// DNSBLResolution holds a blocklist check result for a single DNSBL zone.
type DNSBLResolution struct {
	*ResolutionBase
	Record DNSBLRecord
}

// Type returns "DNSBL".
func (r *DNSBLResolution) Type() ResolutionType {
	return TypeDNSBL
}

/////////////////////////////////////////
// DNSBL RECORD
/////////////////////////////////////////

// DNSBLRecord contains the result of a single DNSBL zone check.
type DNSBLRecord struct {
	Zone       string
	ReturnCode string
	Listed     bool
	Meaning    string
}

// String formats a DNSBL record result.
func (r DNSBLRecord) String() string {
	return fmt.Sprintf("%s: %s (%s)", r.Zone, r.ReturnCode, r.Meaning)
}
