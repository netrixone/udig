package udig

import (
	"strings"
)

/////////////////////////////////////////
// DMARC RESOLUTION
/////////////////////////////////////////

// DMARCResolution is a parsed DMARC policy result.
type DMARCResolution struct {
	*ResolutionBase
	Record DMARCRecord
}

// Type returns "DMARC".
func (r *DMARCResolution) Type() ResolutionType {
	return TypeDMARC
}

// Domains returns domains extracted from DMARC reporting URIs.
func (r *DMARCResolution) Domains() (domains []string) {
	for _, uri := range r.Record.DMARCRua {
		domains = append(domains, DissectDomainsFromString(uri)...)
	}
	for _, uri := range r.Record.DMARCRuf {
		domains = append(domains, DissectDomainsFromString(uri)...)
	}
	return domains
}

/////////////////////////////////////////
// DMARC RECORD
/////////////////////////////////////////

// DMARCRecord holds parsed DMARC fields from a _dmarc TXT record.
type DMARCRecord struct {
	DMARCPolicy string   // p= value from _dmarc TXT
	DMARCRua    []string // rua= reporting URIs
	DMARCRuf    []string // ruf= reporting URIs
}

func (r *DMARCRecord) String() string {
	parts := []string{"p=" + r.DMARCPolicy}
	if len(r.DMARCRua) > 0 {
		parts = append(parts, "rua="+strings.Join(r.DMARCRua, ","))
	}
	if len(r.DMARCRuf) > 0 {
		parts = append(parts, "ruf="+strings.Join(r.DMARCRuf, ","))
	}
	return strings.Join(parts, "; ")
}
