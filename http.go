package udig

import (
	"fmt"
)

/////////////////////////////////////////
// HTTP RESOLUTION
/////////////////////////////////////////

// HTTPResolution is a single HTTP result.
type HTTPResolution struct {
	*ResolutionBase
	Record HTTPRecord
}

// Type returns "HTTP".
func (r *HTTPResolution) Type() ResolutionType {
	return TypeHTTP
}

// Domains returns domains discovered in this single HTTP result.
func (r *HTTPResolution) Domains() (domains []string) {
	return DissectDomainsFromString(r.Record.Value)
}

/////////////////////////////////////////
// HTTP RECORD
/////////////////////////////////////////

// HTTPRecord is a key/value pair (e.g. header name + value, or "robots.txt" + domain).
type HTTPRecord struct {
	Key   string // header name, "security.txt", or "robots.txt"
	Value string // header value or discovered domain
}

func (h HTTPRecord) String() string {
	return fmt.Sprintf("%s: %s", h.Key, h.Value)
}
