package udig

import (
	"fmt"
)

/////////////////////////////////////////
// GEO RESOLUTION
/////////////////////////////////////////

// GeoResolution is a GeoIP resolution of a given IP yielding geographical records.
type GeoResolution struct {
	*ResolutionBase
	Record GeoRecord
}

// Type returns "GEO".
func (r *GeoResolution) Type() ResolutionType {
	return TypeGEO
}

/////////////////////////////////////////
// GEO RECORD
/////////////////////////////////////////

// GeoRecord contains information about a geographical location.
type GeoRecord struct {
	CountryCode string // ISO 3166-1 alpha-2 country code (e.g. US, CZ)
}

func (r *GeoRecord) String() string {
	return fmt.Sprintf("country code: %s", r.CountryCode)
}
