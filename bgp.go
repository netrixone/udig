package udig

import (
	"fmt"
)

/////////////////////////////////////////
// BGP RESOLUTION
/////////////////////////////////////////

// BGPResolution is a single BGP/AS result (denormalized: one AS record per resolution).
type BGPResolution struct {
	*ResolutionBase
	Record ASRecord
}

// Type returns "BGP".
func (r *BGPResolution) Type() ResolutionType {
	return TypeBGP
}

/////////////////////////////////////////
// AS RECORD
/////////////////////////////////////////

// ASRecord contains information about an Autonomous System (AS).
type ASRecord struct {
	Name      string // AS name (e.g. CLOUDFLARENET, US)
	ASN       uint32 // Autonomous System Number
	BGPPrefix string // announced IP prefix (e.g. 104.28.16.0/20)
	Registry  string // Regional Internet Registry (e.g. arin, ripe)
	Allocated string // allocation date (YYYY-MM-DD)
}

func (r ASRecord) String() string {
	return fmt.Sprintf(
		"ASN: %d, AS: %s, prefix: %s, registry: %s, allocated: %s",
		r.ASN, r.Name, r.BGPPrefix, r.Registry, r.Allocated,
	)
}
