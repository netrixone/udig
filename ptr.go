package udig

import (
	"fmt"
)

/////////////////////////////////////////
// PTR RESOLUTION
/////////////////////////////////////////

// PTRResolution is a single PTR result (denormalized: one hostname per resolution).
type PTRResolution struct {
	*ResolutionBase
	Record PTRRecord
}

// Type returns "PTR".
func (r *PTRResolution) Type() ResolutionType {
	return TypePTR
}

// Domains returns the hostname discovered via reverse DNS.
func (r *PTRResolution) Domains() []string {
	if r.Record.Hostname != "" {
		return []string{r.Record.Hostname}
	}
	return nil
}

func (r *PTRResolution) String() string {
	return fmt.Sprintf("PTR -> %s", r.Record.Hostname)
}

// PTRRecord holds a single reverse DNS hostname.
type PTRRecord struct {
	Hostname string
}

func (r PTRRecord) String() string {
	return r.Hostname
}
