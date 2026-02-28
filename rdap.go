package udig

import (
	"strings"
)

////////////////////////////////////////////
// RDAP Resolution
////////////////////////////////////////////

// RDAPResolution is the result of an RDAP IP lookup.
type RDAPResolution struct {
	*ResolutionBase
	Record RDAPRecord
}

// Type returns TypeRDAP.
func (r *RDAPResolution) Type() ResolutionType {
	return TypeRDAP
}

////////////////////////////////////////////
// RDAP Record
////////////////////////////////////////////

// RDAPRecord holds the main fields from an RDAP "ip network" response (RFC 9083).
type RDAPRecord struct {
	Handle       string // registry handle (e.g. NET-104-16-0-0-1)
	Name         string // network name (e.g. CLOUDFLARENET)
	StartAddress string // first IP in the allocated range
	EndAddress   string // last IP in the allocated range
	NetworkType  string // e.g. DIRECT ALLOCATION
	OrgName      string // registrant org from entities
	AbuseEmail   string // abuse contact email from entities
}

// String formats the RDAP record for CLI output (handle, name, range, type, org, abuse).
func (r RDAPRecord) String() string {
	parts := []string{}
	if r.Handle != "" {
		parts = append(parts, "handle: "+r.Handle)
	}
	if r.Name != "" {
		parts = append(parts, "name: "+r.Name)
	}
	if r.StartAddress != "" && r.EndAddress != "" {
		parts = append(parts, r.StartAddress+" - "+r.EndAddress)
	} else if r.StartAddress != "" {
		parts = append(parts, "start: "+r.StartAddress)
	}
	if r.NetworkType != "" {
		parts = append(parts, "type: "+r.NetworkType)
	}
	if r.OrgName != "" {
		parts = append(parts, "org: "+r.OrgName)
	}
	if r.AbuseEmail != "" {
		parts = append(parts, "abuse: "+r.AbuseEmail)
	}
	return strings.Join(parts, ", ")
}
