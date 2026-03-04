package udig

import (
	"fmt"
	"strings"
)

/////////////////////////////////////////
// TOR RESOLUTION
/////////////////////////////////////////

// TorResolution holds the Tor node check result for an IP.
type TorResolution struct {
	*ResolutionBase
	Record TorRecord
}

// Type returns "TOR".
func (r *TorResolution) Type() ResolutionType {
	return TypeTor
}

/////////////////////////////////////////
// TOR RECORD
/////////////////////////////////////////

// TorRecord contains the result of a Tor node lookup via the Onionoo API.
type TorRecord struct {
	Nickname    string
	Fingerprint string
	Flags       []string
}

// IsExitNode reports whether this relay has the Exit flag.
func (r TorRecord) IsExitNode() bool {
	for _, f := range r.Flags {
		if f == "Exit" {
			return true
		}
	}
	return false
}

// String formats a TOR record result.
func (r TorRecord) String() string {
	role := "relay"
	if r.IsExitNode() {
		role = "exit node"
	}
	return fmt.Sprintf("Tor %s %s [%s]", role, r.Nickname, strings.Join(r.Flags, ", "))
}
