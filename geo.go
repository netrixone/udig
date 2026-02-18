package udig

import (
	"fmt"
	"github.com/ip2location/ip2location-go"
	"os"
	"path/filepath"
)

var (
	// GeoDBPath is a path to IP2Location DB file.
	GeoDBPath = findGeoipDatabase("IP2LOCATION-LITE-DB1.IPV6.BIN")
)

// FindGeoipDatabase attempts to locate a GeoIP database file at a given path.
//
// If the given path is absolute, it is used as it is.
// If the path is relative, then it is first checked against CWD and then against
// the dir where the executable resides in.
func findGeoipDatabase(geoipPath string) string {
	// If the path is absolute, leave it as it is.
	if filepath.IsAbs(geoipPath) {
		return geoipPath
	}

	// Otherwise check CWD first.
	cwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	relPath := filepath.Join(cwd, geoipPath)
	if _, err := os.Stat(relPath); !os.IsNotExist(err) {
		return relPath
	}

	// Finally, try a path relative to the binary.
	executable, err := os.Executable()
	if err != nil {
		panic(err)
	}

	return filepath.Join(filepath.Dir(executable), geoipPath)
}

/////////////////////////////////////////
// GEO RESOLVER
/////////////////////////////////////////

// NewGeoResolver creates a new GeoResolver with sensible defaults.
// The GeoIP database is opened once and reused for all lookups.
func NewGeoResolver() *GeoResolver {
	db, err := ip2location.OpenDB(GeoDBPath)
	if err != nil {
		LogErr("%s: Could not open DB at '%s'. The cause was: %s", TypeGEO, GeoDBPath, err.Error())
		return &GeoResolver{
			enabled:       false,
			cachedResults: map[string]*GeoResolution{},
		}
	}
	return &GeoResolver{
		enabled:       true,
		db:            db,
		cachedResults: map[string]*GeoResolution{},
	}
}

// ResolveIP resolves a given IP address to a corresponding GeoIP record.
func (r *GeoResolver) ResolveIP(ip string) Resolution {
	resolution := r.cachedResults[ip]
	if resolution != nil {
		return resolution
	}
	resolution = &GeoResolution{ResolutionBase: &ResolutionBase{query: ip}}
	r.cachedResults[ip] = resolution

	if !r.enabled || r.db == nil {
		return resolution
	}

	record, err := r.db.Get_country_short(ip)
	if err != nil {
		LogErr("%s: Could not query DB for IP %s. The cause was: %s", TypeGEO, ip, err.Error())
		return resolution
	}
	resolution.Record = &GeoRecord{CountryCode: record.Country_short}

	return resolution
}

// Type returns "GEO".
func (r *GeoResolver) Type() ResolutionType {
	return TypeGEO
}

/////////////////////////////////////////
// GEO RESOLUTION
/////////////////////////////////////////

// Type returns "GEO".
func (r *GeoResolution) Type() ResolutionType {
	return TypeGEO
}

/////////////////////////////////////////
// GEO RECORD
/////////////////////////////////////////

func (r *GeoRecord) String() string {
	return fmt.Sprintf("country code: %s", r.CountryCode)
}
