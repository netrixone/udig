package udig

import (
	"github.com/ip2location/ip2location-go"
	"os"
	"path/filepath"
)

var (
	// GeoDBPath is a path to IP2Location DB file.
	GeoDBPath = findGeoipDatabase("IP2LOCATION-LITE-DB1.IPV6.BIN")
)

/////////////////////////////////////////
// GEO RESOLVER
/////////////////////////////////////////

// GeoResolver is a Resolver which is able to resolve an IP to a geographical location.
type GeoResolver struct {
	enabled       bool
	db            *ip2location.DB
	cachedResults map[string][]Resolution
}

// NewGeoResolver creates a new GeoResolver with sensible defaults.
// The GeoIP database is opened once and reused for all lookups.
func NewGeoResolver() *GeoResolver {
	db, err := ip2location.OpenDB(GeoDBPath)
	if err != nil {
		LogErr("%s: Could not open DB at '%s'. The cause was: %s", TypeGEO, GeoDBPath, err.Error())
		return &GeoResolver{
			enabled:       false,
			cachedResults: map[string][]Resolution{},
		}
	}
	return &GeoResolver{
		enabled:       true,
		db:            db,
		cachedResults: map[string][]Resolution{},
	}
}

// ResolveIP resolves a given IP address to a corresponding GeoIP record.
func (r *GeoResolver) ResolveIP(ip string) []Resolution {
	if cached, ok := r.cachedResults[ip]; ok {
		return cached
	}

	if !r.enabled || r.db == nil {
		r.cachedResults[ip] = nil
		return nil
	}

	record, err := r.db.Get_country_short(ip)
	if err != nil {
		LogErr("%s: Could not query DB for IP %s. The cause was: %s", TypeGEO, ip, err.Error())
		r.cachedResults[ip] = nil
		return nil
	}

	result := []Resolution{&GeoResolution{
		ResolutionBase: &ResolutionBase{query: ip},
		Record:         GeoRecord{CountryCode: record.Country_short},
	}}
	r.cachedResults[ip] = result
	return result
}

// Type returns "GEO".
func (r *GeoResolver) Type() ResolutionType {
	return TypeGEO
}

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
