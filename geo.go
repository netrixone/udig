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

// CheckGeoipDatabase returns true if a given path points to a valid GeoIP DB file.
func checkGeoipDatabase(geoipPath string) bool {
	if info, err := os.Stat(geoipPath); err != nil || info.IsDir() {
		LogErr("%s: Cannot use IP2Location DB at '%s' (file exists: %t).", TypeGEO, geoipPath, os.IsExist(err))
		return false
	}
	_, err := ip2location.OpenDB(geoipPath)
	return err == nil
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

func queryIP(ip string) *ip2location.IP2Locationrecord {
	db, err := ip2location.OpenDB(GeoDBPath)
	if err != nil {
		LogErr("%s: Could not open DB. The cause was: %s", TypeGEO, err.Error())
		return nil
	}

	record, err := db.Get_country_short(ip)
	if err != nil {
		LogErr("%s: Could not query DB for IP %s. The cause was: %s", TypeGEO, ip, err.Error())
		return nil
	}

	db.Close()

	return &record
}

/////////////////////////////////////////
// GEO RESOLVER
/////////////////////////////////////////

// NewGeoResolver creates a new GeoResolver with sensible defaults.
func NewGeoResolver() *GeoResolver {
	return &GeoResolver{
		enabled:       checkGeoipDatabase(GeoDBPath),
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

	if !r.enabled {
		return resolution
	}

	geoRecord := queryIP(ip)
	if geoRecord == nil {
		return resolution
	}
	resolution.Record = &GeoRecord{CountryCode: geoRecord.Country_short}

	return resolution
}

// Type returns "GEO".
func (r *GeoResolver) Type() ResolutionType {
	return TypeGEO
}

/////////////////////////////////////////
// GEO RESOLUTION
/////////////////////////////////////////

// Type returns "BGP".
func (r *GeoResolution) Type() ResolutionType {
	return TypeGEO
}

/////////////////////////////////////////
// GEO RECORD
/////////////////////////////////////////

func (r *GeoRecord) String() string {
	return fmt.Sprintf("country code: %s", r.CountryCode)
}
