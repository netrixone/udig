package udig

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_GeoResolver_Type_returnsTypeGEO(t *testing.T) {
	r := NewGeoResolver()
	assert.Equal(t, TypeGEO, r.Type())
}

func Test_GeoResolver_ResolveIP_returnsResolutionWithQuery(t *testing.T) {
	r := NewGeoResolver()
	resolution := r.ResolveIP("192.0.2.1")
	assert.Equal(t, TypeGEO, resolution.Type())
	assert.Equal(t, "192.0.2.1", resolution.Query())
	gr, ok := resolution.(*GeoResolution)
	assert.True(t, ok)
	assert.NotNil(t, gr)
	// With or without DB, Record may be nil
	assert.NotNil(t, gr.ResolutionBase)
}

func Test_GeoResolution_Type_returnsTypeGEO(t *testing.T) {
	res := &GeoResolution{ResolutionBase: &ResolutionBase{query: "1.1.1.1"}}
	assert.Equal(t, TypeGEO, res.Type())
}

func Test_GeoRecord_String(t *testing.T) {
	r := GeoRecord{CountryCode: "US"}
	assert.Equal(t, "country code: US", r.String())
}
