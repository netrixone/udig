package udig

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_ResolutionBase_Query(t *testing.T) {
	base := &ResolutionBase{query: "example.com"}
	assert.Equal(t, "example.com", base.Query())
}

func Test_ResolutionBase_Domains_defaultEmpty(t *testing.T) {
	base := &ResolutionBase{query: "example.com"}
	domains := base.Domains()
	assert.Empty(t, domains)
}

func Test_ResolutionBase_IPs_defaultEmpty(t *testing.T) {
	base := &ResolutionBase{query: "192.0.2.1"}
	ips := base.IPs()
	assert.Empty(t, ips)
}

func Test_WithTimeout_appliedToNewEmptyUdig(t *testing.T) {
	udig := NewEmptyUdig(WithTimeout(30 * time.Second)).(*udigImpl)
	assert.Equal(t, 30*time.Second, udig.timeout)
}

func Test_WithDomainRelation_appliedToNewEmptyUdig(t *testing.T) {
	strict := func(a, b string) bool { return a == b }
	udig := NewEmptyUdig(WithDomainRelation(strict)).(*udigImpl)
	assert.NotNil(t, udig.isDomainRelated)
	assert.True(t, udig.isDomainRelated("x", "x"))
	assert.False(t, udig.isDomainRelated("x", "y"))
}
