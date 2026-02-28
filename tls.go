package udig

import (
	"crypto/x509"
	"fmt"
)

/////////////////////////////////////////
// TLS RESOLUTION
/////////////////////////////////////////

// TLSResolution is a single TLS certificate result (denormalized: one cert per resolution).
type TLSResolution struct {
	*ResolutionBase
	Record TLSCertificate
}

// Type returns "TLS".
func (r *TLSResolution) Type() ResolutionType {
	return TypeTLS
}

// Domains returns domains discovered in this single TLS certificate.
func (r *TLSResolution) Domains() (domains []string) {
	return dissectDomainsFromCert(&r.Record)
}

/////////////////////////////////////////
// TLS CERTIFICATE
/////////////////////////////////////////

// TLSCertificate is a wrapper for the actual x509.Certificate.
type TLSCertificate struct {
	x509.Certificate
}

func (c TLSCertificate) String() string {
	subject := c.Subject.CommonName
	if subject == "" {
		subject = c.Subject.String()
	}
	issuer := c.Issuer.CommonName
	if issuer == "" {
		issuer = c.Issuer.String()
	}
	return fmt.Sprintf("subject: %s, issuer: %s, domains: %v", subject, issuer, c.DNSNames)
}

func dissectDomainsFromCert(cert *TLSCertificate) (domains []string) {
	var haystack []string
	haystack = append(haystack, cert.CRLDistributionPoints...)
	haystack = append(haystack, cert.DNSNames...)
	haystack = append(haystack, cert.EmailAddresses...)
	haystack = append(haystack, cert.ExcludedDNSDomains...)
	haystack = append(haystack, cert.ExcludedEmailAddresses...)
	haystack = append(haystack, cert.ExcludedURIDomains...)
	haystack = append(haystack, cert.Issuer.String())
	haystack = append(haystack, cert.PermittedDNSDomains...)
	haystack = append(haystack, cert.PermittedEmailAddresses...)
	haystack = append(haystack, cert.PermittedURIDomains...)
	haystack = append(haystack, cert.Subject.String())
	for _, uri := range cert.URIs {
		haystack = append(haystack, uri.Host)
	}

	return DissectDomainsFromStrings(haystack)
}
