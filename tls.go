package udig

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"time"
)

/////////////////////////////////////////
// TLS RESOLVER
/////////////////////////////////////////

// NewTLSResolver creates a new TLSResolver with sensible defaults.
func NewTLSResolver(timeout time.Duration) *TLSResolver {
	transport := http.DefaultTransport.(*http.Transport)

	transport.DialContext = (&net.Dialer{
		Timeout: timeout,
	}).DialContext

	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	transport.TLSHandshakeTimeout = timeout

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	return &TLSResolver{
		Client: client,
	}
}

// Type returns "TLS".
func (r *TLSResolver) Type() ResolutionType {
	return TypeTLS
}

// ResolveDomain resolves a given domain to a list of TLS certificates.
func (r *TLSResolver) ResolveDomain(domain string) Resolution {
	resolution := &TLSResolution{
		ResolutionBase: &ResolutionBase{query: domain},
	}

	certificates := r.fetchTLSCertChain(domain)
	for _, cert := range certificates {
		resolution.Certificates = append(resolution.Certificates, TLSCertificate{*cert})
	}

	return resolution
}

func (r *TLSResolver) fetchTLSCertChain(domain string) (chain []*x509.Certificate) {
	res, err := r.Client.Get("https://" + domain)
	if err != nil {
		LogErr("%s: %s -> %s", TypeTLS, domain, err.Error())
		return chain
	}

	if res.TLS == nil {
		// No cert available.
		return chain
	}

	return res.TLS.PeerCertificates
}

/////////////////////////////////////////
// TLS RESOLUTION
/////////////////////////////////////////

// Type returns "TLS".
func (r *TLSResolution) Type() ResolutionType {
	return TypeTLS
}

// Domains returns a list of domains discovered in records within this Resolution.
func (r *TLSResolution) Domains() (domains []string) {
	for _, cert := range r.Certificates {
		domains = append(domains, dissectDomainsFromCert(&cert)...)
	}
	return domains
}

/////////////////////////////////////////
// TLS CERTIFICATE
/////////////////////////////////////////

func (c *TLSCertificate) String() string {
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
