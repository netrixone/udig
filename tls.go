package udig

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
)

/////////////////////////////////////////
// TLS RESOLVER
/////////////////////////////////////////

// NewTLSResolver creates a new TLSResolver with sensible defaults.
func NewTLSResolver() *TLSResolver {
	transport := http.DefaultTransport.(*http.Transport)

	transport.DialContext = (&net.Dialer{
		Timeout:   DefaultTimeout,
		KeepAlive: DefaultTimeout,
		DualStack: true,
	}).DialContext

	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	transport.TLSHandshakeTimeout = DefaultTimeout

	client := &http.Client{
		Transport: transport,
		Timeout:   DefaultTimeout,
	}

	return &TLSResolver{
		Client: client,
	}
}

// Type returns "TLS".
func (resolver *TLSResolver) Type() ResolutionType {
	return TypeTLS
}

// ResolveDomain resolves a given domain to a list of TLS certificates.
func (resolver *TLSResolver) ResolveDomain(domain string) Resolution {
	resolution := &TLSResolution{
		ResolutionBase: &ResolutionBase{query: domain},
	}

	certificates := resolver.fetchTLSCertChain(domain)
	for _, cert := range certificates {
		resolution.Certificates = append(resolution.Certificates, TLSCertificate{*cert})
	}

	return resolution
}

func (resolver *TLSResolver) fetchTLSCertChain(domain string) (chain []*x509.Certificate) {
	res, err := resolver.Client.Get("https://" + domain)
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
func (res *TLSResolution) Type() ResolutionType {
	return TypeTLS
}

// Domains returns a list of domains discovered in records within this Resolution.
func (res *TLSResolution) Domains() (domains []string) {
	for _, cert := range res.Certificates {
		domains = append(domains, dissectDomainsFromCert(&cert)...)
	}
	return domains
}

/////////////////////////////////////////
// TLS CERTIFICATE
/////////////////////////////////////////

func (cert *TLSCertificate) String() string {
	subject := cert.Subject.CommonName
	if subject == "" {
		subject = cert.Subject.String()
	}
	issuer := cert.Issuer.CommonName
	if issuer == "" {
		issuer = cert.Issuer.String()
	}
	return fmt.Sprintf("subject: %s, issuer: %s, domains: %v", subject, issuer, cert.DNSNames)
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
