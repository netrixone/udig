package udig

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"time"
)

/////////////////////////////////////////
// TLS RESOLVER
/////////////////////////////////////////

// TLSResolver is a Resolver responsible for resolution of a given domain
// to a list of TLS certificates.
type TLSResolver struct {
	Client *http.Client
}

// NewTLSResolver creates a new TLSResolver with sensible defaults.
func NewTLSResolver(timeout time.Duration) *TLSResolver {
	transport := &http.Transport{
		DialContext:         (&net.Dialer{Timeout: timeout}).DialContext,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		TLSHandshakeTimeout: timeout,
	}
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

// ResolveDomain resolves a given domain to TLS certificates (one resolution per cert).
func (r *TLSResolver) ResolveDomain(domain string) []Resolution {
	certificates := r.fetchTLSCertChain(domain)

	var results []Resolution
	for _, cert := range certificates {
		results = append(results, &TLSResolution{
			ResolutionBase: &ResolutionBase{query: domain},
			Record:         TLSCertificate{*cert},
		})
	}
	return results
}

func (r *TLSResolver) fetchTLSCertChain(domain string) (chain []*x509.Certificate) {
	res, err := r.Client.Get("https://" + domain)
	if err != nil {
		LogErr("%s: %s -> %s", TypeTLS, domain, err.Error())
		return chain
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, res.Body)

	if res.TLS == nil {
		return chain
	}

	return res.TLS.PeerCertificates
}
