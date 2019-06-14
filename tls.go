package udig

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
)

/////////////////////////////////////////
// TLS RESOLVER
/////////////////////////////////////////

func NewTLSResolver() *TLSResolver {
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		TLSHandshakeTimeout: DefaultTimeout,
	}
	client := &http.Client{Transport: transport}

	return &TLSResolver{
		Client: client,
	}
}

func (resolver *TLSResolver) Resolve(domain string) *TLSResolution {
	resolution := &TLSResolution{
		Query: TLSQuery{domain},
	}

	certificates := resolver.fetchTLSCertChain(domain)
	for _, cert := range certificates {
		resolution.Answers = append(resolution.Answers, *cert)
	}

	return resolution
}

func (resolver *TLSResolver) fetchTLSCertChain(domain string) (chain []*x509.Certificate) {
	res, err := resolver.Client.Get("https://" + domain)
	if err != nil {
		LogErr("%s: %s -> %s", KindTLS, domain, err.Error())
		return chain
	}

	if res.TLS == nil {
		// No cert available.
		return chain
	}

	return res.TLS.PeerCertificates
}
