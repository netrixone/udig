package udig

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
)

/////////////////////////////////////////
// TLS RESOLVER
/////////////////////////////////////////

func NewTlsResolver() *TlsResolver {
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		TLSHandshakeTimeout: DefaultTimeout,
	}
	client := &http.Client{Transport: transport}

	return &TlsResolver{
		Client: client,
	}
}

func (resolver *TlsResolver) Resolve(domain string) *TlsResolution {
	resolution := &TlsResolution{
		Query: TlsQuery{domain},
	}

	certificates := resolver.fetchTlsCertChain(domain)
	for _, cert := range certificates {
		resolution.Answers = append(resolution.Answers, *cert)
	}

	return resolution
}

func (resolver *TlsResolver) fetchTlsCertChain(domain string) (chain []*x509.Certificate) {
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
