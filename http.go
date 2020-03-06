package udig

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
)

var (
	// DefaultHTTPHeaders is a list of default HTTP header names that we look for.
	DefaultHTTPHeaders = [...]string{
		"access-control-allow-origin",
		"alt-svc",
		"content-security-policy",
		"content-security-policy-report-only",
	}
)

/////////////////////////////////////////
// HTTP RESOLVER
/////////////////////////////////////////

// NewHTTPResolver creates a new HTTPResolver with sensible defaults.
func NewHTTPResolver() *HTTPResolver {
	transport := http.DefaultTransport.(*http.Transport)

	transport.DialContext = (&net.Dialer{
		Timeout:   DefaultTimeout,
		KeepAlive: DefaultTimeout,
	}).DialContext

	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	transport.TLSHandshakeTimeout = DefaultTimeout

	client := &http.Client{
		Transport: transport,
		Timeout:   DefaultTimeout,
	}

	return &HTTPResolver{
		Headers: DefaultHTTPHeaders[:],
		Client:  client,
	}
}

// Type returns "HTTP".
func (resolver *HTTPResolver) Type() ResolutionType {
	return TypeHTTP
}

// Resolve resolves a given domain to a list of corresponding HTTP headers.
func (resolver *HTTPResolver) Resolve(domain string) Resolution {
	resolution := &HTTPResolution{
		ResolutionBase: &ResolutionBase{query: domain},
	}

	headers := resolver.fetchHeaders("https://" + domain)
	for _, name := range resolver.Headers {
		value := headers[http.CanonicalHeaderKey(name)]
		if len(value) > 0 {
			resolution.Headers = append(resolution.Headers, HTTPHeader{name, value})
		}
	}

	return resolution
}

func (resolver *HTTPResolver) fetchHeaders(url string) http.Header {
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

	response, err := client.Get(url)
	if err != nil {
		// Don't bother trying to find CSP on non-TLS sites.
		LogErr("HTTP: Could not GET %s - the cause was: %s.", url, err.Error())
		return map[string][]string{}
	}

	return response.Header
}

/////////////////////////////////////////
// HTTP RESOLUTION
/////////////////////////////////////////

// Type returns "HTTP".
func (res *HTTPResolution) Type() ResolutionType {
	return TypeHTTP
}

// Domains returns a list of domains discovered in records within this Resolution.
func (res *HTTPResolution) Domains() (domains []string) {
	for _, header := range res.Headers {
		domains = append(domains, dissectDomainsFromStrings(header.Value)...)
	}
	return domains
}

/////////////////////////////////////////
// HTTP HEADER
/////////////////////////////////////////

func (header *HTTPHeader) String() string {
	return fmt.Sprintf("%s: %v", header.Name, header.Value)
}
