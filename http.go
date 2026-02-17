package udig

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"
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

// fetchHeaders connects to a given URL and on successful connection returns
// a map of HTTP headers in the response.
func fetchHeaders(url string) http.Header {
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

	response, err := client.Get(url)
	if err != nil {
		// Don't bother trying to find CSP on non-TLS sites.
		LogErr("HTTP: Could not GET %s - the cause was: %s.", url, err.Error())
		return map[string][]string{}
	}

	return response.Header
}

/////////////////////////////////////////
// HTTP RESOLVER
/////////////////////////////////////////

// NewHTTPResolver creates a new HTTPResolver with sensible defaults.
func NewHTTPResolver(timeout time.Duration) *HTTPResolver {
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

	return &HTTPResolver{
		Headers: DefaultHTTPHeaders[:],
		Client:  client,
	}
}

// Type returns "HTTP".
func (r *HTTPResolver) Type() ResolutionType {
	return TypeHTTP
}

// ResolveDomain resolves a given domain to a list of corresponding HTTP headers.
func (r *HTTPResolver) ResolveDomain(domain string) Resolution {
	resolution := &HTTPResolution{
		ResolutionBase: &ResolutionBase{query: domain},
	}

	headers := fetchHeaders("https://" + domain)
	for _, name := range r.Headers {
		value := headers[http.CanonicalHeaderKey(name)]
		if len(DissectDomainsFromStrings(value)) > 0 {
			resolution.Headers = append(resolution.Headers, HTTPHeader{name, value})
		}
	}

	return resolution
}

/////////////////////////////////////////
// HTTP RESOLUTION
/////////////////////////////////////////

// Type returns "HTTP".
func (r *HTTPResolution) Type() ResolutionType {
	return TypeHTTP
}

// Domains returns a list of domains discovered in records within this Resolution.
func (r *HTTPResolution) Domains() (domains []string) {
	for _, header := range r.Headers {
		domains = append(domains, DissectDomainsFromStrings(header.Value)...)
	}
	return domains
}

/////////////////////////////////////////
// HTTP HEADER
/////////////////////////////////////////

func (h *HTTPHeader) String() string {
	return fmt.Sprintf("%s: %v", h.Name, h.Value)
}
