package udig

import (
	"crypto/tls"
	"fmt"
	"io"
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

// fetchHeaders uses the given client to GET the URL and returns the response headers.
func fetchHeaders(client *http.Client, url string) http.Header {
	response, err := client.Get(url)
	if err != nil {
		// Don't bother trying to find CSP on non-TLS sites.
		LogErr("HTTP: Could not GET %s - the cause was: %s.", url, err.Error())
		return map[string][]string{}
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)

	return response.Header
}

/////////////////////////////////////////
// HTTP RESOLVER
/////////////////////////////////////////

// NewHTTPResolver creates a new HTTPResolver with sensible defaults.
func NewHTTPResolver(timeout time.Duration) *HTTPResolver {
	transport := &http.Transport{
		DialContext:         (&net.Dialer{Timeout: timeout}).DialContext,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		TLSHandshakeTimeout: timeout,
	}
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

	headers := fetchHeaders(r.Client, "https://"+domain)
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
