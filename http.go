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
		LogErr("HTTP: Could not GET %s - the cause was: %s.", url, err.Error())
		return map[string][]string{}
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)

	return response.Header
}

// fetchBody fetches the given URL and returns the body as a string (up to 256 KB).
func fetchBody(client *http.Client, url string) string {
	response, err := client.Get(url)
	if err != nil {
		LogDebug("HTTP: Could not GET %s - %s.", url, err.Error())
		return ""
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, response.Body)
		return ""
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, 256*1024))
	if err != nil {
		return ""
	}
	return string(body)
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

	baseURL := "https://" + domain

	headers := fetchHeaders(r.Client, baseURL)
	for _, name := range r.Headers {
		value := headers[http.CanonicalHeaderKey(name)]
		if len(DissectDomainsFromStrings(value)) > 0 {
			resolution.Headers = append(resolution.Headers, HTTPHeader{name, value})
		}
	}

	if body := fetchBody(r.Client, baseURL+"/.well-known/security.txt"); body != "" {
		resolution.SecurityTxtDomains = DissectDomainsFromString(body)
	}

	if body := fetchBody(r.Client, baseURL+"/robots.txt"); body != "" {
		resolution.RobotsTxtDomains = DissectDomainsFromString(body)
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

// Domains returns a deduplicated list of domains from headers, security.txt, and robots.txt.
func (r *HTTPResolution) Domains() (domains []string) {
	seen := map[string]bool{}
	for _, header := range r.Headers {
		for _, d := range DissectDomainsFromStrings(header.Value) {
			seen[d] = true
		}
	}

	for _, d := range r.SecurityTxtDomains {
		seen[d] = true
	}

	for _, d := range r.RobotsTxtDomains {
		seen[d] = true
	}

	domains = make([]string, 0, len(seen))
	for d := range seen {
		domains = append(domains, d)
	}
	return domains
}

/////////////////////////////////////////
// HTTP HEADER
/////////////////////////////////////////

func (h *HTTPHeader) String() string {
	return fmt.Sprintf("%s: %v", h.Name, h.Value)
}
