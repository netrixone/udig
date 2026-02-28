package udig

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
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

/////////////////////////////////////////
// HTTP RESOLVER
/////////////////////////////////////////

// HTTPResolver is a Resolver responsible for resolution of a given domain
// to a list of corresponding HTTP headers.
type HTTPResolver struct {
	Headers []string     // HTTP header names to look for (e.g. content-security-policy)
	Client  *http.Client // HTTP client used for all requests
}

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

// ResolveDomain resolves a given domain to HTTP results (one resolution per header
// or discovered domain from robots.txt / security.txt).
func (r *HTTPResolver) ResolveDomain(domain string) []Resolution {
	var results []Resolution
	baseURL := "https://" + domain

	headers := fetchHeaders(r.Client, baseURL)
	for _, name := range r.Headers {
		values := headers[http.CanonicalHeaderKey(name)]
		joined := strings.Join(values, ", ")
		if len(DissectDomainsFromString(joined)) > 0 {
			results = append(results, &HTTPResolution{
				ResolutionBase: &ResolutionBase{query: domain},
				Record:         HTTPRecord{Key: name, Value: joined},
			})
		}
	}

	seen := make(map[string]bool)
	seen[domain] = true

	if body := fetchBody(r.Client, baseURL+"/.well-known/security.txt"); body != "" {
		for _, d := range DissectDomainsFromString(body) {
			if seen[d] {
				continue
			}
			seen[d] = true

			results = append(results, &HTTPResolution{
				ResolutionBase: &ResolutionBase{query: domain},
				Record:         HTTPRecord{Key: "security.txt", Value: d},
			})
		}
	}

	clear(seen)
	seen[domain] = true

	if body := fetchBody(r.Client, baseURL+"/robots.txt"); body != "" {
		for _, d := range DissectDomainsFromString(body) {
			if seen[d] {
				continue
			}
			seen[d] = true

			results = append(results, &HTTPResolution{
				ResolutionBase: &ResolutionBase{query: domain},
				Record:         HTTPRecord{Key: "robots.txt", Value: d},
			})
		}
	}

	return results
}

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
