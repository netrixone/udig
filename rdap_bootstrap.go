package udig

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// bootstrapServices holds the parsed IANA RDAP bootstrap data: for each IP we
// find the longest-matching CIDR and use its RDAP base URL. IPv4 and IPv6 are
// loaded separately and lazily on first use. Access is protected by mux.
type bootstrapServices struct {
	mux   sync.RWMutex
	ipv4  []bootstrapEntry
	ipv6  []bootstrapEntry
	mtime time.Time
}

// bootstrapEntry associates a CIDR block with the RDAP server base URL for that range.
type bootstrapEntry struct {
	network *net.IPNet
	baseURL string
}

// rdapBootstrap is the process-wide cached bootstrap; shared by all RDAPResolver instances.
var rdapBootstrap bootstrapServices

// ipv4BootstrapJSON matches the IANA bootstrap JSON schema: services is an array
// of [ [cidr1, cidr2, ...], [url1, url2, ...] ] pairs.
type ipv4BootstrapJSON struct {
	Services [][][]string `json:"services"`
}

// loadIPv4 fetches and parses the IANA IPv4 RDAP bootstrap file. Caller must not hold b.mux.
func (b *bootstrapServices) loadIPv4(client *http.Client) error {
	b.mux.Lock()
	defer b.mux.Unlock()

	req, err := http.NewRequest(http.MethodGet, ianaBootstrapIPv4, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bootstrap %s: %s", ianaBootstrapIPv4, resp.Status)
	}

	var data ipv4BootstrapJSON
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return err
	}

	var entries []bootstrapEntry
	for _, pair := range data.Services {
		if len(pair) != 2 || len(pair[0]) == 0 || len(pair[1]) == 0 {
			continue
		}

		cidrs := pair[0]
		urls := pair[1]
		baseURL := pickHTTPS(urls)
		if baseURL == "" {
			baseURL = urls[0]
		}

		baseURL = strings.TrimSuffix(baseURL, "/")
		for _, cidrStr := range cidrs {
			_, network, err := net.ParseCIDR(cidrStr)
			if err != nil {
				continue
			}
			entries = append(entries, bootstrapEntry{network: network, baseURL: baseURL})
		}
	}

	b.ipv4 = entries
	b.mtime = time.Now()
	return nil
}

// pickHTTPS returns the first HTTPS URL from the list, or "" if none.
func pickHTTPS(urls []string) string {
	for _, u := range urls {
		if strings.HasPrefix(strings.ToLower(u), "https://") {
			return u
		}
	}
	return ""
}

// findBaseURL returns the RDAP base URL for the given IP using longest-matching
// CIDR from the IANA bootstrap. Loads IPv4 or IPv6 bootstrap on first use.
func (b *bootstrapServices) findBaseURL(ip net.IP, client *http.Client) (string, error) {
	var entries []bootstrapEntry
	if ip.To4() == nil {
		b.mux.RLock()
		if len(b.ipv6) == 0 {
			b.mux.RUnlock()
			if err := b.loadIPv6(client); err != nil {
				return "", err
			}
			b.mux.RLock()
		}
		entries = b.ipv6
		b.mux.RUnlock()
	} else {
		b.mux.RLock()
		if len(b.ipv4) == 0 {
			b.mux.RUnlock()
			if err := b.loadIPv4(client); err != nil {
				return "", err
			}
			b.mux.RLock()
		}
		entries = b.ipv4
		b.mux.RUnlock()
	}

	var best *bootstrapEntry
	for i := range entries {
		e := &entries[i]
		if e.network.Contains(ip) {
			if best == nil {
				best = e
				continue
			}

			bestOnes, _ := best.network.Mask.Size()
			curOnes, _ := e.network.Mask.Size()
			if curOnes > bestOnes {
				best = e
			}
		}
	}

	if best == nil {
		return "", fmt.Errorf("no RDAP bootstrap for IP %s", ip.String())
	}
	return best.baseURL, nil
}

// loadIPv6 fetches and parses the IANA IPv6 RDAP bootstrap file. Caller must not hold b.mux.
func (b *bootstrapServices) loadIPv6(client *http.Client) error {
	b.mux.Lock()
	defer b.mux.Unlock()

	req, err := http.NewRequest(http.MethodGet, ianaBootstrapIPv6, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bootstrap %s: %s", ianaBootstrapIPv6, resp.Status)
	}

	var data ipv4BootstrapJSON
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return err
	}

	var entries []bootstrapEntry
	for _, pair := range data.Services {
		if len(pair) != 2 || len(pair[0]) == 0 || len(pair[1]) == 0 {
			continue
		}
		cidrs := pair[0]
		urls := pair[1]
		baseURL := pickHTTPS(urls)
		if baseURL == "" {
			baseURL = urls[0]
		}
		baseURL = strings.TrimSuffix(baseURL, "/")
		for _, cidrStr := range cidrs {
			_, network, err := net.ParseCIDR(cidrStr)
			if err != nil {
				continue
			}
			entries = append(entries, bootstrapEntry{network: network, baseURL: baseURL})
		}
	}
	b.ipv6 = entries
	return nil
}
