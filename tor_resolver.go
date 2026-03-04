package udig

import (
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"time"
)

const onionooDetailsURL = "https://onionoo.torproject.org/details"

/////////////////////////////////////////
// TOR RESOLVER
/////////////////////////////////////////

// onionooDetailsResponse is the minimal subset of the Onionoo details response we use.
type onionooDetailsResponse struct {
	Relays []onionooRelay `json:"relays"`
}

type onionooRelay struct {
	Nickname      string   `json:"nickname"`
	Fingerprint   string   `json:"fingerprint"`
	Flags         []string `json:"flags"`
	ORAddresses   []string `json:"or_addresses"`
	ExitAddresses []string `json:"exit_addresses"`
}

// TorResolver checks if an IP is a Tor node via the Onionoo API.
type TorResolver struct {
	Client *http.Client
}

// NewTorResolver creates a new TorResolver with the given timeout.
func NewTorResolver(timeout time.Duration) *TorResolver {
	return &TorResolver{
		Client: &http.Client{Timeout: timeout},
	}
}

// ResolveIP checks whether an IP is a Tor node via the Onionoo details API.
// Returns one Resolution if the IP is a known Tor relay, nil otherwise.
func (r *TorResolver) ResolveIP(ip string) []Resolution {
	if net.ParseIP(ip) == nil {
		LogErr("%s: IP %s is invalid.", TypeTor, ip)
		return nil
	}

	u, _ := url.Parse(onionooDetailsURL)
	q := u.Query()
	q.Set("search", ip)
	u.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		LogErr("%s: request build failed: %s", TypeTor, err)
		return nil
	}

	resp, err := r.Client.Do(req)
	if err != nil {
		LogErr("%s: Onionoo request failed: %s", TypeTor, err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		LogErr("%s: Onionoo returned %s", TypeTor, resp.Status)
		return nil
	}

	var data onionooDetailsResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		LogErr("%s: JSON decode failed: %s", TypeTor, err)
		return nil
	}

	relay := findRelayForIP(data.Relays, ip)
	if relay == nil {
		return nil
	}

	return []Resolution{&TorResolution{
		ResolutionBase: &ResolutionBase{query: ip},
		Record: TorRecord{
			Nickname:    relay.Nickname,
			Fingerprint: relay.Fingerprint,
			Flags:       relay.Flags,
		},
	}}
}

// Type returns "TOR".
func (r *TorResolver) Type() ResolutionType {
	return TypeTor
}

// findRelayForIP returns the first relay whose OR addresses or exit addresses contain given ip.
func findRelayForIP(relays []onionooRelay, ip string) *onionooRelay {
	for i := range relays {
		relay := &relays[i]
		for _, addr := range relay.ORAddresses {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				host = addr
			}

			if host == ip {
				return relay
			}
		}

		for _, addr := range relay.ExitAddresses {
			if addr == ip {
				return relay
			}
		}
	}
	return nil
}
