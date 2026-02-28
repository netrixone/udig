// RDAP resolver and IANA bootstrap.
//
// The RDAP resolver looks up IP addresses against Regional Internet Registry (RIR)
// RDAP services to retrieve registration metadata: network handle, name, address
// range, allocation type, and abuse contact. It uses the IANA RDAP bootstrap
// (RFC 9224) to find the correct RIR server for each IP.
package udig

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// IANA RDAP bootstrap URLs (RFC 9224). Each JSON file maps IP address space
// to the authoritative RDAP server base URLs (e.g. ARIN, RIPE, APNIC).
const (
	ianaBootstrapIPv4 = "https://data.iana.org/rdap/ipv4.json"
	ianaBootstrapIPv6 = "https://data.iana.org/rdap/ipv6.json"
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

// rdapIPResponse is the top-level structure of an RDAP "ip network" response (RFC 9083).
type rdapIPResponse struct {
	Handle       string       `json:"handle"`
	Name         string       `json:"name"`
	StartAddress string       `json:"startAddress"`
	EndAddress   string       `json:"endAddress"`
	Type         string       `json:"type"`
	Entities     []rdapEntity `json:"entities"`
}

// rdapEntity represents a contact or organisation in the RDAP response (roles + vCard).
type rdapEntity struct {
	Roles      []string      `json:"roles"`
	VcardArray []interface{} `json:"vcardArray"`
}

// parseVcardEmail extracts the first email value from an RDAP vcardArray.
// Format: ["vcard", [ [key, {}, "text", value], ... ] ]. Used for abuse/registrant contacts.
func parseVcardEmail(vcardArray []interface{}) string {
	if len(vcardArray) < 2 {
		return ""
	}

	inner, ok := vcardArray[1].([]interface{})
	if !ok {
		return ""
	}

	for _, row := range inner {
		arr, ok := row.([]interface{})
		if !ok || len(arr) < 4 {
			continue
		}
		key, _ := arr[0].(string)
		if strings.ToLower(key) == "email" {
			if val, ok := arr[3].(string); ok {
				return val
			}
		}
	}
	return ""
}

// parseVcardOrg extracts the organisation name from an RDAP vcardArray (fn or org field).
func parseVcardOrg(vcardArray []interface{}) string {
	if len(vcardArray) < 2 {
		return ""
	}
	inner, ok := vcardArray[1].([]interface{})
	if !ok {
		return ""
	}

	var fn, org string
	for _, row := range inner {
		arr, ok := row.([]interface{})
		if !ok || len(arr) < 4 {
			continue
		}
		key, _ := arr[0].(string)
		val, _ := arr[3].(string)
		switch strings.ToLower(key) {
		case "fn":
			fn = val
		case "org":
			org = val
		}
	}

	if fn != "" {
		return fn
	}
	return org
}

// fetchRDAPForIP performs GET {baseURL}/ip/{ip}, parses the JSON response, and returns
// an RDAPRecord with handle, name, address range, type, and abuse/org from entities.
func fetchRDAPForIP(client *http.Client, baseURL, ip string) (*RDAPRecord, error) {
	u, err := url.JoinPath(baseURL, "ip", ip)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/rdap+json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("RDAP %s: %s", u, resp.Status)
	}

	var data rdapIPResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	record := &RDAPRecord{
		Handle:       data.Handle,
		Name:         data.Name,
		StartAddress: data.StartAddress,
		EndAddress:   data.EndAddress,
		NetworkType:  data.Type,
	}

	for _, e := range data.Entities {
		roles := strings.Join(e.Roles, " ")
		if strings.Contains(roles, "abuse") {
			if record.AbuseEmail == "" {
				record.AbuseEmail = parseVcardEmail(e.VcardArray)
			}
		}
		if record.OrgName == "" && (strings.Contains(roles, "registrant") || strings.Contains(roles, "technical")) {
			record.OrgName = parseVcardOrg(e.VcardArray)
		}
	}
	if record.OrgName == "" && len(data.Entities) > 0 {
		record.OrgName = parseVcardOrg(data.Entities[0].VcardArray)
	}

	return record, nil
}

// --- RDAP Resolver (IPResolver) ---

// NewRDAPResolver returns an RDAP resolver that queries RIR RDAP servers for IP
// registration data. The bootstrap is loaded lazily from IANA; results are cached per IP.
func NewRDAPResolver(timeout time.Duration) *RDAPResolver {
	return &RDAPResolver{
		Client:        &http.Client{Timeout: timeout},
		cachedResults: map[string]*RDAPResolution{},
	}
}

// ResolveIP looks up the IP via IANA bootstrap and the appropriate RIR RDAP server,
// returning an RDAPResolution with network handle, name, range, type, and abuse contact.
// Invalid IP or lookup errors yield an empty Record; results are cached.
func (r *RDAPResolver) ResolveIP(ip string) Resolution {
	if cached := r.cachedResults[ip]; cached != nil {
		return cached
	}

	resolution := &RDAPResolution{
		ResolutionBase: &ResolutionBase{query: ip},
	}
	r.cachedResults[ip] = resolution

	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		LogErr("%s: IP %s is invalid.", TypeRDAP, ip)
		return resolution
	}

	baseURL, err := rdapBootstrap.findBaseURL(ipAddr, r.Client)
	if err != nil {
		LogErr("%s: %s", TypeRDAP, err.Error())
		return resolution
	}

	record, err := fetchRDAPForIP(r.Client, baseURL, ip)
	if err != nil {
		LogErr("%s: %s", TypeRDAP, err.Error())
		return resolution
	}

	resolution.Record = record
	return resolution
}

// Type returns TypeRDAP.
func (r *RDAPResolver) Type() ResolutionType {
	return TypeRDAP
}

// Type returns TypeRDAP.
func (r *RDAPResolution) Type() ResolutionType {
	return TypeRDAP
}

// String formats the RDAP record for CLI output (handle, name, range, type, org, abuse).
func (r *RDAPRecord) String() string {
	parts := []string{}
	if r.Handle != "" {
		parts = append(parts, "handle: "+r.Handle)
	}
	if r.Name != "" {
		parts = append(parts, "name: "+r.Name)
	}
	if r.StartAddress != "" && r.EndAddress != "" {
		parts = append(parts, r.StartAddress+" - "+r.EndAddress)
	} else if r.StartAddress != "" {
		parts = append(parts, "start: "+r.StartAddress)
	}
	if r.NetworkType != "" {
		parts = append(parts, "type: "+r.NetworkType)
	}
	if r.OrgName != "" {
		parts = append(parts, "org: "+r.OrgName)
	}
	if r.AbuseEmail != "" {
		parts = append(parts, "abuse: "+r.AbuseEmail)
	}
	return strings.Join(parts, ", ")
}
