package udig

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

////////////////////////////////////////////
// RDAP (Registration Data Access Protocol)
////////////////////////////////////////////

// IANA RDAP bootstrap URLs (RFC 9224). Each JSON file maps IP address space
// to the authoritative RDAP server base URLs (e.g. ARIN, RIPE, APNIC).
const (
	ianaBootstrapIPv4 = "https://data.iana.org/rdap/ipv4.json"
	ianaBootstrapIPv6 = "https://data.iana.org/rdap/ipv6.json"
)

// RDAPResolver implements IPResolver by querying RIR RDAP servers for IP registration
// data. It uses the IANA RDAP bootstrap to find the correct server per IP and caches
// results. No API key is required.
type RDAPResolver struct {
	Client        *http.Client
	cachedResults map[string][]Resolution
}

// NewRDAPResolver returns an RDAP resolver that queries RIR RDAP servers for IP
// registration data. The bootstrap is loaded lazily from IANA; results are cached per IP.
func NewRDAPResolver(timeout time.Duration) *RDAPResolver {
	return &RDAPResolver{
		Client:        &http.Client{Timeout: timeout},
		cachedResults: map[string][]Resolution{},
	}
}

// ResolveIP looks up the IP via IANA bootstrap and the appropriate RIR RDAP server,
// returning an RDAPResolution with network handle, name, range, type, and abuse contact.
// Invalid IP or lookup errors yield an empty Record; results are cached.
func (r *RDAPResolver) ResolveIP(ip string) []Resolution {
	if cached, ok := r.cachedResults[ip]; ok {
		return cached
	}

	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		LogErr("%s: IP %s is invalid.", TypeRDAP, ip)
		r.cachedResults[ip] = nil
		return nil
	}

	baseURL, err := rdapBootstrap.findBaseURL(ipAddr, r.Client)
	if err != nil {
		LogErr("%s: %s", TypeRDAP, err.Error())
		r.cachedResults[ip] = nil
		return nil
	}

	record, err := fetchRDAPForIP(r.Client, baseURL, ip)
	if err != nil {
		LogErr("%s: %s", TypeRDAP, err.Error())
		r.cachedResults[ip] = nil
		return nil
	}

	result := []Resolution{&RDAPResolution{
		ResolutionBase: &ResolutionBase{query: ip},
		Record:         *record,
	}}
	r.cachedResults[ip] = result
	return result
}

// Type returns TypeRDAP.
func (r *RDAPResolver) Type() ResolutionType {
	return TypeRDAP
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
