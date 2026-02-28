package udig

import (
	"github.com/miekg/dns"
	"strings"
	"time"
)

/////////////////////////////////////////
// DMARC RESOLVER
/////////////////////////////////////////

// DMARCResolver queries _dmarc TXT records and parses DMARC policy fields.
type DMARCResolver struct {
	Client *dns.Client
}

// NewDMARCResolver creates a new DMARCResolver with sensible defaults.
func NewDMARCResolver(timeout time.Duration) *DMARCResolver {
	return &DMARCResolver{
		Client: &dns.Client{ReadTimeout: timeout},
	}
}

// Type returns "DMARC".
func (r *DMARCResolver) Type() ResolutionType {
	return TypeDMARC
}

// ResolveDomain queries _dmarc.{domain} TXT and parses DMARC policy, rua, ruf.
// Returns at most one DMARCResolution if a valid DMARC record is found.
func (r *DMARCResolver) ResolveDomain(domain string) []Resolution {
	query := "_dmarc." + domain

	msg, err := queryOneCallback(query, dns.TypeTXT, localNameServer, r.Client)
	if err != nil {
		LogDebug("%s: %s -> %s", TypeDMARC, query, err.Error())
		return nil
	}

	var raw string
	for _, rr := range msg.Answer {
		if rr.Header().Rrtype != dns.TypeTXT {
			continue
		}
		for _, s := range rr.(*dns.TXT).Txt {
			raw += s
		}
	}

	policy, rua, ruf := parseDMARC(raw)
	if policy == "" && len(rua) == 0 && len(ruf) == 0 {
		return nil
	}

	return []Resolution{&DMARCResolution{
		ResolutionBase: &ResolutionBase{query: domain},
		Record: DMARCRecord{
			DMARCPolicy: policy,
			DMARCRua:    rua,
			DMARCRuf:    ruf,
		},
	}}
}

// parseDMARC extracts policy, rua and ruf from a raw DMARC TXT value.
func parseDMARC(raw string) (policy string, rua, ruf []string) {
	if raw == "" {
		return
	}

	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}

		key := strings.TrimSpace(strings.ToLower(kv[0]))
		val := strings.TrimSpace(kv[1])
		switch key {
		case "p":
			policy = strings.ToLower(val)

		case "rua":
			for _, uri := range strings.Split(val, ",") {
				uri = strings.TrimSpace(uri)
				if uri != "" {
					rua = append(rua, uri)
				}
			}

		case "ruf":
			for _, uri := range strings.Split(val, ",") {
				uri = strings.TrimSpace(uri)
				if uri != "" {
					ruf = append(ruf, uri)
				}
			}
		}
	}
	return
}
