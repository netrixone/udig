package udig

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/domainr/whois"
	"io"
	"strings"
)

var (
	// SupportedWhoisProperties is a set of WHOIS properties that WhoisResolver honors.
	SupportedWhoisProperties = map[string]bool{
		"registry domain id":        true,
		"registrant":                true,
		"registrant organization":   true,
		"registrant state/province": true,
		"registrant country":        true,

		"registrar":              true,
		"registrar iana id":      true,
		"registrar whois server": true,
		"registrar url":          true,
		"creation date":          true,
		"updated date":           true,
		"registered":             true,
		"changed":                true,
		"expire":                 true,

		"nsset": true,

		"contact": true,
		"name":    true,
		"address": true,
	}
)

// Expect to receive a reader to text with 3 parts:
// 1. Key-value pairs separated by colon (":")
// 2. A line `>>> Last update of WHOIS database: [date]<<<`
// 3. Follow by an empty line, then free text of the legal disclaimers.
func parseWhoisResponse(reader io.Reader) (contacts []WhoisContact) {
	scanner := bufio.NewScanner(reader)
	contact := WhoisContact{}

	var lineNumber int
	for lineNumber = 1; scanner.Scan(); lineNumber++ {
		// Grab the line and clean it.
		line := strings.Trim(scanner.Text(), " \n\r\t")
		line = strings.ToLower(line)

		if line == "" {
			// Empty line usually separates contacts -> create a new one.
			if len(contact) != 0 {
				contacts = append(contacts, contact)
				contact = WhoisContact{}
			}
			continue
		} else if line[0] == '%' {
			// Comment/disclaimer -> skip.
			continue
		} else if strings.Index(line, ">>> last update of whois database") == 0 {
			// Last line -> break.
			if len(contact) != 0 {
				contacts = append(contacts, contact)
			}
			break
		}

		// Parse the individual parts.
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			// Invalid line -> skip.
			continue
		}

		key := strings.Trim(parts[0], " \n\r\t")
		value := strings.Trim(parts[1], " \n\r\t")
		if key == "" || value == "" {
			// No key/value -> skip.
			continue
		}

		if !SupportedWhoisProperties[key] {
			// Record not supported -> skip.
			continue
		}

		if contact[key] == "" {
			contact[key] = value
		} else {
			contact[key] += ", " + value
		}
	}

	return contacts
}

/////////////////////////////////////////
// WHOIS RESOLVER
/////////////////////////////////////////

// NewWhoisResolver creates a new WhoisResolver instance provisioned
// with sensible defaults.
func NewWhoisResolver() *WhoisResolver {
	return &WhoisResolver{
		Client: whois.NewClient(DefaultTimeout),
	}
}

// Type returns "WHOIS".
func (resolver *WhoisResolver) Type() ResolutionType {
	return TypeWHOIS
}

// ResolveDomain attempts to resolve a given domain using WHOIS query
// yielding a list of WHOIS contacts.
func (resolver *WhoisResolver) ResolveDomain(domain string) Resolution {
	resolution := &WhoisResolution{
		ResolutionBase: &ResolutionBase{query: domain},
	}

	// Prepare a request.
	request, err := whois.NewRequest(domain)
	if err != nil {
		LogErr("%s: %s -> %s", TypeWHOIS, domain, err.Error())
		return resolution
	}

	response, err := resolver.Client.Fetch(request)
	if err != nil {
		LogErr("%s: %s -> %s", TypeWHOIS, domain, err.Error())
		return resolution
	}

	contacts := parseWhoisResponse(bytes.NewReader(response.Body))
	for _, contact := range contacts {
		resolution.Contacts = append(resolution.Contacts, contact)
	}

	return resolution
}

/////////////////////////////////////////
// WHOIS RESOLUTION
/////////////////////////////////////////

// Type returns "WHOIS".
func (res *WhoisResolution) Type() ResolutionType {
	return TypeWHOIS
}

// Domains returns a list of domains discovered in records within this Resolution.
func (res *WhoisResolution) Domains() (domains []string) {
	for _, contact := range res.Contacts {
		for _, item := range contact {
			if extracted := dissectDomainsFromString(item); len(extracted) > 0 {
				domains = append(domains, extracted...)
			}
		}
	}
	return domains
}

/////////////////////////////////////////
// WHOIS CONTACT
/////////////////////////////////////////

func (contact *WhoisContact) String() string {
	cMap := map[string]string(*contact)
	var entries []string

	if cMap["name"] != "" {
		entries = append(entries, "name: "+cMap["name"])
	}
	if cMap["subject"] != "" {
		entries = append(entries, "subject: "+cMap["subject"])
	}
	if cMap["address"] != "" {
		entries = append(entries, "address: "+cMap["address"])
	}
	if cMap["registrant"] != "" {
		entries = append(entries, "registrant: "+cMap["registrant"])
	}
	if cMap["registrant organization"] != "" {
		entries = append(entries, "registrant organization: "+cMap["registrant organization"])
	}
	if cMap["registrant country"] != "" {
		entries = append(entries, "registrant country: "+cMap["registrant country"])
	} else if cMap["registrant state/province"] != "" {
		entries = append(entries, "registrant state/province: "+cMap["registrant state/province"])
	}

	if len(entries) == 0 {
		for key, val := range cMap {
			entries = append(entries, fmt.Sprintf("%s: %s", key, val))
		}
	}

	return strings.Join(entries, ", ")
}
