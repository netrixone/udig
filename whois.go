package udig

import (
	"bufio"
	"bytes"
	"github.com/domainr/whois"
	"io"
	"strings"
)

var (
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

/////////////////////////////////////////
// WHOIS RESOLVER
/////////////////////////////////////////

func NewWhoisResolver() *WhoisResolver {
	return &WhoisResolver{
		Client: whois.NewClient(DefaultTimeout),
	}
}

func (resolver *WhoisResolver) Resolve(domain string) *WhoisResolution {
	resolution := &WhoisResolution{
		Query: WhoisQuery{domain},
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
		resolution.Answers = append(resolution.Answers, contact)
	}

	return resolution
}

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
