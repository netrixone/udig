package udig

import (
	"bufio"
	"bytes"
	"github.com/domainr/whois"
	"io"
	"strings"
	"time"
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
			if !contact.IsEmpty() {
				contacts = append(contacts, contact)
				contact = WhoisContact{}
			}
			continue
		} else if line[0] == '%' {
			// Comment/disclaimer -> skip.
			continue
		} else if strings.Index(line, ">>> last update of whois database") == 0 {
			// Last line -> break.
			if !contact.IsEmpty() {
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

		switch key {
		case "registry domain id":
			setOrAppendString(&contact.RegistryDomainId, value)

		case "registrant":
			setOrAppendString(&(contact.Registrant), value)

		case "registrant organization":
			setOrAppendString(&contact.RegistrantOrganization, value)

		case "registrant state/province":
			setOrAppendString(&contact.RegistrantStateProvince, value)

		case "registrant country":
			setOrAppendString(&contact.RegistrantCountry, value)

		case "registrar":
			setOrAppendString(&contact.Registrar, value)

		case "registrar iana id":
			setOrAppendString(&contact.RegistrarIanaId, value)

		case "registrar whois server":
			setOrAppendString(&contact.RegistrarWhoisServer, value)

		case "registrar url":
			setOrAppendString(&contact.RegistrarUrl, value)

		case "creation date":
			setOrAppendString(&contact.CreationDate, value)

		case "updated date":
			setOrAppendString(&contact.UpdatedDate, value)

		case "registered":
			setOrAppendString(&contact.Registered, value)

		case "changed":
			setOrAppendString(&contact.Changed, value)

		case "expire":
			setOrAppendString(&contact.Expire, value)

		case "nsset":
			setOrAppendString(&contact.NSSet, value)

		case "contact":
			setOrAppendString(&contact.Contact, value)

		case "name":
			setOrAppendString(&contact.Name, value)

		case "address":
			setOrAppendString(&contact.Address, value)

		}
	}

	return contacts
}

func setOrAppendString(target *string, value string) {
	if *target != "" {
		value = *target + ", " + value
	}
	*target = value
}

/////////////////////////////////////////
// WHOIS RESOLVER
/////////////////////////////////////////

// WhoisResolver is a Resolver responsible for resolution of a given
// domain to a list of WHOIS contacts.
type WhoisResolver struct {
	Client *whois.Client
}

// NewWhoisResolver creates a new WhoisResolver instance provisioned
// with sensible defaults.
func NewWhoisResolver(timeout time.Duration) *WhoisResolver {
	return &WhoisResolver{
		Client: whois.NewClient(timeout),
	}
}

// Type returns "WHOIS".
func (r *WhoisResolver) Type() ResolutionType {
	return TypeWHOIS
}

// ResolveDomain attempts to resolve a given domain using WHOIS query
// yielding one resolution per WHOIS contact found.
func (r *WhoisResolver) ResolveDomain(domain string) []Resolution {
	request, err := whois.NewRequest(domain)
	if err != nil {
		LogErr("%s: %s -> %s", TypeWHOIS, domain, err.Error())
		return nil
	}

	response, err := r.Client.Fetch(request)
	if err != nil {
		LogErr("%s: %s -> %s", TypeWHOIS, domain, err.Error())
		return nil
	}

	contacts := parseWhoisResponse(bytes.NewReader(response.Body))

	var results []Resolution
	for _, contact := range contacts {
		results = append(results, &WhoisResolution{
			ResolutionBase: &ResolutionBase{query: domain},
			Record:         contact,
		})
	}
	return results
}
