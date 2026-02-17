package udig

import (
	"bufio"
	"bytes"
	"io"
	"strings"
	"time"

	"github.com/domainr/whois"
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
			break
		case "registrant":
			setOrAppendString(&(contact.Registrant), value)
			break
		case "registrant organization":
			setOrAppendString(&contact.RegistrantOrganization, value)
			break
		case "registrant state/province":
			setOrAppendString(&contact.RegistrantStateProvince, value)
			break
		case "registrant country":
			setOrAppendString(&contact.RegistrantCountry, value)
			break
		case "registrar":
			setOrAppendString(&contact.Registrar, value)
			break
		case "registrar iana id":
			setOrAppendString(&contact.RegistrarIanaId, value)
			break
		case "registrar whois server":
			setOrAppendString(&contact.RegistrarWhoisServer, value)
			break
		case "registrar url":
			setOrAppendString(&contact.RegistrarUrl, value)
			break
		case "creation date":
			setOrAppendString(&contact.CreationDate, value)
			break
		case "updated date":
			setOrAppendString(&contact.UpdatedDate, value)
			break
		case "registered":
			setOrAppendString(&contact.Registered, value)
			break
		case "changed":
			setOrAppendString(&contact.Changed, value)
			break
		case "expire":
			setOrAppendString(&contact.Expire, value)
			break
		case "nsset":
			setOrAppendString(&contact.NSSet, value)
			break
		case "contact":
			setOrAppendString(&contact.Contact, value)
			break
		case "name":
			setOrAppendString(&contact.Name, value)
			break
		case "address":
			setOrAppendString(&contact.Address, value)
			break
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
// yielding a list of WHOIS contacts.
func (r *WhoisResolver) ResolveDomain(domain string) Resolution {
	resolution := &WhoisResolution{
		ResolutionBase: &ResolutionBase{query: domain},
	}

	// Prepare a request.
	request, err := whois.NewRequest(domain)
	if err != nil {
		LogErr("%s: %s -> %s", TypeWHOIS, domain, err.Error())
		return resolution
	}

	response, err := r.Client.Fetch(request)
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
func (r *WhoisResolution) Type() ResolutionType {
	return TypeWHOIS
}

// Domains returns a list of domains discovered in records within this Resolution.
func (r *WhoisResolution) Domains() (domains []string) {
	for _, contact := range r.Contacts {
		domains = append(domains, DissectDomainsFromString(contact.RegistryDomainId)...)
		domains = append(domains, DissectDomainsFromString(contact.Registrant)...)
		domains = append(domains, DissectDomainsFromString(contact.RegistrantOrganization)...)
		domains = append(domains, DissectDomainsFromString(contact.RegistrantStateProvince)...)
		domains = append(domains, DissectDomainsFromString(contact.RegistrantCountry)...)
		domains = append(domains, DissectDomainsFromString(contact.Registrar)...)
		domains = append(domains, DissectDomainsFromString(contact.RegistrarIanaId)...)
		domains = append(domains, DissectDomainsFromString(contact.RegistrarWhoisServer)...)
		domains = append(domains, DissectDomainsFromString(contact.RegistrarUrl)...)
		domains = append(domains, DissectDomainsFromString(contact.CreationDate)...)
		domains = append(domains, DissectDomainsFromString(contact.UpdatedDate)...)
		domains = append(domains, DissectDomainsFromString(contact.Registered)...)
		domains = append(domains, DissectDomainsFromString(contact.Changed)...)
		domains = append(domains, DissectDomainsFromString(contact.Expire)...)
		domains = append(domains, DissectDomainsFromString(contact.NSSet)...)
		domains = append(domains, DissectDomainsFromString(contact.Contact)...)
		domains = append(domains, DissectDomainsFromString(contact.Name)...)
		domains = append(domains, DissectDomainsFromString(contact.Address)...)
	}
	return domains
}

/////////////////////////////////////////
// WHOIS CONTACT
/////////////////////////////////////////

func (c *WhoisContact) IsEmpty() bool {
	return c.RegistryDomainId == "" &&
		c.Registrant == "" &&
		c.RegistrantOrganization == "" &&
		c.RegistrantStateProvince == "" &&
		c.RegistrantCountry == "" &&
		c.Registrar == "" &&
		c.RegistrarIanaId == "" &&
		c.RegistrarWhoisServer == "" &&
		c.RegistrarUrl == "" &&
		c.CreationDate == "" &&
		c.UpdatedDate == "" &&
		c.Registered == "" &&
		c.Changed == "" &&
		c.Expire == "" &&
		c.NSSet == "" &&
		c.Contact == "" &&
		c.Name == "" &&
		c.Address == ""
}

func (c *WhoisContact) String() string {
	var entries []string

	if c.RegistryDomainId != "" {
		entries = append(entries, "registry domain id: "+c.RegistryDomainId)
	}
	if c.Registrant != "" {
		entries = append(entries, "registrant: "+c.Registrant)
	}
	if c.RegistrantOrganization != "" {
		entries = append(entries, "registrant organization: "+c.RegistrantOrganization)
	}
	if c.RegistrantStateProvince != "" {
		entries = append(entries, "registrant state/province: "+c.RegistrantStateProvince)
	}
	if c.RegistrantCountry != "" {
		entries = append(entries, "registrant country: "+c.RegistrantCountry)
	}
	if c.Registrar != "" {
		entries = append(entries, "registrar: "+c.Registrar)
	}
	if c.RegistrarIanaId != "" {
		entries = append(entries, "registrar iana id: "+c.RegistrarIanaId)
	}
	if c.RegistrarWhoisServer != "" {
		entries = append(entries, "registrar whois server: "+c.RegistrarWhoisServer)
	}
	if c.RegistrarUrl != "" {
		entries = append(entries, "registrar url: "+c.RegistrarUrl)
	}
	if c.CreationDate != "" {
		entries = append(entries, "creation date: "+c.CreationDate)
	}
	if c.UpdatedDate != "" {
		entries = append(entries, "updated date: "+c.UpdatedDate)
	}
	if c.Registered != "" {
		entries = append(entries, "registered: "+c.Registered)
	}
	if c.Changed != "" {
		entries = append(entries, "changed: "+c.Changed)
	}
	if c.Expire != "" {
		entries = append(entries, "expire: "+c.Expire)
	}
	if c.NSSet != "" {
		entries = append(entries, "nsset: "+c.NSSet)
	}
	if c.Contact != "" {
		entries = append(entries, "c: "+c.Contact)
	}
	if c.Name != "" {
		entries = append(entries, "name: "+c.Name)
	}
	if c.Address != "" {
		entries = append(entries, "address: "+c.Address)
	}

	return strings.Join(entries, ", ")
}
