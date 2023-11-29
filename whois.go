package udig

import (
	"bufio"
	"bytes"
	"io"
	"strings"

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
		domains = append(domains, dissectDomainsFromString(contact.RegistryDomainId)...)
		domains = append(domains, dissectDomainsFromString(contact.Registrant)...)
		domains = append(domains, dissectDomainsFromString(contact.RegistrantOrganization)...)
		domains = append(domains, dissectDomainsFromString(contact.RegistrantStateProvince)...)
		domains = append(domains, dissectDomainsFromString(contact.RegistrantCountry)...)
		domains = append(domains, dissectDomainsFromString(contact.Registrar)...)
		domains = append(domains, dissectDomainsFromString(contact.RegistrarIanaId)...)
		domains = append(domains, dissectDomainsFromString(contact.RegistrarWhoisServer)...)
		domains = append(domains, dissectDomainsFromString(contact.RegistrarUrl)...)
		domains = append(domains, dissectDomainsFromString(contact.CreationDate)...)
		domains = append(domains, dissectDomainsFromString(contact.UpdatedDate)...)
		domains = append(domains, dissectDomainsFromString(contact.Registered)...)
		domains = append(domains, dissectDomainsFromString(contact.Changed)...)
		domains = append(domains, dissectDomainsFromString(contact.Expire)...)
		domains = append(domains, dissectDomainsFromString(contact.NSSet)...)
		domains = append(domains, dissectDomainsFromString(contact.Contact)...)
		domains = append(domains, dissectDomainsFromString(contact.Name)...)
		domains = append(domains, dissectDomainsFromString(contact.Address)...)
	}
	return domains
}

/////////////////////////////////////////
// WHOIS CONTACT
/////////////////////////////////////////

func (contact *WhoisContact) IsEmpty() bool {
	return contact.RegistryDomainId == "" &&
		contact.Registrant == "" &&
		contact.RegistrantOrganization == "" &&
		contact.RegistrantStateProvince == "" &&
		contact.RegistrantCountry == "" &&
		contact.Registrar == "" &&
		contact.RegistrarIanaId == "" &&
		contact.RegistrarWhoisServer == "" &&
		contact.RegistrarUrl == "" &&
		contact.CreationDate == "" &&
		contact.UpdatedDate == "" &&
		contact.Registered == "" &&
		contact.Changed == "" &&
		contact.Expire == "" &&
		contact.NSSet == "" &&
		contact.Contact == "" &&
		contact.Name == "" &&
		contact.Address == ""
}

func (contact *WhoisContact) String() string {
	var entries []string

	if contact.RegistryDomainId != "" {
		entries = append(entries, "registry domain id: "+contact.RegistryDomainId)
	}
	if contact.Registrant != "" {
		entries = append(entries, "registrant: "+contact.Registrant)
	}
	if contact.RegistrantOrganization != "" {
		entries = append(entries, "registrant organization: "+contact.RegistrantOrganization)
	}
	if contact.RegistrantStateProvince != "" {
		entries = append(entries, "registrant state/province: "+contact.RegistrantStateProvince)
	}
	if contact.RegistrantCountry != "" {
		entries = append(entries, "registrant country: "+contact.RegistrantCountry)
	}
	if contact.Registrar != "" {
		entries = append(entries, "registrar: "+contact.Registrar)
	}
	if contact.RegistrarIanaId != "" {
		entries = append(entries, "registrar iana id: "+contact.RegistrarIanaId)
	}
	if contact.RegistrarWhoisServer != "" {
		entries = append(entries, "registrar whois server: "+contact.RegistrarWhoisServer)
	}
	if contact.RegistrarUrl != "" {
		entries = append(entries, "registrar url: "+contact.RegistrarUrl)
	}
	if contact.CreationDate != "" {
		entries = append(entries, "creation date: "+contact.CreationDate)
	}
	if contact.UpdatedDate != "" {
		entries = append(entries, "updated date: "+contact.UpdatedDate)
	}
	if contact.Registered != "" {
		entries = append(entries, "registered: "+contact.Registered)
	}
	if contact.Changed != "" {
		entries = append(entries, "changed: "+contact.Changed)
	}
	if contact.Expire != "" {
		entries = append(entries, "expire: "+contact.Expire)
	}
	if contact.NSSet != "" {
		entries = append(entries, "nsset: "+contact.NSSet)
	}
	if contact.Contact != "" {
		entries = append(entries, "contact: "+contact.Contact)
	}
	if contact.Name != "" {
		entries = append(entries, "name: "+contact.Name)
	}
	if contact.Address != "" {
		entries = append(entries, "address: "+contact.Address)
	}

	return strings.Join(entries, ", ")
}
