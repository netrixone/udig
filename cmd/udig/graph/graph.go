package graph

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"github.com/netrixone/udig"
	"strings"
)

type graphNodeType string

const (
	graphNodeDomain  graphNodeType = "domain"
	graphNodeIP      graphNodeType = "ip"
	graphNodeASN     graphNodeType = "asn"
	graphNodeCountry graphNodeType = "country"
	graphNodeWhois   graphNodeType = "whois"
)

type Graph struct {
	Nodes map[string]graphNodeType
	Edges map[Edge]bool
	Seed  string // domain passed to Collect; used as root for terminal output
}

func New() *Graph {
	return &Graph{
		Nodes: make(map[string]graphNodeType),
		Edges: make(map[Edge]bool),
	}
}

func (g *Graph) setNode(id string, nt graphNodeType) {
	if _, exists := g.Nodes[id]; !exists {
		g.Nodes[id] = nt
	}
}

func (g *Graph) addEdges(from string, targets []string, nt graphNodeType, label string) {
	for _, t := range targets {
		if t != "" && t != from {
			g.setNode(t, nt)
			g.Edges[Edge{From: from, To: t, Label: label}] = true
		}
	}
}

func (g *Graph) addEdge(from, to, label string, nt graphNodeType) {
	if to == "" || to == from {
		return
	}
	g.setNode(to, nt)
	g.Edges[Edge{From: from, To: to, Label: label}] = true
}

type Edge struct {
	From  string
	To    string
	Label string
}

func (g *Graph) Collect(domain string, options []udig.Option) {
	g.Seed = domain
	dig := udig.NewUdig(options...)
	resChan := dig.Resolve(context.Background(), domain)

	for res := range resChan {
		q := res.Query()

		switch res.Type() {
		case udig.TypeDNS:
			g.setNode(q, graphNodeDomain)
			for _, rr := range res.(*udig.DNSResolution).Records {
				rrType := dns.TypeToString[rr.Record.RR.Header().Rrtype]
				label := "DNS/" + rrType
				data := rr.Record.String()
				g.addEdges(q, udig.DissectDomainsFromString(data), graphNodeDomain, label)
				g.addEdges(q, udig.DissectIpsFromString(data), graphNodeIP, label)
			}

		case udig.TypePTR:
			g.setNode(q, graphNodeIP)
			g.addEdges(q, res.(*udig.PTRResolution).Hostnames, graphNodeDomain, "PTR")

		case udig.TypeTLS:
			g.setNode(q, graphNodeDomain)
			for _, cert := range res.(*udig.TLSResolution).Certificates {
				g.addEdges(q, udig.DissectDomainsFromStrings(cert.DNSNames), graphNodeDomain, "TLS/SAN")
				g.addEdges(q, udig.DissectDomainsFromStrings(cert.CRLDistributionPoints), graphNodeDomain, "TLS/CRL")
				g.addEdges(q, udig.DissectDomainsFromString(cert.Issuer.String()), graphNodeDomain, "TLS/Issuer")
				g.addEdges(q, udig.DissectDomainsFromString(cert.Subject.CommonName), graphNodeDomain, "TLS/CN")
			}

		case udig.TypeCT:
			g.setNode(q, graphNodeDomain)
			for _, log := range res.(*udig.CTResolution).Logs {
				g.addEdges(q, log.ExtractDomains(), graphNodeDomain, "CT")
			}

		case udig.TypeHTTP:
			g.setNode(q, graphNodeDomain)
			for _, header := range res.(*udig.HTTPResolution).Headers {
				g.addEdges(q, udig.DissectDomainsFromStrings(header.Value), graphNodeDomain, "HTTP/"+header.Name)
			}

		case udig.TypeWHOIS:
			g.setNode(q, graphNodeDomain)
			whoisRes := res.(*udig.WhoisResolution)
			g.addEdges(q, res.Domains(), graphNodeDomain, "WHOIS")
			for _, contact := range whoisRes.Contacts {
				contactStr := contact.String()
				g.addEdges(q, udig.DissectIpsFromString(contactStr), graphNodeIP, "WHOIS")
				g.addEdge(q, formatWhoisContact(contact), "WHOIS/contact", graphNodeWhois)
			}

		case udig.TypeBGP:
			g.setNode(q, graphNodeIP)
			for _, as := range res.(*udig.BGPResolution).Records {
				asNode := fmt.Sprintf("AS%d", as.ASN)
				if as.Name != "" {
					asNode = fmt.Sprintf("AS%d (%s)", as.ASN, as.Name)
				}
				g.setNode(asNode, graphNodeASN)
				label := "BGP"
				if as.BGPPrefix != "" {
					label = "BGP/" + as.BGPPrefix
				}
				g.Edges[Edge{From: q, To: asNode, Label: label}] = true
			}

		case udig.TypeGEO:
			g.setNode(q, graphNodeIP)
			geoRes := res.(*udig.GeoResolution)
			if geoRes.Record != nil && geoRes.Record.CountryCode != "" {
				g.setNode(geoRes.Record.CountryCode, graphNodeCountry)
				g.Edges[Edge{From: q, To: geoRes.Record.CountryCode, Label: "GEO"}] = true
			}
		}
	}
}

func formatWhoisContact(c udig.WhoisContact) string {
	var entries []string

	if c.Name == "" && c.Address == "" && c.Contact == "" {
		return ""
	}

	if c.Registrar != "" {
		entries = append(entries, "reg: "+c.Registrar)
	}

	if c.Changed != "" {
		entries = append(entries, "since: "+c.Changed)
	} else if c.Registered != "" {
		entries = append(entries, "since: "+c.Registered)
	}

	contact := []string{}
	if c.Contact != "" {
		contact = append(contact, c.Contact)
	}
	if c.Name != "" {
		contact = append(contact, c.Name)
	}
	if c.Address != "" {
		contact = append(contact, c.Address)
	}

	if len(contact) > 0 {
		entries = append(entries, "contact: "+strings.Join(contact, ", "))
	}

	return strings.Join(entries, ", ")
}
