package graph

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"github.com/netrixone/udig"
	"strings"
)

type nodeType string

const (
	nodeTypeDomain  nodeType = "domain"
	nodeTypeIP      nodeType = "ip"
	nodeTypeASN     nodeType = "asn"
	nodeTypeCountry nodeType = "country"
	nodeTypeWhois   nodeType = "whois"
)

func (t nodeType) String() string {
	return string(t)
}

type Graph struct {
	Root  string
	Nodes map[string]*Node
	Edges []*Edge
}

func New() *Graph {
	return &Graph{
		Nodes: make(map[string]*Node),
		Edges: make([]*Edge, 0),
	}
}

func (g *Graph) addNode(label string, nt nodeType) {
	if _, exists := g.Nodes[label]; !exists {
		g.Nodes[label] = &Node{
			Label: label,
			Type:  nt,
		}
	}
}

func (g *Graph) addEdges(from string, targets []string, label string, nt nodeType) {
	for _, to := range targets {
		g.addEdge(from, to, label, nt)
	}
}

func (g *Graph) addEdge(from, to, label string, nt nodeType) {
	if to == "" || to == from {
		return
	}

	// Make sure the target node exists.
	g.addNode(to, nt)

	g.Edges = append(g.Edges, &Edge{From: from, To: to, Label: label})
}

type Node struct {
	Label string
	Type  nodeType
}

type Edge struct {
	From  string
	To    string
	Label string
}

func (g *Graph) Collect(domain string, options []udig.Option) {
	g.Root = domain
	dig := udig.NewUdig(options...)
	resChan := dig.Resolve(context.Background(), domain)

	for res := range resChan {
		query := res.Query()

		switch res.Type() {
		case udig.TypeDNS:
			dnsRes := res.(*udig.DNSResolution)
			g.addNode(query, nodeTypeDomain)
			if dnsRes.Signed {
				g.Nodes[query].Label = query + " 🔒"
			}

			for _, rr := range dnsRes.Records {
				rrType := dns.TypeToString[rr.Record.RR.Header().Rrtype]
				label := "DNS/" + rrType
				data := rr.Record.String()
				g.addEdges(query, udig.DissectDomainsFromString(data), label, nodeTypeDomain)
				g.addEdges(query, udig.DissectIpsFromString(data), label, nodeTypeIP)
			}

		case udig.TypeTLS:
			g.addNode(query, nodeTypeDomain)
			for _, cert := range res.(*udig.TLSResolution).Certificates {
				g.addEdges(query, udig.DissectDomainsFromStrings(cert.DNSNames), "TLS/SAN", nodeTypeDomain)
				g.addEdges(query, udig.DissectDomainsFromStrings(cert.CRLDistributionPoints), "TLS/CRL", nodeTypeDomain)
				g.addEdges(query, udig.DissectDomainsFromString(cert.Issuer.String()), "TLS/Issuer", nodeTypeDomain)
				g.addEdges(query, udig.DissectDomainsFromString(cert.Subject.CommonName), "TLS/CN", nodeTypeDomain)
			}

		case udig.TypeCT:
			g.addNode(query, nodeTypeDomain)
			for _, log := range res.(*udig.CTResolution).Logs {
				label := "CT"
				if !log.Active {
					label = "CT/expired"
				}
				g.addEdges(query, log.ExtractDomains(), label, nodeTypeDomain)
			}

		case udig.TypeHTTP:
			g.addNode(query, nodeTypeDomain)
			for _, header := range res.(*udig.HTTPResolution).Headers {
				g.addEdges(query, udig.DissectDomainsFromStrings(header.Value), "HTTP/"+header.Name, nodeTypeDomain)
			}

		case udig.TypeWHOIS:
			whoisRes := res.(*udig.WhoisResolution)
			g.addEdges(query, res.Domains(), "WHOIS", nodeTypeDomain)

			for _, contact := range whoisRes.Contacts {
				contactStr := contact.String()
				g.addEdges(query, udig.DissectIpsFromString(contactStr), "WHOIS", nodeTypeIP)
				g.addEdge(query, formatWhoisContact(contact), "WHOIS/contact", nodeTypeWhois)
			}

		case udig.TypeBGP:
			g.addNode(query, nodeTypeIP)
			for _, as := range res.(*udig.BGPResolution).Records {
				asNode := fmt.Sprintf("AS%d", as.ASN)
				if as.Name != "" {
					asNode = fmt.Sprintf("AS%d (%s)", as.ASN, as.Name)
				}

				label := "BGP"
				if as.BGPPrefix != "" {
					label = "BGP/" + as.BGPPrefix
				}
				g.addEdge(query, asNode, label, nodeTypeASN)
			}

		case udig.TypeGEO:
			g.addNode(query, nodeTypeIP)
			geoRes := res.(*udig.GeoResolution)
			if geoRes.Record != nil && geoRes.Record.CountryCode != "" {
				g.addEdge(query, geoRes.Record.CountryCode, "GEO", nodeTypeCountry)
			}

		case udig.TypePTR:
			g.addNode(query, nodeTypeIP)
			g.addEdges(query, res.(*udig.PTRResolution).Hostnames, "PTR", nodeTypeDomain)
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
