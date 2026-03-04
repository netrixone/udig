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
	nodeTypeRDAP    nodeType = "rdap"
	nodeTypeDNSBL   nodeType = "dnsbl"
	nodeTypeTor     nodeType = "tor"
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
			if dnsRes.Record.Signed {
				g.Nodes[query].Label = query + " 🔒"
			}

			if dnsRes.Record.RR != nil {
				rrType := dns.TypeToString[dnsRes.Record.RR.Header().Rrtype]
				label := "DNS/" + rrType
				data := dnsRes.Record.String()
				g.addEdges(query, udig.DissectDomainsFromString(data), label, nodeTypeDomain)
				g.addEdges(query, udig.DissectIpsFromString(data), label, nodeTypeIP)
			}

		case udig.TypeDMARC:
			g.addNode(query, nodeTypeDomain)
			g.addEdges(query, res.Domains(), "DMARC", nodeTypeDomain)

		case udig.TypeTLS:
			g.addNode(query, nodeTypeDomain)
			cert := &res.(*udig.TLSResolution).Record
			g.addEdges(query, udig.DissectDomainsFromStrings(cert.DNSNames), "TLS/SAN", nodeTypeDomain)
			g.addEdges(query, udig.DissectDomainsFromStrings(cert.CRLDistributionPoints), "TLS/CRL", nodeTypeDomain)
			g.addEdges(query, udig.DissectDomainsFromString(cert.Issuer.String()), "TLS/Issuer", nodeTypeDomain)
			g.addEdges(query, udig.DissectDomainsFromString(cert.Subject.CommonName), "TLS/CN", nodeTypeDomain)

		case udig.TypeCT:
			g.addNode(query, nodeTypeDomain)
			record := &res.(*udig.CTResolution).Record
			label := "CT"
			if !record.Active {
				label = "CT/expired"
			}
			g.addEdges(query, record.ExtractDomains(), label, nodeTypeDomain)

		case udig.TypeHTTP:
			g.addNode(query, nodeTypeDomain)
			record := &res.(*udig.HTTPResolution).Record
			g.addEdges(query, udig.DissectDomainsFromString(record.Value), "HTTP/"+record.Key, nodeTypeDomain)

		case udig.TypeWHOIS:
			whoisRes := res.(*udig.WhoisResolution)
			g.addEdges(query, res.Domains(), "WHOIS", nodeTypeDomain)
			recordStr := whoisRes.Record.String()
			g.addEdges(query, udig.DissectIpsFromString(recordStr), "WHOIS", nodeTypeIP)
			g.addEdge(query, formatWhoisContact(whoisRes.Record), "WHOIS/contact", nodeTypeWhois)

		case udig.TypeBGP:
			g.addNode(query, nodeTypeIP)
			record := &res.(*udig.BGPResolution).Record
			asNode := fmt.Sprintf("AS%d", record.ASN)
			if record.Name != "" {
				asNode = fmt.Sprintf("AS%d (%s)", record.ASN, record.Name)
			}
			label := "BGP"
			if record.BGPPrefix != "" {
				label = "BGP/" + record.BGPPrefix
			}
			g.addEdge(query, asNode, label, nodeTypeASN)

		case udig.TypeGEO:
			g.addNode(query, nodeTypeIP)
			geoRes := res.(*udig.GeoResolution)
			if geoRes.Record.CountryCode != "" {
				g.addEdge(query, geoRes.Record.CountryCode, "GEO", nodeTypeCountry)
			}

		case udig.TypePTR:
			g.addNode(query, nodeTypeIP)
			hostname := res.(*udig.PTRResolution).Record.Hostname
			if hostname != "" {
				g.addEdge(query, hostname, "PTR", nodeTypeDomain)
			}

		case udig.TypeRDAP:
			g.addNode(query, nodeTypeIP)
			rdapRes := res.(*udig.RDAPResolution)
			nodeID := rdapRes.Record.Name
			if nodeID == "" {
				nodeID = "RDAP/" + rdapRes.Record.Handle
			}
			if nodeID != "" && nodeID != "RDAP/" {
				g.addEdge(query, nodeID, "RDAP", nodeTypeRDAP)
			}

		case udig.TypeDNSBL:
			g.addNode(query, nodeTypeIP)
			record := res.(*udig.DNSBLResolution).Record
			zoneNode := fmt.Sprintf("%s (%s)", record.Zone, record.Meaning)
			g.addEdge(query, zoneNode, "DNSBL", nodeTypeDNSBL)

		case udig.TypeTor:
			g.addNode(query, nodeTypeIP)
			record := res.(*udig.TorResolution).Record
			label := "Tor Relay"
			if record.IsExitNode() {
				label = "Tor Exit Node"
			}
			if record.Nickname != "" {
				label = fmt.Sprintf("%s (%s)", label, record.Nickname)
			}
			g.addEdge(query, label, "TOR", nodeTypeTor)
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
