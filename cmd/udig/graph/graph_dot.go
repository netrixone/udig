package graph

import (
	"fmt"
	"strings"
)

func dotEdgeStyle(label string) (color, fontcolor string) {
	switch {
	case strings.HasPrefix(label, "DNS/"):
		return "#89B4FA", "#89B4FA"

	case strings.HasPrefix(label, "TLS/"):
		return "#94E2D5", "#94E2D5"

	case label == "CT" || label == "CT/expired":
		return "#FAB387", "#FAB387"

	case strings.HasPrefix(label, "HTTP/"):
		return "#74C7EC", "#74C7EC"

	case strings.HasPrefix(label, "WHOIS"):
		return "#6C7086", "#9399B2"

	case strings.HasPrefix(label, "BGP"):
		return "#A6E3A1", "#A6E3A1"

	case label == "GEO":
		return "#CBA6F7", "#CBA6F7"

	default:
		return "#6C7086", "#9399B2"
	}
}

func (g *Graph) EmitDOT() {
	fmt.Print(`digraph udig {
	Graph [
		rankdir=LR,
		dpi=150,
		pad=0.5,
		ranksep=1.2,
		nodesep=0.4,
		splines=true,
		bgcolor="#1B1B1C"
	];
	node [
		fontname="Helvetica Neue,Helvetica,Arial,sans-serif",
		fontsize=11,
		shape=box,
		style="rounded,filled",
		penwidth=0,
		margin="0.2,0.08"
	];
	edge [
		fontname="Helvetica Neue,Helvetica,Arial,sans-serif",
		fontsize=9,
		penwidth=1.3,
		arrowsize=0.7
	];
`)

	for id, node := range g.Nodes {
		var attrs string
		switch node.Type {
		case nodeTypeIP:
			attrs = `fillcolor="#FAB387", fontcolor="#1B1B1C"`

		case nodeTypeASN:
			attrs = `fillcolor="#A6E3A1", fontcolor="#1B1B1C"`

		case nodeTypeCountry:
			attrs = `fillcolor="#CBA6F7", fontcolor="#1B1B1C"`

		case nodeTypeWhois:
			attrs = `fillcolor="#6C7086", fontcolor="#CDD6F4"`

		default:
			attrs = `fillcolor="#313244", fontcolor="#CDD6F4"`
		}

		fmt.Printf("\t%q [label=%q, %s];\n", id, node.Label, attrs)
	}

	for _, e := range g.Edges {
		ec, fc := dotEdgeStyle(e.Label)
		fmt.Printf("\t%q -> %q [label=%q, color=%q, fontcolor=%q];\n", e.From, e.To, e.Label, ec, fc)
	}

	fmt.Println("}")
}
