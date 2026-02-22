package graph

import (
	"encoding/json"
	"os"
)

// JSON Graph structure (nodes + edges with source/target) compatible with D3, Cytoscape, and similar tools.
type jsonGraphNode struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Type  string `json:"type"`
}

type jsonGraphEdge struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Label  string `json:"label"`
}

type jsonGraph struct {
	Nodes []jsonGraphNode `json:"nodes"`
	Edges []jsonGraphEdge `json:"edges"`
}

func (g *Graph) EmitJSON() {
	jsonNodes := make([]jsonGraphNode, 0, len(g.Nodes))
	for _, node := range g.Nodes {
		jsonNodes = append(jsonNodes, jsonGraphNode{
			ID:    node.Label,
			Label: node.Label,
			Type:  node.Type.String(),
		})
	}

	jsonEdges := make([]jsonGraphEdge, 0, len(g.Edges))
	for _, e := range g.Edges {
		jsonEdges = append(jsonEdges, jsonGraphEdge{
			Source: e.From,
			Target: e.To,
			Label:  e.Label,
		})
	}

	out := jsonGraph{Nodes: jsonNodes, Edges: jsonEdges}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(out)
}
