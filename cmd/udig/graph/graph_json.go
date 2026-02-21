package graph

import (
	"encoding/json"
	"os"
	"sort"
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
	nodeIDs := make([]string, 0, len(g.Nodes))
	for id := range g.Nodes {
		nodeIDs = append(nodeIDs, id)
	}
	sort.Strings(nodeIDs)

	outNodes := make([]jsonGraphNode, 0, len(g.Nodes))
	for _, id := range nodeIDs {
		outNodes = append(outNodes, jsonGraphNode{
			ID:    id,
			Label: id,
			Type:  string(g.Nodes[id]),
		})
	}

	edgeSlice := make([]Edge, 0, len(g.Edges))
	for e := range g.Edges {
		edgeSlice = append(edgeSlice, e)
	}
	sort.Slice(edgeSlice, func(i, j int) bool {
		a, b := edgeSlice[i], edgeSlice[j]
		if a.From != b.From {
			return a.From < b.From
		}
		if a.To != b.To {
			return a.To < b.To
		}
		return a.Label < b.Label
	})

	outEdges := make([]jsonGraphEdge, 0, len(edgeSlice))
	for _, e := range edgeSlice {
		outEdges = append(outEdges, jsonGraphEdge{Source: e.From, Target: e.To, Label: e.Label})
	}

	out := jsonGraph{Nodes: outNodes, Edges: outEdges}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(out)
}
