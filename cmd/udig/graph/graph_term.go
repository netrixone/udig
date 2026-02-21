package graph

import (
	"fmt"
	"os"
	"sort"
)

const (
	termReset   = "\033[0m"
	termCyan    = "\033[1;36m"
	termGreen   = "\033[1;32m"
	termMagenta = "\033[1;35m"
)

// isSharedLeaf returns true for node types that are shared singletons (country codes,
// ASN labels) which should appear under every parent that points to them.
func (t graphNodeType) isSharedLeaf() bool {
	return t == graphNodeCountry || t == graphNodeASN
}

func (t graphNodeType) termColor() string {
	switch t {
	case graphNodeIP:
		return termCyan
	case graphNodeASN:
		return termGreen
	case graphNodeCountry:
		return termMagenta
	default:
		return termReset
	}
}

// EmitTerminal renders the Graph as a tree in the terminal using Unicode box-drawing
// and optional ANSI colors. The root is the seed domain from Collect. BFS avoids cycles.
func (g *Graph) EmitTerminal() {
	if g.Seed == "" {
		return
	}
	adj := g.buildTermAdjacency()
	treeEdges := g.bfsTree(adj)
	treeMap := buildTreeMap(treeEdges)
	printTermNode(g, g.Seed, "")
	printTermSubtree(g, treeMap, g.Seed, "")
}

type termEdge struct {
	To    string
	Label string
}

func (g *Graph) buildTermAdjacency() map[string][]termEdge {
	adj := make(map[string][]termEdge)
	for e := range g.Edges {
		adj[e.From] = append(adj[e.From], termEdge{To: e.To, Label: e.Label})
	}
	for from := range adj {
		sort.Slice(adj[from], func(i, j int) bool {
			a, b := adj[from][i], adj[from][j]
			if a.To != b.To {
				return a.To < b.To
			}
			return a.Label < b.Label
		})
	}
	return adj
}

// bfsTree returns tree edges (parent, child, label) reachable from seed.
// Shared-leaf nodes (country, ASN) are duplicated under each parent so every
// IP keeps its GEO/BGP children; all other nodes appear at most once.
func (g *Graph) bfsTree(adj map[string][]termEdge) []struct{ From, To, Label string } {
	visited := map[string]bool{g.Seed: true}
	var queue []string
	queue = append(queue, g.Seed)
	var edges []struct{ From, To, Label string }

	for len(queue) > 0 {
		from := queue[0]
		queue = queue[1:]

		for _, e := range adj[from] {
			if visited[e.To] && !g.Nodes[e.To].isSharedLeaf() {
				continue
			}
			if !visited[e.To] {
				visited[e.To] = true
				queue = append(queue, e.To)
			}
			edges = append(edges, struct{ From, To, Label string }{from, e.To, e.Label})
		}
	}
	return edges
}

// buildTreeMap returns parent -> sorted (child, label) for the BFS tree.
func buildTreeMap(treeEdges []struct{ From, To, Label string }) map[string][]termEdge {
	out := make(map[string][]termEdge)
	for _, e := range treeEdges {
		out[e.From] = append(out[e.From], termEdge{To: e.To, Label: e.Label})
	}

	for parent := range out {
		sort.Slice(out[parent], func(i, j int) bool {
			a, b := out[parent][i], out[parent][j]
			if a.To != b.To {
				return a.To < b.To
			}
			return a.Label < b.Label
		})
	}
	return out
}

func printTermNode(g *Graph, id string, label string) {
	color := g.Nodes[id].termColor()
	if color != termReset {
		_, _ = fmt.Fprint(os.Stdout, color)
	}

	_, _ = fmt.Fprint(os.Stdout, id)

	if color != termReset {
		_, _ = fmt.Fprint(os.Stdout, termReset)
	}

	if label != "" {
		_, _ = fmt.Fprintf(os.Stdout, "  [%s]", label)
	}

	_, _ = fmt.Fprintln(os.Stdout)
}

func printTermSubtree(g *Graph, treeMap map[string][]termEdge, parent string, prefix string) {
	children := treeMap[parent]
	for i, c := range children {
		var branch, nextPrefix string
		if i == len(children)-1 {
			branch = "└── "
			nextPrefix = prefix + "    "
		} else {
			branch = "├── "
			nextPrefix = prefix + "│   "
		}

		_, _ = fmt.Fprint(os.Stdout, prefix, branch)
		printTermNode(g, c.To, c.Label)
		printTermSubtree(g, treeMap, c.To, nextPrefix)
	}
}
