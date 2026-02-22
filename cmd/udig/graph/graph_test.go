package graph

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEmitDOT(t *testing.T) {
	g := makeTestGraph()
	out, err := captureStdout(t, g.EmitDOT)
	require.NoError(t, err)
	assert.Contains(t, out, "digraph udig")
	assert.Contains(t, out, `"example.com"`)
	assert.Contains(t, out, `"93.184.216.34"`)
	assert.Contains(t, out, `"US"`)
	assert.Contains(t, out, "DNS/A")
	assert.Contains(t, out, "GEO")
	assert.Contains(t, out, "->")
}

func TestEmitJSON(t *testing.T) {
	g := makeTestGraph()
	out, err := captureStdout(t, g.EmitJSON)
	require.NoError(t, err)

	var decoded struct {
		Nodes []struct {
			ID    string `json:"id"`
			Label string `json:"label"`
			Type  string `json:"type"`
		} `json:"nodes"`
		Edges []struct {
			Source string `json:"source"`
			Target string `json:"target"`
			Label  string `json:"label"`
		} `json:"edges"`
	}

	err = json.Unmarshal([]byte(out), &decoded)
	require.NoError(t, err)
	assert.Len(t, decoded.Nodes, 5)
	assert.Len(t, decoded.Edges, 4)

	ids := make(map[string]string)
	for _, n := range decoded.Nodes {
		ids[n.ID] = n.Type
	}

	assert.Equal(t, "domain", ids["example.com"])
	assert.Equal(t, "ip", ids["93.184.216.34"])
	assert.Equal(t, "country", ids["US"])

	var hasGeo bool
	for _, e := range decoded.Edges {
		if e.Label == "GEO" && e.Target == "US" {
			hasGeo = true
			break
		}
	}
	assert.True(t, hasGeo)
}

func TestEmitTerminal(t *testing.T) {
	g := makeTestGraph()
	out, err := captureStdout(t, g.EmitTerminal)
	require.NoError(t, err)

	assert.Contains(t, out, "example.com")
	assert.Contains(t, out, "93.184.216.34")
	assert.Contains(t, out, "US")
	assert.Contains(t, out, "├──")
	assert.Contains(t, out, "└──")
	assert.Contains(t, out, "[DNS/A]")
	assert.Contains(t, out, "[GEO]")
}

func TestEmitTerminal_emptySeed(t *testing.T) {
	g := New()
	g.Nodes["orphan.com"] = &Node{Label: "orphan.com", Type: nodeTypeDomain}
	out, err := captureStdout(t, g.EmitTerminal)
	require.NoError(t, err)

	assert.Empty(t, out)
}

func TestEmitTerminal_sharedLeaf(t *testing.T) {
	g := makeTestGraphSharedLeaf()
	out, err := captureStdout(t, g.EmitTerminal)
	require.NoError(t, err)

	// Both IPs should show US [GEO] as child (shared-leaf behavior).
	assert.Contains(t, out, "1.2.3.4")
	assert.Contains(t, out, "5.6.7.8")

	// Count occurrences of "US" as a line label (under each IP).
	lines := strings.Split(out, "\n")
	usWithGeo := 0
	for _, line := range lines {
		if strings.Contains(line, "US") && strings.Contains(line, "GEO") {
			usWithGeo++
		}
	}
	assert.GreaterOrEqual(t, usWithGeo, 2, "shared leaf US should appear under both IPs")
}

// makeTestGraph builds a small graph in memory (no resolution). Root is "example.com"
// with one IP, one ASN, one country, and one child domain.
func makeTestGraph() *Graph {
	g := New()
	g.Root = "example.com"
	g.Nodes["example.com"] = &Node{Label: "example.com", Type: nodeTypeDomain}
	g.Nodes["93.184.216.34"] = &Node{Label: "93.184.216.34", Type: nodeTypeIP}
	g.Nodes["AS15133 (MCI)"] = &Node{Label: "AS15133 (MCI)", Type: nodeTypeASN}
	g.Nodes["US"] = &Node{Label: "US", Type: nodeTypeCountry}
	g.Nodes["ns.example.com"] = &Node{Label: "ns.example.com", Type: nodeTypeDomain}
	g.Edges = append(g.Edges, &Edge{From: "example.com", To: "93.184.216.34", Label: "DNS/A"})
	g.Edges = append(g.Edges, &Edge{From: "example.com", To: "ns.example.com", Label: "DNS/NS"})
	g.Edges = append(g.Edges, &Edge{From: "93.184.216.34", To: "AS15133 (MCI)", Label: "BGP/93.184.0.0/16"})
	g.Edges = append(g.Edges, &Edge{From: "93.184.216.34", To: "US", Label: "GEO"})
	return g
}

// makeTestGraphSharedLeaf builds a graph where two IPs point to the same country (shared leaf).
func makeTestGraphSharedLeaf() *Graph {
	g := New()
	g.Root = "example.com"
	g.Nodes["example.com"] = &Node{Label: "example.com", Type: nodeTypeDomain}
	g.Nodes["1.2.3.4"] = &Node{Label: "1.2.3.4", Type: nodeTypeIP}
	g.Nodes["5.6.7.8"] = &Node{Label: "5.6.7.8", Type: nodeTypeIP}
	g.Nodes["US"] = &Node{Label: "US", Type: nodeTypeCountry}
	g.Edges = append(g.Edges, &Edge{From: "example.com", To: "1.2.3.4", Label: "DNS/A"})
	g.Edges = append(g.Edges, &Edge{From: "example.com", To: "5.6.7.8", Label: "DNS/A"})
	g.Edges = append(g.Edges, &Edge{From: "1.2.3.4", To: "US", Label: "GEO"})
	g.Edges = append(g.Edges, &Edge{From: "5.6.7.8", To: "US", Label: "GEO"})
	return g
}

func captureStdout(t *testing.T, outputProducer func()) (string, error) {
	t.Helper()

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		return "", err
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()

	outputProducer()

	_ = w.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)

	return buf.String(), nil
}
