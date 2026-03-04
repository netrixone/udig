package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/netrixone/udig/cmd/udig/graph"
	"net/url"
	"os"
	"time"

	"github.com/akamensky/argparse"
	"github.com/miekg/dns"
	"github.com/netrixone/udig"
)

const (
	prog        = "udig"
	version     = "1.6"
	author      = "stuchl4n3k"
	description = "ÜberDig - dig on steroids v" + version + " by " + author
)

var (
	banner = `
 _   _ ____ ___ ____
(_) (_|  _ |_ _/ ___|
| | | | | | | | |  _
| |_| | |_| | | |_| |
 \__,_|____|___\____| v`[1:] + version + `
`
)
var outputJson = false

func resolve(domain string, options []udig.Option) {
	dig := udig.NewUdig(options...)
	resChan := dig.Resolve(context.Background(), domain)

	for res := range resChan {
		switch res.Type() {
		case udig.TypeDNS:
			record := res.(*udig.DNSResolution).Record
			signed := ""
			if record.Signed {
				signed = " [DNSSEC]"
			}
			udig.LogInfo("%s: %s %s -> %s%s", res.Type(), dns.TypeToString[record.QueryType], res.Query(), formatRecord(record), signed)

		case udig.TypeDMARC:
			record := res.(*udig.DMARCResolution).Record
			udig.LogInfo("%s: %s -> %s", res.Type(), res.Query(), formatRecord(record))

		case udig.TypePTR:
			record := res.(*udig.PTRResolution).Record
			udig.LogInfo("%s: %s -> %s", res.Type(), res.Query(), record)

		case udig.TypeTLS:
			record := &res.(*udig.TLSResolution).Record
			udig.LogInfo("%s: %s -> %s", res.Type(), res.Query(), formatRecord(record))

		case udig.TypeWHOIS:
			record := &res.(*udig.WhoisResolution).Record
			udig.LogInfo("%s: %s -> %s", res.Type(), res.Query(), formatRecord(record))

		case udig.TypeHTTP:
			record := &res.(*udig.HTTPResolution).Record
			udig.LogInfo("%s: %s -> %s", res.Type(), res.Query(), formatRecord(record))

		case udig.TypeCT:
			record := &res.(*udig.CTResolution).Record
			udig.LogInfo("%s: %s -> %s", res.Type(), res.Query(), formatRecord(record))

		case udig.TypeBGP:
			record := &res.(*udig.BGPResolution).Record
			udig.LogInfo("%s: %s -> %s", res.Type(), res.Query(), formatRecord(record))

		case udig.TypeGEO:
			record := &res.(*udig.GeoResolution).Record
			udig.LogInfo("%s: %s -> %s", res.Type(), res.Query(), formatRecord(record))

		case udig.TypeRDAP:
			record := &res.(*udig.RDAPResolution).Record
			udig.LogInfo("%s: %s -> %s", res.Type(), res.Query(), formatRecord(record))

		case udig.TypeDNSBL:
			record := &res.(*udig.DNSBLResolution).Record
			udig.LogInfo("%s: %s -> %s", res.Type(), res.Query(), formatRecord(record))

		case udig.TypeTor:
			record := &res.(*udig.TorResolution).Record
			udig.LogInfo("%s: %s -> %s", res.Type(), res.Query(), formatRecord(record))
		}
	}
}

func isValidDomain(domain string) bool {
	if len(domain) == 0 {
		return false
	}

	if _, err := url.Parse("https://" + domain); err != nil {
		return false
	}

	return true
}

func formatRecord(record interface{}) string {
	if outputJson {
		result, _ := json.Marshal(record)
		return string(result)
	}
	return fmt.Sprintf("%s", record)
}

func main() {
	parser := argparse.NewParser(prog, description)
	printVersion := parser.Flag("v", "version", &argparse.Options{Required: false, Help: "Print version and exit"})
	beVerbose := parser.Flag("V", "verbose", &argparse.Options{Required: false, Help: "Be more verbose"})
	beStrict := parser.Flag("s", "strict", &argparse.Options{Required: false, Help: "Strict domain relation (TLD match)"})
	domain := parser.String("d", "domain", &argparse.Options{Required: false, Help: "Domain to resolve", Validate: func(args []string) error {
		if !isValidDomain(args[0]) {
			return fmt.Errorf("'%s' is not a valid domain", args[0])
		}
		return nil
	}})
	timeout := parser.String("t", "timeout", &argparse.Options{
		Required: false,
		Help:     "Connection timeout",
		Default:  udig.DefaultTimeout.String(),
		Validate: func(args []string) error {
			_, err := time.ParseDuration(args[0])
			return err
		},
	})
	ctExpired := parser.Flag("", "ct:expired", &argparse.Options{Required: false, Help: "Collect expired CT logs"})
	ctFrom := parser.String("", "ct:from", &argparse.Options{
		Required: false,
		Help:     "Date to collect logs from in YYYY-MM-DD format",
		Default:  fmt.Sprintf("1 year ago (%s)", time.Now().AddDate(-1, 0, 0).Format("2006-01-02")),
		Validate: func(args []string) error {
			_, err := time.Parse("2006-01-02", args[0])
			return err
		},
	})
	jsonOutput := parser.Flag("", "json", &argparse.Options{Required: false, Help: "Output payloads as JSON objects"})
	graphFormat := parser.Selector("g", "graph", []string{"term", "dot", "json"}, &argparse.Options{
		Required: false,
		Help:     "Emit resolution graph (dot, json, or term). DOT output is limited to 200 nodes.",
	})
	maxDepth := parser.Int("", "max-depth", &argparse.Options{
		Required: false,
		Help:     "Max recursion depth (-1 = unlimited, 0 = seed only)",
		Default:  -1,
	})

	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Fprint(os.Stderr, parser.Usage(err))
		os.Exit(1)
	}

	if *printVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	if len(*domain) == 0 {
		fmt.Fprint(os.Stderr, parser.Usage(err))
		os.Exit(1)
	}

	options := make([]udig.Option, 0)
	if *beVerbose {
		options = append(options, udig.WithDebugLogging())
	}

	if *beStrict {
		options = append(options, udig.WithStrictMode())
	}

	if *timeout != "" {
		// Note: already validated value.
		t, _ := time.ParseDuration(*timeout)
		options = append(options, udig.WithTimeout(t))
	}

	if *ctExpired {
		options = append(options, udig.WithCTExpired())
	}

	if *ctFrom != "" {
		// Note: already validated value.
		since, _ := time.Parse("2006-01-02", *ctFrom)
		options = append(options, udig.WithCTSince(since))
	}

	if *maxDepth >= 0 {
		options = append(options, udig.WithMaxDepth(*maxDepth))
	}

	outputJson = *jsonOutput

	if *graphFormat != "" {
		g := graph.New()
		g.Collect(*domain, options)
		switch *graphFormat {
		case "json":
			g.EmitJSON()
		case "term":
			g.EmitTerminal()
		default:
			if err = g.EmitDOT(); err != nil {
				udig.LogPanic("Error: %s", err)
			}
		}
	} else {
		fmt.Println(banner)
		resolve(*domain, options)
	}
}
