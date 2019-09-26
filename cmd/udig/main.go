package main

import (
	"encoding/json"
	"fmt"
	"github.com/akamensky/argparse"
	"github.com/miekg/dns"
	"github.com/netrixone/udig"
	"net/url"
	"os"
)

const (
	prog        = "udig"
	version     = "1.2"
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

func resolveAll(domain string) {
	// Some input checks.
	if !isValidDomain(domain) {
		udig.LogErr("'%s' does not appear like a valid domain to me -> skipping.", domain)
		return
	}

	dig := udig.NewUdig()
	resolutions := dig.Resolve(domain)

	for _, res := range resolutions {
		switch res.Type() {
		case udig.TypeDNS:
			for _, rr := range (res).(*udig.DNSResolution).Records {
				udig.LogInfo("%s: %s %s -> %s", res.Type(), dns.TypeToString[rr.QueryType], res.Query(), formatPayload(rr.Record))
			}
			break

		case udig.TypeTLS:
			for _, cert := range (res).(*udig.TLSResolution).Certificates {
				udig.LogInfo("%s: %s -> %s", res.Type(), res.Query(), formatPayload(&cert))
			}
			break

		case udig.TypeWHOIS:
			for _, contact := range (res).(*udig.WhoisResolution).Contacts {
				udig.LogInfo("%s: %s -> %s", res.Type(), res.Query(), formatPayload(&contact))
			}
			break

		case udig.TypeHTTP:
			for _, header := range (res).(*udig.HTTPResolution).Headers {
				udig.LogInfo("%s: %s -> %s", res.Type(), res.Query(), formatPayload(&header))
			}
			break
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

func formatPayload(resolution fmt.Stringer) string {
	if outputJson {
		result, _ := json.Marshal(resolution)
		return string(result)
	} else {
		return resolution.String()
	}
}

func main() {
	parser := argparse.NewParser(prog, description)
	printVersion := parser.Flag("v", "version", &argparse.Options{Required: false, Help: "Print version and exit"})
	beVerbose := parser.Flag("V", "verbose", &argparse.Options{Required: false, Help: "Be more verbose"})
	jsonOutput := parser.Flag("", "json", &argparse.Options{Required: false, Help: "Output payloads as JSON objects"})
	domains := parser.List("d", "domain", &argparse.Options{Required: false, Help: "Domain to resolve"})

	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Fprint(os.Stderr, parser.Usage(err))
		os.Exit(1)
	}

	if *printVersion {
		fmt.Println(version)
		os.Exit(0)
	} else if len(*domains) == 0 {
		fmt.Fprint(os.Stderr, parser.Usage(err))
		os.Exit(1)
	}

	if *beVerbose {
		udig.LogLevel = udig.LogLevelDebug
	} else {
		udig.LogLevel = udig.LogLevelInfo
	}

	outputJson = *jsonOutput

	fmt.Println(banner)

	// Resolve all domains (sequentially).
	// @todo: goroutine this with a concurrency limiter
	for _, domain := range *domains {
		resolveAll(domain)
	}
}
