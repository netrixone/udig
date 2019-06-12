package main

import (
	"encoding/json"
	"fmt"
	"github.com/akamensky/argparse"
	"net/url"
	"os"
	"sync"
	"udig"
)

const prog = "udig"
const version = "1.0"
const author = "stuchl4n3k"
const description = "ÜberDig - dig on steroids v" + version + " by " + author

var banner = `
 _   _ ____ ___ ____
(_) (_|  _ |_ _/ ___|
| | | | | | | | |  _
| |_| | |_| | | |_| |
 \__,_|____|___\____| v`[1:] + version + `
`

func resolveAll(domain string) {
	// Some input checks.
	if !isValidDomain(domain) {
		udig.LogErr("'%s' does not appear like a valid domain to me -> skipping.", domain)
		return
	}

	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		resolveDns(domain)
	}()
	go func() {
		defer wg.Done()
		resolveWhois(domain)
	}()
	go func() {
		defer wg.Done()
		resolveTls(domain)
	}()

	wg.Wait()
}

func resolveDns(domain string) {
	resolver := udig.NewDnsResolver()
	resolutions := resolver.Resolve(domain)

	for _, res := range resolutions {
		for _, answer := range res.Answers {
			jsonValue, _ := json.Marshal(answer)
			udig.LogInfo("%s: %s %s -> %s", res.Type(), res.Query.Type, res.Query.Domain, jsonValue)
		}
	}
}

func resolveWhois(domain string) {
	resolver := udig.NewWhoisResolver()
	res := resolver.Resolve(domain)

	for _, contact := range res.Answers {
		jsonValue, _ := json.Marshal(contact)
		udig.LogInfo("%s: %s -> %s", res.Type(), res.Query.Domain, jsonValue)
	}
}

func resolveTls(domain string) {
	resolver := udig.NewTlsResolver()
	res := resolver.Resolve(domain)

	for _, cert := range res.Answers {
		jsonValue, _ := json.Marshal(cert)
		udig.LogInfo("%s: %s -> %s", res.Type(), res.Query.Domain, jsonValue)
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

func main() {
	parser := argparse.NewParser(prog, description)
	printVersion := parser.Flag("v", "version", &argparse.Options{Required: false, Help: "Print version and exit"})
	beVerbose := parser.Flag("V", "verbose", &argparse.Options{Required: false, Help: "Be more verbose"})
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

	fmt.Println(banner)

	// Resolve all domains (sequentially).
	// @todo: goroutine this with a concurrency limiter
	for _, domain := range *domains {
		resolveAll(domain)
	}
}
