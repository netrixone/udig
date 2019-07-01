[![Build Status](https://travis-ci.com/netrixone/udig.svg?branch=master)](https://travis-ci.com/netrixone/udig)
[![Go Report Card](https://goreportcard.com/badge/github.com/netrixone/udig)](https://goreportcard.com/report/github.com/netrixone/udig)
[![Go Doc](https://godoc.org/github.com/netrixone/udig?status.svg)](https://godoc.org/github.com/netrixone/udig)
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fnetrixone%2Fudig.svg?type=shield)](https://app.fossa.io/projects/git%2Bgithub.com%2Fnetrixone%2Fudig?ref=badge_shield)

# ÜberDig - dig on steroids

**Simple GoLang tool for domain recon.**

The purpose of this tool is to provide fast overview of a target domain setup. Several active scanning techniques
are employed for this purpose like DNS ping-pong, TLS certificate scraping or WHOIS banner parsing. Some tools on the other
hand are not - intentionally (e.g. nmap, brute-force, search engines etc.). This is not a full-blown DNS enumerator, 
but rather something more unobtrusive and fast which can be deployed in long-term experiments with lots of targets.

_**DISCLAIMER:** This tool is still under heavy development and the API might change without any considerations!_

Feature set:

- [x] Resolves a given domain to all DNS records of interest
- [x] Resolves a given domain to a set of WHOIS contacts (selected properties only)
- [x] Resolves a given domain to a TLS certificate chain
- [x] Supports automatic NS discovery with custom override
- [x] Dissects domains from resolutions and resolves them recursively
- [x] CLI application supports JSON payload format
- [x] Supports multiple domains on the input
- [x] Colorized CLI output
- [x] Clean CLI output (e.g. RAW values, replace numeric constants with more meaningful strings)
- [ ] Resolves IPs and domains found in SPF record
- [ ] Resolves domains in CSP header
- [ ] Supports a web-crawler to enumerate sub-domains
- [ ] Supports parallel resolution of multiple domains at the same time

## Download as dependency

`go get github.com/netrixone/udig`

## Basic usage

```go
dig := udig.NewUdig()
resolutions := dig.Resolve("example.com")
for _, res := range resolutions {
	...
}
```

## CLI app

### Build

`make`

### Usage

```bash
udig [-h|--help] [-v|--version] [-V|--verbose] [--json] [-d|--domain
            "<value>" [-d|--domain "<value>" ...]]

            ÜberDig - dig on steroids v1.0 by stuchl4n3k

Arguments:

  -h  --help     Print help information
  -v  --version  Print version and exit
  -V  --verbose  Be more verbose
      --json     Output payloads as JSON objects
  -d  --domain   Domain to resolve
```

### Demo

![udig demo](doc/res/udig_demo.gif)

## Dependencies

* https://github.com/akamensky/argparse - Argparse for golang
* https://github.com/miekg/dns - DNS library in Go 
* https://github.com/domainr/whois - Whois client for Go

## License
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fnetrixone%2Fudig.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2Fnetrixone%2Fudig?ref=badge_large)