[![Build Status](https://travis-ci.com/netrixone/udig.svg?branch=master)](https://travis-ci.com/netrixone/udig)
[![Go Report Card](https://goreportcard.com/badge/github.com/netrixone/udig)](https://goreportcard.com/report/github.com/netrixone/udig)
[![Go Doc](https://godoc.org/github.com/netrixone/udig?status.svg)](https://godoc.org/github.com/netrixone/udig)
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fnetrixone%2Fudig.svg?type=shield)](https://app.fossa.io/projects/git%2Bgithub.com%2Fnetrixone%2Fudig?ref=badge_shield)

# ÜberDig - dig on steroids

**Simple GoLang tool for domain recon.**

The purpose of this tool is to provide fast overview of a target domain setup. Several active scanning techniques
are employed for this purpose like DNS ping-pong, TLS certificate scraping, WHOIS banner parsing and more. 
Some tools on the other hand are not - intentionally (e.g. nmap, brute-force, search engines etc.). This is not 
a full-blown DNS enumerator, but rather something more unobtrusive and fast which can be deployed in long-term 
experiments with lots of targets.

Feature set:

- [x] Resolves a given domain to all DNS records of interest
- [x] Resolves a given domain to a set of WHOIS contacts (selected properties only)
- [x] Resolves a given domain to a TLS certificate chain
- [x] Supports automatic NS discovery with custom override
- [x] Dissects domains from resolutions and resolves them recursively
- [x] Unobtrusive human-readable CLI output as well as machine readable JSON
- [x] Supports multiple domains on the input
- [x] Colorized output
- [x] Resolves domains in HTTP headers
- [x] Parses IPs found in SPF record
- [x] Looks up BGP AS for each discovered IP
- [x] Looks up GeoIP record for each discovered IP
- [ ] Attempts to detect DNS wildcards
- [ ] Supports graph output

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

## API

```
                                                         +------------+
                                                         |            |
                                                  +------+    Udig    +------------+
Delegates:                                        |      |            |            |
                                                  |      +------------+            |
                                                  |*                               |*
                                      +------------------+                  +------------+
                                      |  DomainResolver  |                  | IPResolver |
             +----------------------> +------------------+                  +------------+
             |                        ^      ^           ^                         ^     ^
Implements:  |                  +-----+      |           |                         |     +-------+
             |                  |            |           |                         |             |
     +-------------+ +-------------+ +--------------+ +---------------+        +-------------+ +---------------+
     | DNSResolver | | TLSResolver | | HTTPResolver | | WhoisResolver |        | BGPResolver | | GeoipResolver |
     +-------------+ +-------------+ +--------------+ +---------------+        +-------------+ +---------------+
             |              |                |               |                        |                |
             |              |                |               |                        |                |
Produces:    |              |                |               |                        |                |
             |              |                |               |                        |                |
             |*             |*               |*              |*                       |*               |*
      +-----------+ +----------------+ +------------+ +--------------+           +----------+   +-------------+
      | DNSRecord | | TLSCertificate | | HTTPHeader | | WhoisContact |           | ASRecord |   | GeoipRecord |
      +-----------+ +----------------+ +------------+ +--------------+           +----------+   +-------------+

```

## CLI app

### Download app

`go get github.com/netrixone/udig/cmd/udig`

### Build from the sources

`make` or `make install`

This will also download the latest GeoIP database (IPLocation-lite).

### Usage

```bash
udig [-h|--help] [-v|--version] [-V|--verbose] [--json] [-d|--domain "<value>"]

            ÜberDig - dig on steroids v1.3 by stuchl4n3k

Arguments:

  -h  --help     Print help information
  -v  --version  Print version and exit
  -V  --verbose  Be more verbose
      --json     Output payloads as JSON objects
  -d  --domain   Domain to resolve
```

### Demo

![udig demo](doc/res/udig_demo.gif)

## Dependencies and attributions

* https://github.com/akamensky/argparse - Argparse for golang
* https://github.com/miekg/dns - DNS library in Go 
* https://github.com/domainr/whois - Whois client for Go
* https://github.com/ip2location/ip2location-go - GeoIP localization package. This product uses IP2Location LITE data available from [https://lite.ip2location.com](https://lite.ip2location.com).
* https://www.team-cymru.com/IP-ASN-mapping.html - IP to ASN mapping service by Team Cymru

## License
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fnetrixone%2Fudig.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2Fnetrixone%2Fudig?ref=badge_large)