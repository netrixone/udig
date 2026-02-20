[![CI](https://github.com/netrixone/udig/actions/workflows/ci.yml/badge.svg)](https://github.com/netrixone/udig/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/netrixone/udig)](https://goreportcard.com/report/github.com/netrixone/udig)
[![Go Doc](https://godoc.org/github.com/netrixone/udig?status.svg)](https://godoc.org/github.com/netrixone/udig)
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fnetrixone%2Fudig.svg?type=shield)](https://app.fossa.io/projects/git%2Bgithub.com%2Fnetrixone%2Fudig?ref=badge_shield)

# udig (ÜberDig) — dig on steroids

**Fast, non-intrusive domain reconnaissance tool written in Go.**

Udig provides a quick overview of a target domain's infrastructure by combining multiple active scanning techniques — DNS enumeration, TLS certificate scraping, WHOIS lookups, HTTP header analysis, Certificate Transparency log search, BGP ASN mapping, and GeoIP resolution. Discovered domains are automatically followed and resolved recursively.

This is not a full-blown DNS enumerator. There is no brute-forcing, no port scanning, no search engine scraping. udig is designed to be unobtrusive and fast, suitable for long-term experiments with many targets.

## Features

- **DNS** — resolves all record types of interest (A, AAAA, NS, MX, TXT, SOA, ...) with automatic nameserver discovery
- **TLS** — extracts full certificate chains and discovers domains from SANs
- **WHOIS** — parses contact information from WHOIS banners
- **HTTP** — inspects security-related headers (CSP, CORS, Alt-Svc, ...)
- **Certificate Transparency** — queries crt.sh for historical and current certificates
- **BGP** — maps discovered IPs to autonomous systems via Team Cymru
- **GeoIP** — resolves country codes for discovered IPs via IP2Location
- **Recursive crawling** — domains found in any resolution are automatically followed
- **SPF parsing** — extracts IPs embedded in SPF records
- **Output** — colorized human-readable CLI output or JSON

## Installation

### Pre-built binary

Download the latest release from the [Releases](https://github.com/netrixone/udig/releases) page.

### Build from source

Requires Go 1.24+.

```bash
make            # build + test
make install    # install binary + GeoIP database
```

The build automatically downloads the IP2Location LITE database if not already present.

### Go install

```bash
go install github.com/netrixone/udig/cmd/udig@latest
```

## Usage

```
udig [-h|--help] [-v|--version] [-V|--verbose] [-s|--strict]
     [-d|--domain "<value>"] [-t|--timeout "<value>"]
     [--ct:expired] [--ct:from "<value>"] [--json]
```

| Flag | Description |
|------|-------------|
| `-d`, `--domain` | Domain(s) to resolve (repeatable) |
| `-s`, `--strict` | Strict domain relation — require TLD match |
| `-t`, `--timeout` | Connection timeout (default: `10s`) |
| `-V`, `--verbose` | Enable debug logging |
| `--ct:expired` | Include expired Certificate Transparency logs |
| `--ct:from` | CT log start date in `YYYY-MM-DD` format (default: 1 year ago) |
| `--json` | Output payloads as JSON objects |

### Example

```bash
udig -d example.com
udig -d example.com -d example.org --json
udig -d example.com --ct:from 2024-01-01 -V
```

### Demo

![udig demo](doc/res/udig_demo.gif)

## Using udig as a Go library

udig can be imported as a package for programmatic use. See [DEVELOPMENT.md](DEVELOPMENT.md) for the API overview, architecture, and build details.

```go
dig := udig.NewUdig()
for res := range dig.Resolve("example.com") {
    // Results stream in as they become available.
    fmt.Println(res.Type(), res.Query())
}
```

## Attributions

- [miekg/dns](https://github.com/miekg/dns) — DNS library for Go
- [akamensky/argparse](https://github.com/akamensky/argparse) — CLI argument parsing
- [domainr/whois](https://github.com/domainr/whois) — WHOIS client for Go
- [ip2location/ip2location-go](https://github.com/ip2location/ip2location-go) — GeoIP using [IP2Location LITE](https://lite.ip2location.com)
- [Team Cymru](https://www.team-cymru.com/IP-ASN-mapping.html) — IP-to-ASN mapping service

## License

MIT — see [LICENSE.txt](LICENSE.txt).

[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fnetrixone%2Fudig.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2Fnetrixone%2Fudig?ref=badge_large)
