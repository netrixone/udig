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

- [x] Resolves a given domain to all interesting DNS records. 
- [x] Supports automatic NS discovery and resolution of related domains (CNAME, MX, KX, NSSEC).
- [x] Resolves a given domain to a set of WHOIS contacts (selected properties only).
- [x] Resolves a given domain to a TLS certificate chain.
- [x] CLI application outputs all resolutions encoded as JSON strings.
- [x] Supports multiple domains on the input.
- [ ] Resolves IPs and domains found in SPF record.
- [ ] Resolves domains in CSP header.
- [ ] Supports a web-crawler to enumerate sub-domains.
- [ ] Supports parallel resolution of multiple domains at the same time.
- [ ] Colorized CLI output.
- [ ] Clean CLI output (e.g. RAW values, replace numeric constants with more meaningful strings).

## Download as dependency

`go get github.com/netrixone/udig`

## CLI app

### Build

`make`

### Usage

```bash
udig [-h|--help] [-v|--version] [-V|--verbose] [-d|--domain "<value>"
            [-d|--domain "<value>" ...]]

            ÜberDig - dig on steroids v1.0 by stuchl4n3k

Arguments:

  -h  --help     Print help information
  -v  --version  Print version and exit
  -V  --verbose  Be more verbose
  -d  --domain   Domain to resolve
```

### Example

```bash

$ udig -d example.com
 _   _ ____ ___ ____
(_) (_|  _ |_ _/ ___|
| | | | | | | | |  _
| |_| | |_| | | |_| |
 \__,_|____|___\____| v1.0

[+] WHOIS: example.com -> {"creation date":"1995-08-14t04:00:00z","registrar":"reserved-internet assigned numbers authority","registrar iana id":"376","registrar url":"http://res-dom.iana.org","registrar whois server":"whois.iana.org","registry domain id":"2336799_domain_com-vrsn","updated date":"2018-08-14t07:14:12z"}
[+] TLS: example.com -> {"SignatureAlgorithm":4,"PublicKeyAlgorithm":1,"Version":3,"SerialNumber":21020869104500376438182461249190639870,"Issuer":{"Country":["US"],"Organization":["DigiCert Inc"],"OrganizationalUnit":null,"Locality":null,"Province":null,"StreetAddress":null,"PostalCode":null,"SerialNumber":"","CommonName":"DigiCert SHA2 Secure Server CA","Names":[{"Type":[2,5,4,6],"Value":"US"},{"Type":[2,5,4,10],"Value":"DigiCert Inc"},{"Type":[2,5,4,3],"Value":"DigiCert SHA2 Secure Server CA"}],"ExtraNames":null},"Subject":{"Country":["US"],"Organization":["Internet Corporation for Assigned Names and Numbers"],"OrganizationalUnit":["Technology"],"Locality":["Los Angeles"],"Province":["California"],"StreetAddress":null,"PostalCode":null,"SerialNumber":"","CommonName":"www.example.org","Names":[{"Type":[2,5,4,6],"Value":"US"},{"Type":[2,5,4,8],"Value":"California"},{"Type":[2,5,4,7],"Value":"Los Angeles"},{"Type":[2,5,4,10],"Value":"Internet Corporation for Assigned Names and Numbers"},{"Type":[2,5,4,11],"Value":"Technology"},{"Type":[2,5,4,3],"Value":"www.example.org"}],"ExtraNames":null},"NotBefore":"2018-11-28T00:00:00Z","NotAfter":"2020-12-02T12:00:00Z","KeyUsage":5,"Extensions":[{"Id":[2,5,29,35],"Critical":false,"Value":"MBaAFA+AYRyCMWHVLyjnjUY4tCzhxtni"},{"Id":[2,5,29,14],"Critical":false,"Value":"BBRmmGIC4AmRp9njNvt2xrC/oW2nvg=="},{"Id":[2,5,29,17],"Critical":false,"Value":"MHiCD3d3dy5leGFtcGxlLm9yZ4ILZXhhbXBsZS5jb22CC2V4YW1wbGUuZWR1ggtleGFtcGxlLm5ldIILZXhhbXBsZS5vcmeCD3d3dy5leGFtcGxlLmNvbYIPd3d3LmV4YW1wbGUuZWR1gg93d3cuZXhhbXBsZS5uZXQ="},{"Id":[2,5,29,15],"Critical":true,"Value":"AwIFoA=="},{"Id":[2,5,29,37],"Critical":false,"Value":"MBQGCCsGAQUFBwMBBggrBgEFBQcDAg=="},{"Id":[2,5,29,31],"Critical":false,"Value":"MGIwL6AtoCuGKWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9zc2NhLXNoYTItZzYuY3JsMC+gLaArhilodHRwOi8vY3JsNC5kaWdpY2VydC5jb20vc3NjYS1zaGEyLWc2LmNybA=="},{"Id":[2,5,29,32],"Critical":false,"Value":"MEMwNwYJYIZIAYb9bAEBMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwCAYGZ4EMAQIC"},{"Id":[1,3,6,1,5,5,7,1,1],"Critical":false,"Value":"MG4wJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBGBggrBgEFBQcwAoY6aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0U0hBMlNlY3VyZVNlcnZlckNBLmNydA=="},{"Id":[2,5,29,19],"Critical":true,"Value":"MAA="},{"Id":[1,3,6,1,4,1,11129,2,4,2],"Critical":false,"Value":"BIIBawFpAHcApLkJkLQYWBSHuxOizGdwCjw1mAT5G9+443fNDsgN3BAAAAFnXDGVRgAABAMASDBGAiEAhGSBtyEd+hpI9XauS+hGhlcnF7B76Tu3SldCbKKExGwCIQC7k7X+MMRk5BZMfG5YU1fu7H+qRU+/DkaO/nD9/Y5CQgB2AId1v+dZfPiMQ5lfvfNu/1aNR1Y2/0q1YMG06v9eoIMPAAABZ1wxlhUAAAQDAEcwRQIgb6p30hynlMBjLS6zht1Bi0CKGi9/rmbBk19zH0iTUBECIQDS+Z1IhgUeoJdEJQs86s76Kxl8gf8ne57bWLbc6PBKTgB2AG9Tdqwx8DEZ2JkApFEV/3cVHBHZAsEAKQaNsgiaN9kTAAABZ1wxlpwAAAQDAEcwRQIhAOR5+0OEjsqh5E/pA7B6u5Lu80Q7jOz+FA19n7djKZ8tAiBNd1rcSQFK9GgEhWGf140gDDH6wdP0cQpb1lbLPSxyjA=="}],"ExtraExtensions":null,"UnhandledCriticalExtensions":null,"ExtKeyUsage":[1,2],"UnknownExtKeyUsage":null,"BasicConstraintsValid":true,"IsCA":false,"MaxPathLen":-1,"MaxPathLenZero":false,"SubjectKeyId":"ZphiAuAJkafZ4zb7dsawv6Ftp74=","AuthorityKeyId":"D4BhHIIxYdUvKOeNRji0LOHG2eI=","OCSPServer":["http://ocsp.digicert.com"],"IssuingCertificateURL":["http://cacerts.digicert.com/DigiCertSHA2SecureServerCA.crt"],"DNSNames":["www.example.org","example.com","example.edu","example.net","example.org","www.example.com","www.example.edu","www.example.net"],"EmailAddresses":null,"IPAddresses":null,"URIs":null,"PermittedDNSDomainsCritical":false,"PermittedDNSDomains":null,"ExcludedDNSDomains":null,"PermittedIPRanges":null,"ExcludedIPRanges":null,"PermittedEmailAddresses":null,"ExcludedEmailAddresses":null,"PermittedURIDomains":null,"ExcludedURIDomains":null,"CRLDistributionPoints":["http://crl3.digicert.com/ssca-sha2-g6.crl","http://crl4.digicert.com/ssca-sha2-g6.crl"],"PolicyIdentifiers":[[2,16,840,1,114412,1,1],[2,23,140,1,2,2]]}
[+] TLS: example.com -> {"SignatureAlgorithm":4,"PublicKeyAlgorithm":1,"Version":3,"SerialNumber":2646203786665923649276728595390119057,"Issuer":{"Country":["US"],"Organization":["DigiCert Inc"],"OrganizationalUnit":["www.digicert.com"],"Locality":null,"Province":null,"StreetAddress":null,"PostalCode":null,"SerialNumber":"","CommonName":"DigiCert Global Root CA","Names":[{"Type":[2,5,4,6],"Value":"US"},{"Type":[2,5,4,10],"Value":"DigiCert Inc"},{"Type":[2,5,4,11],"Value":"www.digicert.com"},{"Type":[2,5,4,3],"Value":"DigiCert Global Root CA"}],"ExtraNames":null},"Subject":{"Country":["US"],"Organization":["DigiCert Inc"],"OrganizationalUnit":null,"Locality":null,"Province":null,"StreetAddress":null,"PostalCode":null,"SerialNumber":"","CommonName":"DigiCert SHA2 Secure Server CA","Names":[{"Type":[2,5,4,6],"Value":"US"},{"Type":[2,5,4,10],"Value":"DigiCert Inc"},{"Type":[2,5,4,3],"Value":"DigiCert SHA2 Secure Server CA"}],"ExtraNames":null},"NotBefore":"2013-03-08T12:00:00Z","NotAfter":"2023-03-08T12:00:00Z","KeyUsage":97,"Extensions":[{"Id":[2,5,29,19],"Critical":true,"Value":"MAYBAf8CAQA="},{"Id":[2,5,29,15],"Critical":true,"Value":"AwIBhg=="},{"Id":[1,3,6,1,5,5,7,1,1],"Critical":false,"Value":"MCYwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbQ=="},{"Id":[2,5,29,31],"Critical":false,"Value":"MHIwN6A1oDOGMWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RDQS5jcmwwN6A1oDOGMWh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RDQS5jcmw="},{"Id":[2,5,29,32],"Critical":false,"Value":"MDQwMgYEVR0gADAqMCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BT"},{"Id":[2,5,29,14],"Critical":false,"Value":"BBQPgGEcgjFh1S8o541GOLQs4cbZ4g=="},{"Id":[2,5,29,35],"Critical":false,"Value":"MBaAFAPeUDVW0Uy7ZvCj4hsbw5eyPdFV"}],"ExtraExtensions":null,"UnhandledCriticalExtensions":null,"ExtKeyUsage":null,"UnknownExtKeyUsage":null,"BasicConstraintsValid":true,"IsCA":true,"MaxPathLen":0,"MaxPathLenZero":true,"SubjectKeyId":"D4BhHIIxYdUvKOeNRji0LOHG2eI=","AuthorityKeyId":"A95QNVbRTLtm8KPiGxvDl7I90VU=","OCSPServer":["http://ocsp.digicert.com"],"IssuingCertificateURL":null,"DNSNames":null,"EmailAddresses":null,"IPAddresses":null,"URIs":null,"PermittedDNSDomainsCritical":false,"PermittedDNSDomains":null,"ExcludedDNSDomains":null,"PermittedIPRanges":null,"ExcludedIPRanges":null,"PermittedEmailAddresses":null,"ExcludedEmailAddresses":null,"PermittedURIDomains":null,"ExcludedURIDomains":null,"CRLDistributionPoints":["http://crl3.digicert.com/DigiCertGlobalRootCA.crl","http://crl4.digicert.com/DigiCertGlobalRootCA.crl"],"PolicyIdentifiers":[[2,5,29,32,0]]}
[+] TLS: example.com -> {"SignatureAlgorithm":3,"PublicKeyAlgorithm":1,"Version":3,"SerialNumber":10944719598952040374951832963794454346,"Issuer":{"Country":["US"],"Organization":["DigiCert Inc"],"OrganizationalUnit":["www.digicert.com"],"Locality":null,"Province":null,"StreetAddress":null,"PostalCode":null,"SerialNumber":"","CommonName":"DigiCert Global Root CA","Names":[{"Type":[2,5,4,6],"Value":"US"},{"Type":[2,5,4,10],"Value":"DigiCert Inc"},{"Type":[2,5,4,11],"Value":"www.digicert.com"},{"Type":[2,5,4,3],"Value":"DigiCert Global Root CA"}],"ExtraNames":null},"Subject":{"Country":["US"],"Organization":["DigiCert Inc"],"OrganizationalUnit":["www.digicert.com"],"Locality":null,"Province":null,"StreetAddress":null,"PostalCode":null,"SerialNumber":"","CommonName":"DigiCert Global Root CA","Names":[{"Type":[2,5,4,6],"Value":"US"},{"Type":[2,5,4,10],"Value":"DigiCert Inc"},{"Type":[2,5,4,11],"Value":"www.digicert.com"},{"Type":[2,5,4,3],"Value":"DigiCert Global Root CA"}],"ExtraNames":null},"NotBefore":"2006-11-10T00:00:00Z","NotAfter":"2031-11-10T00:00:00Z","KeyUsage":97,"Extensions":[{"Id":[2,5,29,15],"Critical":true,"Value":"AwIBhg=="},{"Id":[2,5,29,19],"Critical":true,"Value":"MAMBAf8="},{"Id":[2,5,29,14],"Critical":false,"Value":"BBQD3lA1VtFMu2bwo+IbG8OXsj3RVQ=="},{"Id":[2,5,29,35],"Critical":false,"Value":"MBaAFAPeUDVW0Uy7ZvCj4hsbw5eyPdFV"}],"ExtraExtensions":null,"UnhandledCriticalExtensions":null,"ExtKeyUsage":null,"UnknownExtKeyUsage":null,"BasicConstraintsValid":true,"IsCA":true,"MaxPathLen":-1,"MaxPathLenZero":false,"SubjectKeyId":"A95QNVbRTLtm8KPiGxvDl7I90VU=","AuthorityKeyId":"A95QNVbRTLtm8KPiGxvDl7I90VU=","OCSPServer":null,"IssuingCertificateURL":null,"DNSNames":null,"EmailAddresses":null,"IPAddresses":null,"URIs":null,"PermittedDNSDomainsCritical":false,"PermittedDNSDomains":null,"ExcludedDNSDomains":null,"PermittedIPRanges":null,"ExcludedIPRanges":null,"PermittedEmailAddresses":null,"ExcludedEmailAddresses":null,"PermittedURIDomains":null,"ExcludedURIDomains":null,"CRLDistributionPoints":null,"PolicyIdentifiers":null}
[!] DNS: IXFR example.com -> NOTAUTH
[!] DNS: AXFR example.com -> NOTIMP
[+] DNS: A example.com -> {"Hdr":{"Name":"example.com.","Rrtype":1,"Class":1,"Ttl":86400,"Rdlength":4},"A":"93.184.216.34"}
[+] DNS: SOA example.com -> {"Hdr":{"Name":"example.com.","Rrtype":6,"Class":1,"Ttl":3600,"Rdlength":45},"Ns":"sns.dns.icann.org.","Mbox":"noc.dns.icann.org.","Serial":2019041035,"Refresh":7200,"Retry":3600,"Expire":1209600,"Minttl":3600}
[+] DNS: TXT example.com -> {"Hdr":{"Name":"example.com.","Rrtype":16,"Class":1,"Ttl":86400,"Rdlength":12},"Txt":["v=spf1 -all"]}
[+] DNS: AAAA example.com -> {"Hdr":{"Name":"example.com.","Rrtype":28,"Class":1,"Ttl":86400,"Rdlength":16},"AAAA":"2606:2800:220:1:248:1893:25c8:1946"}
[+] DNS: NSEC example.com -> {"Hdr":{"Name":"example.com.","Rrtype":47,"Class":1,"Ttl":3600,"Rdlength":26},"NextDomain":"www.example.com.","TypeBitMap":[1,2,6,16,28,46,47,48]}
[+] DNS: ANY example.com -> {"Hdr":{"Name":"example.com.","Rrtype":6,"Class":1,"Ttl":3600,"Rdlength":45},"Ns":"sns.dns.icann.org.","Mbox":"noc.dns.icann.org.","Serial":2019041035,"Refresh":7200,"Retry":3600,"Expire":1209600,"Minttl":3600}
```

## Dependencies

* https://github.com/akamensky/argparse - Argparse for golang
* https://github.com/miekg/dns - DNS library in Go 
* https://github.com/domainr/whois - Whois client for Go

## License
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fnetrixone%2Fudig.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2Fnetrixone%2Fudig?ref=badge_large)