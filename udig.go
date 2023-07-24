package udig

import (
	"github.com/miekg/dns"
	"sync"
)

type udigImpl struct {
	Udig
	domainResolvers []DomainResolver
	ipResolvers     []IPResolver
	domainQueue     chan string
	ipQueue         chan string
	processed       map[string]bool
	seen            map[string]bool
}

// NewUdig creates a new Udig instances provisioned with
// all supported resolvers. You can also supply your own
// resolvers to the returned instance.
func NewUdig() Udig {
	udig := &udigImpl{
		domainResolvers: []DomainResolver{},
		ipResolvers:     []IPResolver{},
		domainQueue:     make(chan string, 1024),
		ipQueue:         make(chan string, 1024),
		processed:       map[string]bool{},
		seen:            map[string]bool{},
	}

	udig.AddDomainResolver(NewDNSResolver())
	udig.AddDomainResolver(NewWhoisResolver())
	udig.AddDomainResolver(NewTLSResolver())
	udig.AddDomainResolver(NewHTTPResolver())

	udig.AddIPResolver(NewBGPResolver())
	udig.AddIPResolver(NewGeoResolver())

	return udig
}

func (udig *udigImpl) Resolve(domain string) (resolutions []Resolution) {
	udig.domainQueue <- domain
	resolutions = append(resolutions, udig.resolveDomains()...)

	// Enqueue all discovered IPs.
	for _, resolution := range resolutions {
		udig.enqueueIps(resolution.IPs()...)
	}
	resolutions = append(resolutions, udig.resolveIPs()...)

	return resolutions
}

func (udig *udigImpl) AddDomainResolver(resolver DomainResolver) {
	udig.domainResolvers = append(udig.domainResolvers, resolver)
}

func (udig *udigImpl) AddIPResolver(resolver IPResolver) {
	udig.ipResolvers = append(udig.ipResolvers, resolver)
}

func (udig *udigImpl) resolveDomains() (resolutions []Resolution) {
	for len(udig.domainQueue) > 0 {
		// Poll a domain.
		domain := <-udig.domainQueue

		// Resolve it.
		newResolutions := udig.resolveOneDomain(domain)

		// Store the results.
		resolutions = append(resolutions, newResolutions...)

		// Enqueue all related domains from the result.
		udig.enqueueDomains(udig.getRelatedDomains(newResolutions)...)
	}

	return resolutions
}

func (udig *udigImpl) resolveIPs() (resolutions []Resolution) {
	for len(udig.ipQueue) > 0 {
		// Poll an IP.
		ip := <-udig.ipQueue

		// Resolve it.
		newResolutions := udig.resolveOneIP(ip)

		resolutions = append(resolutions, newResolutions...)
	}

	return resolutions
}

func (udig *udigImpl) resolveOneDomain(domain string) (resolutions []Resolution) {
	// Make sure we don't repeat ourselves.
	if udig.isProcessed(domain) {
		return resolutions
	}
	defer udig.addProcessed(domain)

	resolutionChannel := make(chan Resolution, 1024)

	var wg sync.WaitGroup
	wg.Add(len(udig.domainResolvers))

	for _, resolver := range udig.domainResolvers {
		go func(resolver DomainResolver) {
			resolutionChannel <- resolver.ResolveDomain(domain)
			wg.Done()
		}(resolver)
	}

	wg.Wait()

	for len(resolutionChannel) > 0 {
		resolutions = append(resolutions, <-resolutionChannel)
	}

	return resolutions
}

func (udig *udigImpl) resolveOneIP(ip string) (resolutions []Resolution) {
	// Make sure we don't repeat ourselves.
	if udig.isProcessed(ip) {
		return resolutions
	}
	defer udig.addProcessed(ip)

	resolutionChannel := make(chan Resolution, 1024)

	var wg sync.WaitGroup
	wg.Add(len(udig.ipResolvers))

	for _, resolver := range udig.ipResolvers {
		go func(resolver IPResolver) {
			resolutionChannel <- resolver.ResolveIP(ip)
			wg.Done()
		}(resolver)
	}

	wg.Wait()

	for len(resolutionChannel) > 0 {
		resolutions = append(resolutions, <-resolutionChannel)
	}

	return resolutions
}

func (udig *udigImpl) isCnameOrRelated(nextDomain string, resolution Resolution) bool {
	switch resolution.Type() {
	case TypeDNS:
		for _, rr := range resolution.(*DNSResolution).Records {
			if rr.Record.Header().Rrtype == dns.TypeCNAME && rr.Record.RR.(*dns.CNAME).Target == nextDomain {
				// Follow DNS CNAME pointers.
				return true
			}
		}
		break
	}

	// Otherwise try heuristics.
	return IsDomainRelated(nextDomain, resolution.Query())
}

func (udig *udigImpl) getRelatedDomains(resolutions []Resolution) (domains []string) {
	for _, resolution := range resolutions {
		for _, nextDomain := range resolution.Domains() {
			// Crawl new and related domains only.
			if udig.isProcessed(nextDomain) || udig.isSeen(nextDomain) {
				continue
			}

			udig.addSeen(nextDomain)

			if !udig.isCnameOrRelated(nextDomain, resolution) {
				LogDebug("%s: Domain %s is not related to %s -> skipping.", resolution.Type(), nextDomain, resolution.Query())
				continue
			}

			LogDebug("%s: Discovered a related domain %s via %s.", resolution.Type(), nextDomain, resolution.Query())

			domains = append(domains, nextDomain)
		}
	}
	return domains
}

func (udig *udigImpl) enqueueDomains(domains ...string) {
	for _, domain := range domains {
		udig.domainQueue <- domain
	}
}

func (udig *udigImpl) enqueueIps(ips ...string) {
	for _, ip := range ips {
		udig.ipQueue <- ip
	}
}

func (udig *udigImpl) isProcessed(query string) bool {
	return udig.processed[query]
}

func (udig *udigImpl) addProcessed(query string) {
	udig.processed[query] = true
}

func (udig *udigImpl) isSeen(query string) bool {
	return udig.seen[query]
}

func (udig *udigImpl) addSeen(query string) {
	udig.seen[query] = true
}
