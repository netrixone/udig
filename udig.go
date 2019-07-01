package udig

import (
	"github.com/miekg/dns"
	"sync"
)

type udigImpl struct {
	Udig
	resolvers       []Resolver
	domainQueue     chan string
	resolvedDomains map[string]bool
	seenDomains     map[string]bool
}

// NewUdig creates a new Udig instances provisioned with
// all supported resolvers. You can also supply your own
// resolvers.
func NewUdig(extraResolvers ...Resolver) Udig {
	udig := &udigImpl{
		domainQueue:     make(chan string, 1024),
		resolvedDomains: map[string]bool{},
		seenDomains:     map[string]bool{},
		resolvers:       []Resolver{},
	}

	udig.resolvers = append(udig.resolvers, NewDNSResolver())
	udig.resolvers = append(udig.resolvers, NewWhoisResolver())
	udig.resolvers = append(udig.resolvers, NewTLSResolver())
	udig.resolvers = append(udig.resolvers, extraResolvers...)

	return udig
}

func (udig *udigImpl) Resolve(domain string) (resolutions []Resolution) {
	udig.domainQueue <- domain

	for len(udig.domainQueue) > 0 {

		// Poll a domain.
		domain := <-udig.domainQueue

		// Resolve it.
		newResolutions := udig.resolveOne(domain)

		// Store the results.
		resolutions = append(resolutions, newResolutions...)

		// Push discovered domains to the queue.
		udig.crawlRelatedDomains(resolutions)
	}

	return resolutions
}

func (udig *udigImpl) resolveOne(domain string) (resolutions []Resolution) {
	// Make sure we don't repeat ourselves.
	if udig.isProcessed(domain) {
		return resolutions
	}
	defer udig.addProcessed(domain)

	resolutionChannel := make(chan Resolution, 1024)

	var wg sync.WaitGroup
	wg.Add(len(udig.resolvers))

	for _, resolver := range udig.resolvers {
		go func(resolver Resolver) {
			resolutionChannel <- (resolver).Resolve(domain)
			wg.Done()
		}(resolver)
	}

	wg.Wait()

	for len(resolutionChannel) > 0 {
		resolutions = append(resolutions, <-resolutionChannel)
	}

	return resolutions
}

func (udig *udigImpl) shouldCrawlDomain(nextDomain string, resolution Resolution) bool {
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
	return isDomainRelated(nextDomain, resolution.Query())
}

func (udig *udigImpl) crawlRelatedDomains(resolutions []Resolution) {
	for _, resolution := range resolutions {
		for _, nextDomain := range resolution.Domains() {
			// Crawl new and related domains only.
			if udig.isProcessed(nextDomain) || udig.isSeen(nextDomain) {
				continue
			}

			udig.addSeen(nextDomain)

			if !udig.shouldCrawlDomain(nextDomain, resolution) {
				LogDebug("%s: Domain %s is not related to %s -> skipping.", resolution.Type(), nextDomain, resolution.Query())
				continue
			}

			LogDebug("%s: Discovered a related domain %s via %s.", resolution.Type(), nextDomain, resolution.Query())

			udig.domainQueue <- nextDomain
		}
	}
}

func (udig *udigImpl) isProcessed(domain string) bool {
	return udig.resolvedDomains[domain]
}

func (udig *udigImpl) addProcessed(domain string) {
	udig.resolvedDomains[domain] = true
}

func (udig *udigImpl) isSeen(domain string) bool {
	return udig.seenDomains[domain]
}

func (udig *udigImpl) addSeen(domain string) {
	udig.seenDomains[domain] = true
}
