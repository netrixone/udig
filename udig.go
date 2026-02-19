package udig

import (
	"sync"
	"time"

	"github.com/miekg/dns"
)

type udigImpl struct {
	domainResolvers []DomainResolver
	ipResolvers     []IPResolver
	domainQueue     chan string
	ipQueue         chan string
	processed       map[string]bool
	seen            map[string]bool

	// Configurable:
	isDomainRelated DomainRelationFn
	timeout         time.Duration
	ctSince         string
	ctExclude       string
}

type udigOption struct {
	f func(*udigImpl)
}

func newUdigOption(f func(*udigImpl)) udigOption {
	return udigOption{f}
}

func (opt udigOption) apply(udig *udigImpl) {
	opt.f(udig)
}

// NewUdig creates a new Udig instances provisioned with
// all supported resolvers.
func NewUdig(opts ...Option) Udig {
	udig := newUdigIml(opts...)

	udig.AddDomainResolver(NewDNSResolver(udig.timeout))
	udig.AddDomainResolver(NewWhoisResolver(udig.timeout))
	udig.AddDomainResolver(NewTLSResolver(udig.timeout))
	udig.AddDomainResolver(NewHTTPResolver(udig.timeout))
	udig.AddDomainResolver(NewCTResolver(udig.timeout, udig.ctSince, udig.ctExclude))

	udig.AddIPResolver(NewBGPResolver(udig.timeout))
	udig.AddIPResolver(NewGeoResolver())

	return udig
}

// NewEmptyUdig creates a new Udig instance without any resolvers.
// You can also supply your own resolvers to the returned instance.
func NewEmptyUdig(opts ...Option) Udig {
	return newUdigIml(opts...)
}

func newUdigIml(opts ...Option) *udigImpl {
	udig := &udigImpl{
		domainResolvers: []DomainResolver{},
		ipResolvers:     []IPResolver{},
		domainQueue:     make(chan string, 1024),
		ipQueue:         make(chan string, 1024),
		processed:       map[string]bool{},
		seen:            map[string]bool{},

		isDomainRelated: DefaultDomainRelation,
		timeout:         DefaultTimeout,
	}

	for _, opt := range opts {
		opt.apply(udig)
	}

	return udig
}

func (u *udigImpl) Resolve(domain string) <-chan Resolution {
	resCh := make(chan Resolution, 256)

	u.domainQueue <- domain
	go u.resolveInto(resCh)

	return resCh
}

func (u *udigImpl) AddDomainResolver(resolver DomainResolver) {
	u.domainResolvers = append(u.domainResolvers, resolver)
}

func (u *udigImpl) AddIPResolver(resolver IPResolver) {
	u.ipResolvers = append(u.ipResolvers, resolver)
}

func (u *udigImpl) resolveInto(resChan chan<- Resolution) {
	defer close(resChan)
	for len(u.domainQueue) > 0 {
		// Poll a domain.
		domain := <-u.domainQueue

		// Resolve it.
		u.resolveDomainInto(domain, resChan)

		// Resolve all the discovered IPs.
		for len(u.ipQueue) > 0 {
			ip := <-u.ipQueue
			u.resolveIPInto(ip, resChan)
		}
	}
}

func (u *udigImpl) resolveDomainInto(domain string, resChan chan<- Resolution) {
	if u.isProcessed(domain) {
		return
	}
	defer u.addProcessed(domain)

	var wg sync.WaitGroup
	wg.Add(len(u.domainResolvers))

	for _, resolver := range u.domainResolvers {
		go func(resolver DomainResolver) {
			resolution := resolver.ResolveDomain(domain)
			resChan <- resolution

			// Enqueue all related domains from the result.
			u.enqueueDomains(u.getRelatedDomains(resolution)...)

			// Enqueue all discovered IPs.
			u.enqueueIps(resolution.IPs()...)

			wg.Done()
		}(resolver)
	}

	wg.Wait()
}

func (u *udigImpl) resolveIPInto(ip string, ch chan<- Resolution) {
	if u.isProcessed(ip) {
		return
	}
	defer u.addProcessed(ip)

	var wg sync.WaitGroup
	wg.Add(len(u.ipResolvers))

	for _, resolver := range u.ipResolvers {
		go func(resolver IPResolver) {
			ch <- resolver.ResolveIP(ip)
			wg.Done()
		}(resolver)
	}

	wg.Wait()
}

func (u *udigImpl) isCnameOrRelated(nextDomain string, resolution Resolution) bool {
	switch resolution.Type() {
	case TypeDNS:
		for _, rr := range resolution.(*DNSResolution).Records {
			if rr.Record.Header().Rrtype == dns.TypeCNAME && rr.Record.RR.(*dns.CNAME).Target == nextDomain {
				// Follow DNS CNAME pointers.
				return true
			}
		}
	}

	// Otherwise try heuristics.
	return u.isDomainRelated(nextDomain, resolution.Query())
}

func (u *udigImpl) getRelatedDomains(resolution Resolution) (domains []string) {
	for _, nextDomain := range resolution.Domains() {
		// Crawl new and related domains only.
		if u.isProcessed(nextDomain) || u.isSeen(nextDomain) {
			continue
		}

		u.addSeen(nextDomain)

		if !u.isCnameOrRelated(nextDomain, resolution) {
			LogDebug("%s: Domain %s is not related to %s -> skipping.", resolution.Type(), nextDomain, resolution.Query())
			continue
		}

		LogDebug("%s: Discovered a related domain %s via %s.", resolution.Type(), nextDomain, resolution.Query())

		domains = append(domains, nextDomain)
	}
	return domains
}

func (u *udigImpl) enqueueDomains(domains ...string) {
	for _, domain := range domains {
		u.domainQueue <- domain
	}
}

func (u *udigImpl) enqueueIps(ips ...string) {
	for _, ip := range ips {
		u.ipQueue <- ip
	}
}

func (u *udigImpl) isProcessed(query string) bool {
	return u.processed[query]
}

func (u *udigImpl) addProcessed(query string) {
	u.processed[query] = true
}

func (u *udigImpl) isSeen(query string) bool {
	return u.seen[query]
}

func (u *udigImpl) addSeen(query string) {
	u.seen[query] = true
}
