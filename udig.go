package udig

import (
	"context"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Option is a Udig configuration option pattern.
type Option interface {
	apply(*udigImpl)
}

// WithDebugLogging activates debug logging.
func WithDebugLogging() Option {
	return WithLoggingLevel(LogLevelDebug)
}

// WithLoggingLevel sets the log level used for logging.
func WithLoggingLevel(logLevel int) Option {
	return newUdigOption(func(opt *udigImpl) {
		LogLevel = logLevel
	})
}

// WithStrictMode activates strict mode domain relation (TLD match).
func WithStrictMode() Option {
	return WithDomainRelation(StrictDomainRelation)
}

// WithDomainRelation supplies a given domain relation func for domain heuristic.
func WithDomainRelation(rel DomainRelationFn) Option {
	return newUdigOption(func(udig *udigImpl) {
		if rel != nil {
			udig.isDomainRelated = rel
		}
	})
}

// WithTimeout changes a default timeout to the supplied value.
func WithTimeout(timeout time.Duration) Option {
	return newUdigOption(func(udig *udigImpl) {
		udig.timeout = timeout
	})
}

// WithCTExpired includes expired Certificate Transparency logs in the results (slower).
func WithCTExpired() Option {
	return newUdigOption(func(udig *udigImpl) {
		udig.ctExclude = ""
	})
}

// WithCTSince ignores Certificate Transparency logs older than a given time.
func WithCTSince(t time.Time) Option {
	return newUdigOption(func(udig *udigImpl) {
		udig.ctSince = t.Format("2006-01-02")
	})
}

// WithCTPGConnStr sets the PostgreSQL connection string for direct crt.sh database access.
// Pass an empty string to disable PostgreSQL and use the HTTP API exclusively.
// Defaults to DefaultCTPGConnStr (the public crt.sh read-only endpoint).
func WithCTPGConnStr(connStr string) Option {
	return newUdigOption(func(udig *udigImpl) {
		udig.ctPGConnStr = connStr
	})
}

// WithMaxDepth limits recursive domain discovery depth.
// Depth 0 = seed only, 1 = seed + one hop, etc.
// Default: unlimited (-1).
func WithMaxDepth(n int) Option {
	return newUdigOption(func(udig *udigImpl) {
		udig.maxDepth = n
	})
}

type udigImpl struct {
	domainResolvers []DomainResolver
	ipResolvers     []IPResolver
	domainQueue     chan string
	ipQueue         chan string
	processed       map[string]bool
	seen            map[string]bool
	depthOf         map[string]int // crawl depth of each discovered domain
	mux             sync.Mutex     // protects seen and depthOf

	// Configurable:
	isDomainRelated DomainRelationFn
	timeout         time.Duration
	ctSince         string
	ctExclude       string
	ctPGConnStr     string
	maxDepth        int // -1 = unlimited (default)
}

type optionImpl struct {
	f func(*udigImpl)
}

func newUdigOption(f func(*udigImpl)) optionImpl {
	return optionImpl{f}
}

func (opt optionImpl) apply(udig *udigImpl) {
	opt.f(udig)
}

// NewUdig creates a new Udig instances provisioned with
// all supported resolvers.
func NewUdig(opts ...Option) Udig {
	udig := newUdigIml(opts...)

	udig.AddDomainResolver(NewDNSResolver(udig.timeout))
	udig.AddDomainResolver(NewDMARCResolver(udig.timeout))
	udig.AddDomainResolver(NewWhoisResolver(udig.timeout))
	udig.AddDomainResolver(NewTLSResolver(udig.timeout))
	udig.AddDomainResolver(NewHTTPResolver(udig.timeout))
	udig.AddDomainResolver(NewCTResolver(udig.timeout, udig.ctSince, udig.ctExclude, udig.ctPGConnStr))

	udig.AddIPResolver(NewBGPResolver(udig.timeout))
	udig.AddIPResolver(NewGeoResolver())
	udig.AddIPResolver(NewPTRResolver(udig.timeout))
	udig.AddIPResolver(NewRDAPResolver(udig.timeout))
	udig.AddIPResolver(NewDNSBLResolver(udig.timeout))
	udig.AddIPResolver(NewTorResolver(udig.timeout))

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
		depthOf:         map[string]int{},

		isDomainRelated: DefaultDomainRelation,
		timeout:         DefaultTimeout,
		ctSince:         "",
		ctExclude:       "expired",
		ctPGConnStr:     DefaultCTPGConnStr,
		maxDepth:        -1,
	}

	for _, opt := range opts {
		opt.apply(udig)
	}

	return udig
}

func (u *udigImpl) Resolve(ctx context.Context, domain string) <-chan Resolution {
	u.enqueueDomains(0, domain)

	resCh := make(chan Resolution, 256)
	go u.resolveInto(ctx, resCh)
	return resCh
}

func (u *udigImpl) AddDomainResolver(resolver DomainResolver) {
	u.domainResolvers = append(u.domainResolvers, resolver)
}

func (u *udigImpl) AddIPResolver(resolver IPResolver) {
	u.ipResolvers = append(u.ipResolvers, resolver)
}

func (u *udigImpl) resolveInto(ctx context.Context, resChan chan<- Resolution) {
	defer close(resChan)
	for len(u.domainQueue) > 0 {
		select {
		case <-ctx.Done():
			return
		default:
		}

		domain := <-u.domainQueue

		if u.maxDepth >= 0 && u.depthOf[domain] > u.maxDepth {
			// Max depth reached -> skip.
			continue
		}

		u.resolveDomainInto(domain, ctx, resChan)

		for len(u.ipQueue) > 0 {
			select {
			case <-ctx.Done():
				return
			default:
			}
			ip := <-u.ipQueue
			u.resolveIPInto(ip, resChan)
		}
	}
}

func (u *udigImpl) resolveDomainInto(domain string, ctx context.Context, resChan chan<- Resolution) {
	if u.isProcessed(domain) {
		return
	}
	defer u.addProcessed(domain)

	// Capture depth before spawning goroutines to avoid a concurrent map read
	// while other goroutines write depthOf via enqueueDomains.
	depth := u.depthOf[domain]

	var wg sync.WaitGroup
	wg.Add(len(u.domainResolvers))

	for _, resolver := range u.domainResolvers {
		go func(resolver DomainResolver) {
			defer wg.Done()
			resolutions := resolver.ResolveDomain(domain)
			for _, resolution := range resolutions {
				select {
				case resChan <- resolution:
					related := u.getRelatedDomains(resolution)
					u.enqueueDomains(depth+1, related...)
					u.enqueueIps(resolution.IPs()...)
				case <-ctx.Done():
					return
				}
			}
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
			defer wg.Done()
			for _, res := range resolver.ResolveIP(ip) {
				ch <- res
			}
		}(resolver)
	}

	wg.Wait()
}

func (u *udigImpl) isCnameOrRelated(nextDomain string, resolution Resolution) bool {
	if resolution.Type() == TypeDNS {
		dnsRes := resolution.(*DNSResolution)
		if dnsRes.Record.RR != nil && dnsRes.Record.RR.Header().Rrtype == dns.TypeCNAME {
			if dnsRes.Record.RR.(*dns.CNAME).Target == nextDomain {
				return true
			}
		}
	}

	return u.isDomainRelated(nextDomain, resolution.Query())
}

func (u *udigImpl) getRelatedDomains(resolution Resolution) (domains []string) {
	for _, nextDomain := range resolution.Domains() {
		// Crawl new and related domains only.
		if u.isProcessed(nextDomain) {
			continue
		}

		// Check-then-set must be atomic: two goroutines could both see isSeen==false
		// and both enqueue the same domain.
		u.mux.Lock()
		alreadySeen := u.seen[nextDomain]
		if !alreadySeen {
			u.seen[nextDomain] = true
		}
		u.mux.Unlock()
		if alreadySeen {
			continue
		}

		if !u.isCnameOrRelated(nextDomain, resolution) {
			LogDebug("%s: Domain %s is not related to %s -> skipping.", resolution.Type(), nextDomain, resolution.Query())
			continue
		}

		LogDebug("%s: Discovered a related domain %s via %s.", resolution.Type(), nextDomain, resolution.Query())

		domains = append(domains, nextDomain)
	}
	return domains
}

// enqueueDomains sets depth for each domain and enqueues it for resolution.
func (u *udigImpl) enqueueDomains(depth int, domains ...string) {
	for _, domain := range domains {
		u.mux.Lock()
		u.depthOf[domain] = depth
		u.mux.Unlock()
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
