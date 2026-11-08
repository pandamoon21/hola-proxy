package main

import (
	"context"
	"errors"
	"net"
	"sort"
	"strconv"
	"sync"
)

// portSelector returns the function picking the tunnel port for the
// configured proxy type. It is resolved once at startup so that a bad
// -proxy-type / -force-port-field fails fast instead of on every rotation.
func portSelector(typ string, trial bool, forcePortField string) (func(PortMap) uint16, error) {
	if forcePortField != "" {
		if port, err := strconv.ParseUint(forcePortField, 0, 16); err == nil {
			return func(PortMap) uint16 { return uint16(port) }, nil
		}
		typ = forcePortField
	}
	switch typ {
	case "skip":
		return func(PortMap) uint16 { return 0 }, nil
	case "direct", "lum", "pool", "virt":
		if !trial {
			return func(p PortMap) uint16 { return p.Trial }, nil
		}
		return func(p PortMap) uint16 { return p.Direct }, nil
	case "peer":
		if !trial {
			return func(p PortMap) uint16 { return p.TrialPeer }, nil
		}
		return func(p PortMap) uint16 { return p.Peer }, nil
	}
	return nil, errors.New("Unsupported port type")
}

// endpointsFromTunnels lists every tunnel in a zgettunnels response, ordered
// by hostname so that the preferred endpoint is stable across lookups.
func endpointsFromTunnels(tunnels *ZGetTunnelsResponse, port func(PortMap) uint16) []*Endpoint {
	hosts := make([]string, 0, len(tunnels.IPList))
	for host, ip := range tunnels.IPList {
		if host != "" && ip != "" {
			hosts = append(hosts, host)
		}
	}
	sort.Strings(hosts)
	eps := make([]*Endpoint, 0, len(hosts))
	p := port(tunnels.Port)
	for _, host := range hosts {
		eps = append(eps, &Endpoint{
			Host:    tunnels.IPList[host],
			Port:    p,
			TLSName: host,
		})
	}
	return eps
}

// UpstreamPool holds the current credentials and tunnel endpoints. Credential
// rotation replaces both together, so a dial never mixes credentials with an
// endpoint list from a different zgettunnels response.
type UpstreamPool struct {
	mu        sync.Mutex
	auth      string
	endpoints []*Endpoint
	preferred int
}

func (p *UpstreamPool) Auth() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.auth
}

// Update installs a new credential and endpoint set and makes its first
// endpoint the preferred one.
func (p *UpstreamPool) Update(auth string, endpoints []*Endpoint) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.auth = auth
	p.endpoints = endpoints
	p.preferred = 0
}

// Endpoints returns the endpoints in dial order, preferred one first.
func (p *UpstreamPool) Endpoints() []*Endpoint {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := len(p.endpoints)
	res := make([]*Endpoint, 0, n)
	for i := 0; i < n; i++ {
		res = append(res, p.endpoints[(p.preferred+i)%n])
	}
	return res
}

// MarkFailed moves the preference past ep if ep is still the preferred
// endpoint. A stale ep (from before an Update, or already skipped by a
// concurrent dial) leaves the preference alone.
func (p *UpstreamPool) MarkFailed(ep *Endpoint) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if n := len(p.endpoints); n > 0 && p.endpoints[p.preferred] == ep {
		p.preferred = (p.preferred + 1) % n
	}
}

// FailoverDialer dials through the pool's preferred endpoint and falls over
// to the next ones when an endpoint cannot be reached.
type FailoverDialer struct {
	pool   *UpstreamPool
	dialer func(*Endpoint) ContextDialer
	logger *CondLogger
}

func NewFailoverDialer(pool *UpstreamPool, dialer func(*Endpoint) ContextDialer, logger *CondLogger) *FailoverDialer {
	return &FailoverDialer{
		pool:   pool,
		dialer: dialer,
		logger: logger,
	}
}

func (d *FailoverDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	eps := d.pool.Endpoints()
	if len(eps) == 0 {
		return nil, errors.New("no upstream endpoints available")
	}
	var err error
	for i, ep := range eps {
		var conn net.Conn
		conn, err = d.dialer(ep).DialContext(ctx, network, address)
		if err == nil {
			return conn, nil
		}
		if !isEndpointFailure(ctx, err) {
			return nil, err
		}
		d.pool.MarkFailed(ep)
		if i+1 < len(eps) {
			d.logger.Warning("Upstream endpoint %s failed: %v. Switching to %s.",
				ep.URL(), err, eps[i+1].URL())
		} else {
			d.logger.Error("Upstream endpoint %s failed: %v. No endpoints left to try.",
				ep.URL(), err)
		}
	}
	return nil, err
}

func (d *FailoverDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

// isEndpointFailure reports whether err means the endpoint itself is
// unusable, so another endpoint may succeed. An answer from the agent (any
// CONNECT status, including a blocked host) means the endpoint works, and a
// cancelled or expired request would fail on every endpoint alike.
func isEndpointFailure(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return false
	}
	var statusErr *UpstreamStatusError
	return !errors.Is(err, UpstreamBlockedError) && !errors.As(err, &statusErr)
}
