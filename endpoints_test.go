package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"testing"
)

func testPorts() PortMap {
	return PortMap{Direct: 1, Hola: 2, Peer: 3, Trial: 4, TrialPeer: 5}
}

func TestPortSelector(t *testing.T) {
	cases := []struct {
		typ   string
		trial bool
		force string
		want  uint16
	}{
		{"direct", false, "", 4},
		{"direct", true, "", 1},
		{"lum", false, "", 4},
		{"peer", false, "", 5},
		{"peer", true, "", 3},
		{"skip", false, "", 0},
		{"direct", false, "24232", 24232},
		{"direct", false, "peer", 5},
	}
	for _, c := range cases {
		sel, err := portSelector(c.typ, c.trial, c.force)
		if err != nil {
			t.Fatalf("%+v: unexpected error %v", c, err)
		}
		if got := sel(testPorts()); got != c.want {
			t.Fatalf("%+v: got port %d, want %d", c, got, c.want)
		}
	}
	if _, err := portSelector("bogus", false, ""); err == nil {
		t.Fatal("expected error for unsupported port type")
	}
}

func TestEndpointsFromTunnels(t *testing.T) {
	tuns := &ZGetTunnelsResponse{
		IPList: map[string]string{"zagent2.hola.org": "2.2.2.2", "zagent1.hola.org": "1.1.1.1", "bad": ""},
		Port:   testPorts(),
	}
	sel, _ := portSelector("direct", true, "")
	eps := endpointsFromTunnels(tuns, sel)
	if len(eps) != 2 {
		t.Fatalf("expected 2 endpoints, got %d", len(eps))
	}
	if eps[0].TLSName != "zagent1.hola.org" || eps[0].NetAddr() != "1.1.1.1:1" ||
		eps[1].TLSName != "zagent2.hola.org" || eps[1].NetAddr() != "2.2.2.2:1" {
		t.Fatalf("unexpected endpoints: %+v %+v", eps[0], eps[1])
	}
}

func testEndpoints(names ...string) []*Endpoint {
	eps := make([]*Endpoint, 0, len(names))
	for _, n := range names {
		eps = append(eps, &Endpoint{Host: n, Port: 443, TLSName: n})
	}
	return eps
}

func TestUpstreamPoolPreference(t *testing.T) {
	pool := &UpstreamPool{}
	eps := testEndpoints("a", "b", "c")
	pool.Update("auth1", eps)
	pool.MarkFailed(eps[0])
	if got := pool.Endpoints(); got[0] != eps[1] || got[2] != eps[0] {
		t.Fatalf("expected rotation to b, got %v", got)
	}
	// A stale failure report (a was already skipped) must not move on to c.
	pool.MarkFailed(eps[0])
	if got := pool.Endpoints(); got[0] != eps[1] {
		t.Fatalf("stale MarkFailed changed preference to %v", got[0])
	}
	eps2 := testEndpoints("d", "e")
	pool.Update("auth2", eps2)
	pool.MarkFailed(eps[1]) // from the replaced set
	if got := pool.Endpoints(); got[0] != eps2[0] || pool.Auth() != "auth2" {
		t.Fatalf("Update should reset preference and auth, got %v %q", got[0], pool.Auth())
	}
}

// dialerMap records which endpoints were dialed and answers per endpoint.
type dialerMap struct {
	results map[string]*fakeDialer
	dialed  []string
}

func (m *dialerMap) factory(ep *Endpoint) ContextDialer {
	m.dialed = append(m.dialed, ep.Host)
	return m.results[ep.Host]
}

func testLogger() *CondLogger {
	return NewCondLogger(log.New(io.Discard, "", 0), 100)
}

func TestFailoverDialerSwitchesOnTransportError(t *testing.T) {
	pool := &UpstreamPool{}
	pool.Update("auth", testEndpoints("a", "b", "c"))
	good, _ := net.Pipe()
	m := &dialerMap{results: map[string]*fakeDialer{
		"a": {err: errors.New("connection refused")},
		"b": {conn: good},
		"c": {err: errors.New("unused")},
	}}
	d := NewFailoverDialer(pool, m.factory, testLogger())
	conn, err := d.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil || conn != good {
		t.Fatalf("expected conn from b, got %v %v", conn, err)
	}
	// The next dial goes straight to b.
	m.dialed = nil
	if _, err := d.DialContext(context.Background(), "tcp", "example.com:443"); err != nil {
		t.Fatal(err)
	}
	if len(m.dialed) != 1 || m.dialed[0] != "b" {
		t.Fatalf("expected only b to be dialed, got %v", m.dialed)
	}
}

func TestFailoverDialerAllFail(t *testing.T) {
	pool := &UpstreamPool{}
	pool.Update("auth", testEndpoints("a", "b"))
	last := errors.New("b down")
	m := &dialerMap{results: map[string]*fakeDialer{
		"a": {err: errors.New("a down")},
		"b": {err: last},
	}}
	_, err := NewFailoverDialer(pool, m.factory, testLogger()).DialContext(context.Background(), "tcp", "x:1")
	if err != last || len(m.dialed) != 2 {
		t.Fatalf("expected last error after 2 dials, got %v after %v", err, m.dialed)
	}
}

func TestFailoverDialerKeepsEndpointOnAgentAnswer(t *testing.T) {
	for _, tc := range []struct {
		name    string
		resp    string
		wantErr func(error) bool
	}{
		{"blocked", "HTTP/1.1 403 Forbidden\r\nX-Hola-Error: Forbidden Host\r\n\r\n",
			func(err error) bool { return err == UpstreamBlockedError }},
		{"status", "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n",
			func(err error) bool { var s *UpstreamStatusError; return errors.As(err, &s) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pool := &UpstreamPool{}
			pool.Update("auth", testEndpoints("a", "b"))
			client, server := net.Pipe()
			defer server.Close()
			go func() {
				br := bufio.NewReader(server)
				if _, err := http.ReadRequest(br); err == nil {
					io.WriteString(server, tc.resp)
				}
			}()
			var dialed []string
			d := NewFailoverDialer(pool, func(ep *Endpoint) ContextDialer {
				dialed = append(dialed, ep.Host)
				return NewProxyDialer(ep.NetAddr(), "", nil, pool.Auth, false, &fakeDialer{conn: client})
			}, testLogger())
			_, err := d.DialContext(context.Background(), "tcp", "example.com:443")
			if !tc.wantErr(err) {
				t.Fatalf("unexpected error %v", err)
			}
			if len(dialed) != 1 || pool.Endpoints()[0].Host != "a" {
				t.Fatalf("agent answer must not trigger failover, dialed %v", dialed)
			}
		})
	}
}

func TestFailoverDialerStopsOnCancelledContext(t *testing.T) {
	pool := &UpstreamPool{}
	pool.Update("auth", testEndpoints("a", "b"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m := &dialerMap{results: map[string]*fakeDialer{
		"a": {err: context.Canceled},
		"b": {err: errors.New("unused")},
	}}
	_, err := NewFailoverDialer(pool, m.factory, testLogger()).DialContext(ctx, "tcp", "x:1")
	if !errors.Is(err, context.Canceled) || len(m.dialed) != 1 {
		t.Fatalf("expected no failover on cancel, got %v after %v", err, m.dialed)
	}
	if pool.Endpoints()[0].Host != "a" {
		t.Fatal("cancelled dial must not demote the endpoint")
	}
}

func TestApplyTunnelsReplacesEndpointsAndAuth(t *testing.T) {
	sel, _ := portSelector("direct", true, "")
	pool := &UpstreamPool{}
	first := &ZGetTunnelsResponse{AgentKey: "k1", IPList: map[string]string{"old.hola.org": "1.1.1.1"}, Port: testPorts()}
	if err := applyTunnels(pool, "u1", first, sel); err != nil {
		t.Fatal(err)
	}
	second := &ZGetTunnelsResponse{AgentKey: "k2", IPList: map[string]string{"new.hola.org": "2.2.2.2"}, Port: testPorts()}
	if err := applyTunnels(pool, "u2", second, sel); err != nil {
		t.Fatal(err)
	}
	eps := pool.Endpoints()
	if len(eps) != 1 || eps[0].TLSName != "new.hola.org" {
		t.Fatalf("rotation should replace endpoints, got %+v", eps)
	}
	if pool.Auth() != basic_auth_header(TemplateLogin("u2"), "k2") {
		t.Fatal("rotation should replace auth")
	}
	empty := &ZGetTunnelsResponse{AgentKey: "k3", Port: testPorts()}
	if err := applyTunnels(pool, "u3", empty, sel); err == nil {
		t.Fatal("expected error for response without tunnels")
	}
	if pool.Endpoints()[0].TLSName != "new.hola.org" || pool.Auth() != basic_auth_header(TemplateLogin("u2"), "k2") {
		t.Fatal("empty response must leave the pool unchanged")
	}
}
