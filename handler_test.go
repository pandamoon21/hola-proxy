package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// fakeDialer hands out a pre-made connection or a fixed error.
type fakeDialer struct {
	conn net.Conn
	err  error
}

func (d *fakeDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d *fakeDialer) DialContext(_ context.Context, _, _ string) (net.Conn, error) {
	if d.err != nil {
		return nil, d.err
	}
	return d.conn, nil
}

func newTestHandler(dialer, requestDialer ContextDialer) *ProxyHandler {
	return NewProxyHandler(dialer, requestDialer, func() string { return basic_auth_header("l", "p") }, "", nil, NewCondLogger(log.New(io.Discard, "", 0), 0))
}

func TestHandleTunnelForwardsPipelinedClientData(t *testing.T) {
	upstreamLocal, upstreamRemote := net.Pipe()
	defer upstreamRemote.Close()
	h := newTestHandler(&fakeDialer{conn: upstreamLocal}, &fakeDialer{err: errors.New("unused")})
	srv := httptest.NewServer(h)
	defer srv.Close()

	client, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	payload := "\x16\x03\x01client-hello-bytes"
	if _, err := io.WriteString(client, "CONNECT host:443 HTTP/1.1\r\nHost: host:443\r\n\r\n"+payload); err != nil {
		t.Fatal(err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	upstreamRemote.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(upstreamRemote, got); err != nil {
		t.Fatalf("upstream did not receive pipelined data: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("upstream got %q, want %q", got, payload)
	}
}

func TestHandleRequestRoundTripFailureIsBadGateway(t *testing.T) {
	h := newTestHandler(&fakeDialer{err: errors.New("unused")}, &fakeDialer{err: errors.New("upstream down")})
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	wr := httptest.NewRecorder()
	h.ServeHTTP(wr, req)
	if wr.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", wr.Code)
	}
}

func TestHandleTunnelClosesUpstreamWhenHijackFails(t *testing.T) {
	upstreamLocal, upstreamRemote := net.Pipe()
	defer upstreamRemote.Close()
	h := newTestHandler(&fakeDialer{conn: upstreamLocal}, &fakeDialer{err: errors.New("unused")})
	req := httptest.NewRequest("CONNECT", "http://example.com:443", nil)
	req.RequestURI = "example.com:443"
	wr := httptest.NewRecorder() // does not implement http.Hijacker
	h.HandleTunnel(wr, req)
	if wr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", wr.Code)
	}

	upstreamRemote.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := upstreamRemote.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("expected upstream conn to be closed (EOF), got %v", err)
	}
}
