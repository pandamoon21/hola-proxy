package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestOrderRequestHeaders(t *testing.T) {
	raw := "CONNECT hola.org:443 HTTP/1.1\r\nUser-Agent: ua\r\nHost: -\r\n" +
		"Proxy-Authorization: Basic abc\r\nProxy-Connection: Keep-Alive\r\n" +
		"Proxy-Host: hola.org:443\r\n\r\n"
	got := string(orderRequestHeaders([]byte(raw), PROXY_HEADER_ORDER))
	want := "CONNECT hola.org:443 HTTP/1.1\r\nHost: -\r\nProxy-Connection: Keep-Alive\r\n" +
		"Proxy-Authorization: Basic abc\r\nUser-Agent: ua\r\nProxy-Host: hola.org:443\r\n\r\n"
	if got != want {
		t.Fatalf("unexpected header order:\n got: %q\nwant: %q", got, want)
	}
	if strings.Index(got, "Proxy-Authorization") > strings.Index(got, "Proxy-Host") {
		t.Fatal("Proxy-Authorization should precede Proxy-Host")
	}
}

func TestProxyConnectRequestShape(t *testing.T) {
	req := buildProxyConnectRequest("hola.org:443", basic_auth_header("l", "p"))
	if req.Host != "-" {
		t.Fatalf("expected Host \"-\", got %q", req.Host)
	}
	for _, h := range []string{"Proxy-Host", "Proxy-Connection", "Proxy-Authorization",
		"Origin", "Accept-Language", "Accept-Encoding"} {
		if req.Header.Get(h) == "" {
			t.Fatalf("missing %s", h)
		}
	}
	if req.Header.Get("Proxy-Host") != "hola.org:443" {
		t.Fatalf("Proxy-Host should carry the tunnel target, got %q", req.Header.Get("Proxy-Host"))
	}
	if !strings.HasPrefix(req.Header.Get("Proxy-Authorization"), "Basic ") {
		t.Fatal("expected Basic scheme")
	}
}

// scratchEOFReader serves data, then returns (0, io.EOF) while scribbling
// fill into p, which io.Reader permits ("may use all of p as scratch space").
type scratchEOFReader struct {
	data []byte
	fill byte
}

func (r *scratchEOFReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		for i := range p {
			p[i] = r.fill
		}
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

type endlessReader struct{ n int }

func (r *endlessReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	r.n += len(p)
	return len(p), nil
}

func TestReadResponseEOFMidHeaders(t *testing.T) {
	r := &scratchEOFReader{data: []byte("HTTP/1.1 200 OK\r\nX: y\r\n\r"), fill: '\n'}
	resp, err := readResponse(r, nil)
	if err == nil {
		t.Fatalf("expected error, got response %v", resp.Status)
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected io.ErrUnexpectedEOF, got %v", err)
	}

	_, err = readResponse(strings.NewReader("HTTP/1.1 200 OK\r\n"), nil)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected io.ErrUnexpectedEOF, got %v", err)
	}
}

func TestReadResponseHeaderTooLarge(t *testing.T) {
	r := &endlessReader{}
	done := make(chan error, 1)
	go func() {
		_, err := readResponse(r, nil)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error for oversized header")
		}
		if r.n > 2*64*1024 {
			t.Fatalf("read %d bytes, expected a cap near 64 KiB", r.n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("readResponse did not stop on an oversized header")
	}
}

func TestReadResponseDoesNotOverRead(t *testing.T) {
	r := strings.NewReader("HTTP/1.1 200 OK\r\nX: y\r\n\r\nTUNNEL")
	resp, err := readResponse(r, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || resp.Header.Get("X") != "y" {
		t.Fatalf("bad parse: %v %v", resp.Status, resp.Header)
	}
	rest, _ := io.ReadAll(r)
	if string(rest) != "TUNNEL" {
		t.Fatalf("tunnel bytes consumed: remaining %q", rest)
	}
}

type pipeDialer struct{ conn net.Conn }

func (d *pipeDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d *pipeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.conn, nil
}

// startFakeProxy reads one CONNECT request from server and answers it with
// resp, or never answers if resp is empty.
func startFakeProxy(server net.Conn, resp string) {
	go func() {
		if _, err := http.ReadRequest(bufio.NewReader(server)); err != nil {
			return
		}
		if resp != "" {
			server.Write([]byte(resp))
		}
	}()
}

// assertPeerClosed checks that the client end of the pipe was closed, which
// makes reads on the server end fail with io.EOF.
func assertPeerClosed(t *testing.T, server net.Conn) {
	t.Helper()
	server.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := server.Read(make([]byte, 1))
	if err != io.EOF {
		t.Fatalf("expected upstream conn to be closed (io.EOF), got %v", err)
	}
}

func TestDialContextBlockedClosesConn(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	startFakeProxy(server, "HTTP/1.1 403 Forbidden\r\nX-Hola-Error: Forbidden Host\r\nContent-Length: 0\r\n\r\n")
	d := NewProxyDialer("upstream:1", "", nil, nil, false, &pipeDialer{client})
	conn, err := d.DialContext(context.Background(), "tcp", "example.com:443")
	if err != UpstreamBlockedError {
		t.Fatalf("expected UpstreamBlockedError, got conn=%v err=%v", conn, err)
	}
	assertPeerClosed(t, server)
}

func TestDialContextBadStatusClosesConn(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	startFakeProxy(server, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
	d := NewProxyDialer("upstream:1", "", nil, nil, false, &pipeDialer{client})
	conn, err := d.DialContext(context.Background(), "tcp", "example.com:443")
	if err == nil {
		t.Fatalf("expected error, got conn %v", conn)
	}
	assertPeerClosed(t, server)
}

func TestDialContextStalledUpstreamHonorsDeadline(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	defer client.Close()
	startFakeProxy(server, "")
	d := NewProxyDialer("upstream:1", "", nil, nil, false, &pipeDialer{client})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := d.DialContext(ctx, "tcp", "example.com:443")
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected context.DeadlineExceeded, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("DialContext ignored ctx deadline on a stalled upstream")
	}
}

func TestDialContextStalledUpstreamHonorsCancel(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	defer client.Close()
	startFakeProxy(server, "")
	d := NewProxyDialer("upstream:1", "", nil, nil, false, &pipeDialer{client})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := d.DialContext(ctx, "tcp", "example.com:443")
		done <- err
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("DialContext ignored ctx cancellation on a stalled upstream")
	}
}

func TestDialContextSuccessClearsDeadline(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	startFakeProxy(server, "HTTP/1.1 200 OK\r\n\r\n")
	d := NewProxyDialer("upstream:1", "", nil, nil, false, &pipeDialer{client})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	conn, err := d.DialContext(ctx, "tcp", "example.com:443")
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	defer conn.Close()
	cancel()
	time.Sleep(300 * time.Millisecond) // past the original ctx deadline
	go server.Write([]byte("x"))
	if _, err := conn.Read(make([]byte, 1)); err != nil {
		t.Fatalf("tunnel unusable after ctx ended: %v", err)
	}
}
