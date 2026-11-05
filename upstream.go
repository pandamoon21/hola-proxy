package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"

	tls "github.com/refraction-networking/utls"
)

const (
	PROXY_CONNECT_METHOD       = "CONNECT"
	PROXY_HOST_HEADER          = "Host"
	PROXY_AUTHORIZATION_HEADER = "Proxy-Authorization"
	PROXY_CONNECTION_HEADER    = "Proxy-Connection"
	PROXY_HOLA_HOST_HEADER     = "Proxy-Host"
)

// PROXY_CONNECT_HOST_HEADER is the special Host value Hola's extension uses
// when it asks a zagent for a tunnel.
const PROXY_CONNECT_HOST_VALUE = "-"

var UpstreamBlockedError = errors.New("blocked by upstream")

type Dialer interface {
	Dial(network, address string) (net.Conn, error)
}

type ContextDialer interface {
	Dialer
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type ProxyDialer struct {
	address       string
	tlsServerName string
	auth          AuthProvider
	next          ContextDialer
	caPool        *x509.CertPool
	hideSNI       bool
}

func NewProxyDialer(address, tlsServerName string, caPool *x509.CertPool, auth AuthProvider, hideSNI bool, nextDialer ContextDialer) *ProxyDialer {
	return &ProxyDialer{
		address:       address,
		tlsServerName: tlsServerName,
		auth:          auth,
		next:          nextDialer,
		caPool:        caPool,
		hideSNI:       hideSNI,
	}
}

func ProxyDialerFromURL(u *url.URL, caPool *x509.CertPool, next ContextDialer) (*ProxyDialer, error) {
	host := u.Hostname()
	port := u.Port()
	tlsServerName := ""
	var auth AuthProvider = nil

	switch strings.ToLower(u.Scheme) {
	case "http":
		if port == "" {
			port = "80"
		}
	case "https":
		if port == "" {
			port = "443"
		}
		tlsServerName = host
	default:
		return nil, errors.New("unsupported proxy type")
	}

	address := net.JoinHostPort(host, port)

	if u.User != nil {
		username := u.User.Username()
		password, _ := u.User.Password()
		authHeader := basic_auth_header(username, password)
		auth = func() string {
			return authHeader
		}
	}
	return NewProxyDialer(address, tlsServerName, caPool, auth, false, next), nil
}

func (d *ProxyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, errors.New("bad network specified for DialContext: only tcp is supported")
	}

	conn, err := d.next.DialContext(ctx, "tcp", d.address)
	if err != nil {
		return nil, err
	}

	if d.tlsServerName != "" {
		// Custom cert verification logic:
		// DO NOT send SNI extension of TLS ClientHello
		// DO peer certificate verification against specified servername
		sni := d.tlsServerName
		if d.hideSNI {
			sni = ""
		}
		conn = tls.UClient(conn, &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
			VerifyConnection: func(cs tls.ConnectionState) error {
				opts := x509.VerifyOptions{
					DNSName:       d.tlsServerName,
					Intermediates: x509.NewCertPool(),
					Roots:         d.caPool,
				}
				for _, cert := range cs.PeerCertificates[1:] {
					opts.Intermediates.AddCert(cert)
				}
				_, err := cs.PeerCertificates[0].Verify(opts)
				return err
			},
		}, tls.HelloChrome_Auto)
	}

	var authHeader string
	if d.auth != nil {
		authHeader = d.auth()
	}
	req := buildProxyConnectRequest(address, authHeader)

	rawreq, err := httputil.DumpRequest(req, false)
	if err != nil {
		return nil, err
	}
	rawreq = orderRequestHeaders(rawreq, PROXY_HEADER_ORDER)

	_, err = conn.Write(rawreq)
	if err != nil {
		return nil, err
	}

	proxyResp, err := readResponse(conn, req)
	if err != nil {
		return nil, err
	}

	if proxyResp.StatusCode != http.StatusOK {
		if proxyResp.StatusCode == http.StatusForbidden &&
			proxyResp.Header.Get("X-Hola-Error") == "Forbidden Host" {
			return nil, UpstreamBlockedError
		}
		return nil, errors.New(fmt.Sprintf("bad response from upstream proxy server: %s", proxyResp.Status))
	}

	return conn, nil
}

// buildProxyConnectRequest builds a CONNECT request shaped like the one
// Hola's browser extension sends to a zagent: Host "-", the tunnel target in
// Proxy-Host, Proxy-Connection and the extension headers. Nested proxies (our
// own -proxy, or a fallback agent in front of ours) check all of these before
// accepting the credentials; with Go's default headers the agent answers
// "407 Auth Failed suspicious".
func buildProxyConnectRequest(address, authHeader string) *http.Request {
	req := &http.Request{
		Method:     PROXY_CONNECT_METHOD,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		RequestURI: address,
		Host:       PROXY_CONNECT_HOST_VALUE,
		Header: http.Header{
			PROXY_HOST_HEADER: []string{PROXY_CONNECT_HOST_VALUE},
		},
	}
	req.Header.Set(PROXY_CONNECTION_HEADER, "Keep-Alive")
	req.Header.Set(PROXY_HOLA_HOST_HEADER, address)
	req.Header.Set("Origin", EXT_ORIGIN)
	req.Header.Set("Accept-Encoding", ACCEPT_ENCODING)
	req.Header.Set("Accept-Language", ACCEPT_LANGUAGE)
	if authHeader != "" {
		req.Header.Set(PROXY_AUTHORIZATION_HEADER, authHeader)
	}
	return req
}

// orderRequestHeaders rewrites the header block of a dumped HTTP request so
// that headers listed in order come first, in that order, and the rest keep
// their original relative order (mirrors the CycleTLS HeaderOrder behaviour
// used for API requests).
func orderRequestHeaders(raw []byte, order []string) []byte {
	sep := []byte("\r\n\r\n")
	i := bytes.Index(raw, sep)
	if i < 0 {
		return raw
	}
	head, rest := raw[:i], raw[i+len(sep):]
	lines := bytes.Split(head, []byte("\r\n"))
	if len(lines) < 2 {
		return raw
	}
	start := 1
	for start < len(lines) && (lines[start][0] == ' ' || lines[start][0] == '\t') {
		start++
	}
	header := lines[start:]
	rank := make(map[string]int, len(order))
	for i, name := range order {
		rank[name] = i
	}
	// Stable partition: known headers first (by rank), unknown afterwards.
	keyed := make([]string, len(header))
	for i, h := range header {
		keyed[i] = strings.ToLower(string(bytes.SplitN(h, []byte(":"), 2)[0]))
	}
	idx := make([]int, len(header))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool {
		ra, oka := rank[keyed[idx[a]]]
		rb, okb := rank[keyed[idx[b]]]
		switch {
		case oka && okb:
			return ra < rb
		case oka:
			return true
		case okb:
			return false
		}
		return false
	})
	out := &bytes.Buffer{}
	for _, l := range lines[:start] {
		out.Write(l)
		out.WriteString("\r\n")
	}
	for _, i := range idx {
		out.Write(header[i])
		out.WriteString("\r\n")
	}
	out.WriteString("\r\n")
	out.Write(rest)
	return out.Bytes()
}

func (d *ProxyDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func readResponse(r io.Reader, req *http.Request) (*http.Response, error) {
	endOfResponse := []byte("\r\n\r\n")
	buf := &bytes.Buffer{}
	b := make([]byte, 1)
	for {
		n, err := r.Read(b)
		if n < 1 && err == nil {
			continue
		}

		buf.Write(b)
		sl := buf.Bytes()
		if len(sl) < len(endOfResponse) {
			continue
		}

		if bytes.Equal(sl[len(sl)-4:], endOfResponse) {
			break
		}

		if err != nil {
			return nil, err
		}
	}
	return http.ReadResponse(bufio.NewReader(buf), req)
}
