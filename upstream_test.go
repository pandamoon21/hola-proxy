package main

import (
	"strings"
	"testing"
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
