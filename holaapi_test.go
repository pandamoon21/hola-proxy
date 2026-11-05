package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCommonParams(t *testing.T) {
	params := commonParams("1.2.3")
	for _, k := range []string{"rmt_ver", "ext_ver", "browser", "product", "lccgi"} {
		if params.Get(k) == "" {
			t.Fatalf("commonParams missing %s", k)
		}
	}
	if params.Get("ext_ver") != "1.2.3" || params.Get("rmt_ver") != "1.2.3" {
		t.Fatal("ext_ver/rmt_ver mismatch")
	}
}

func TestZGetTunnelsBlockedParsing(t *testing.T) {
	var res ZGetTunnelsResponse
	if err := json.Unmarshal([]byte(`{"blocked":true,"permanent":true}`), &res); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if !res.Blocked || !res.Permanent {
		t.Fatalf("expected blocked+permanent, got %+v", res)
	}
}

func TestEnsureTransactionAbortsOnPermanentBan(t *testing.T) {
	calls := 0
	err := EnsureTransaction(context.Background(), time.Second, "", func(_ context.Context, _ string) error {
		calls++
		return PermanentBanError
	})
	if !errors.Is(err, PermanentBanError) {
		t.Fatalf("expected PermanentBanError, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected abort after first attempt, got %d calls", calls)
	}
}

func TestEnsureTransactionSuccess(t *testing.T) {
	calls := 0
	err := EnsureTransaction(context.Background(), time.Second, "", func(_ context.Context, _ string) error {
		calls++
		return nil
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected a single attempt, got %d calls", calls)
	}
}

func TestBasicAuthHeaderCanonicalScheme(t *testing.T) {
	h := basic_auth_header("login", "pass")
	if !strings.HasPrefix(h, "Basic ") {
		t.Fatalf("expected canonical Basic scheme, got %q", h)
	}
}

func TestProxyAuthRejectsMissingCredentials(t *testing.T) {
	d := &net.Dialer{}
	h := NewProxyHandler(d, d, func() string { return basic_auth_header("l", "p") }, "user:pass", nil, NewCondLogger(log.New(io.Discard, "", 0), 0))
	req := httptest.NewRequest("CONNECT", "http://example.com:443", nil)
	req.RequestURI = "example.com:443"
	wr := httptest.NewRecorder()
	h.ServeHTTP(wr, req)
	if wr.Code != http.StatusProxyAuthRequired {
		t.Fatalf("expected 407, got %d", wr.Code)
	}
	if wr.Header().Get("Proxy-Authenticate") == "" {
		t.Fatal("expected Proxy-Authenticate header")
	}
}
