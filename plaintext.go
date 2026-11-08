package main

import (
	"context"
	"crypto/x509"
	"errors"
	"net"

	tls "github.com/refraction-networking/utls"
)

type PlaintextDialer struct {
	fixedAddress  string
	tlsServerName string
	next          ContextDialer
	caPool        *x509.CertPool
	hideSNI       bool
}

func NewPlaintextDialer(address, tlsServerName string, caPool *x509.CertPool, hideSNI bool, next ContextDialer) *PlaintextDialer {
	return &PlaintextDialer{
		fixedAddress:  address,
		tlsServerName: tlsServerName,
		next:          next,
		caPool:        caPool,
		hideSNI:       hideSNI,
	}
}

func (d *PlaintextDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, errors.New("bad network specified for DialContext: only tcp is supported")
	}

	conn, err := d.next.DialContext(ctx, "tcp", d.fixedAddress)
	if err != nil {
		return nil, err
	}

	if d.tlsServerName != "" {
		tlsConn := tls.UClient(conn, verifyPeerTLSConfig(d.tlsServerName, d.hideSNI, d.caPool), tls.HelloChrome_Auto)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		return tlsConn, nil
	}
	return conn, nil
}

func (d *PlaintextDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}
