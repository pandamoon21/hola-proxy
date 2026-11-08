package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

const DEFAULT_LIST_LIMIT = 3

// CredService fetches tunnels and credentials into an UpstreamPool and, when
// interval is positive, refreshes both once per interval. A rotation replaces
// the endpoint list as well as the credentials, since a new zgettunnels
// response may point to different agents.
func CredService(interval, timeout time.Duration,
	extVer string,
	country string,
	proxytype string,
	port func(PortMap) uint16,
	logger *CondLogger,
	backoffInitial time.Duration,
	backoffDeadline time.Duration,
	baseProxy string,
) (pool *UpstreamPool, err error) {
	fetch := func(errMsg string) (*ZGetTunnelsResponse, string, error) {
		var (
			tunnels   *ZGetTunnelsResponse
			user_uuid string
		)
		tx_err := EnsureTransaction(context.Background(), timeout, baseProxy, func(ctx context.Context, purl string) error {
			tuns, uuidRes, terr := Tunnels(ctx, logger, purl, extVer, country, proxytype,
				DEFAULT_LIST_LIMIT, timeout, backoffInitial, backoffDeadline)
			if terr != nil {
				logger.Error("%s: %v. Retrying with the fallback mechanism...", errMsg, terr)
				return terr
			}
			tunnels, user_uuid = tuns, uuidRes
			return nil
		})
		if tx_err != nil {
			logger.Critical("Transaction recovery mechanism failure: %v", tx_err)
			return nil, "", tx_err
		}
		return tunnels, user_uuid, nil
	}

	tunnels, user_uuid, err := fetch("Configuration bootstrap error")
	if err != nil {
		return nil, err
	}
	pool = &UpstreamPool{}
	if err = applyTunnels(pool, user_uuid, tunnels, port); err != nil {
		return nil, err
	}
	logger.Info("Upstream endpoints: %s", describeEndpoints(pool.Endpoints()))
	if interval <= 0 {
		return pool, nil
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			<-ticker.C
			logger.Info("Rotating credentials...")
			tuns, user_uuid, err := fetch("Credential rotation error")
			if err != nil {
				if errors.Is(err, PermanentBanError) {
					// Stop rotating: each retry would only re-register
					// into the same ban.
					return
				}
				continue
			}
			if err := applyTunnels(pool, user_uuid, tuns, port); err != nil {
				logger.Error("Keeping previous credentials and endpoints: %v", err)
				continue
			}
			logger.Info("Credentials rotated successfully. Upstream endpoints: %s",
				describeEndpoints(pool.Endpoints()))
		}
	}()
	return pool, nil
}

// applyTunnels installs the credentials and endpoints of one zgettunnels
// response into pool. A response without usable tunnels leaves pool as is.
func applyTunnels(pool *UpstreamPool, user_uuid string, tunnels *ZGetTunnelsResponse, port func(PortMap) uint16) error {
	eps := endpointsFromTunnels(tunnels, port)
	if len(eps) == 0 {
		return fmt.Errorf("no tunnels found in API response")
	}
	pool.Update(basic_auth_header(TemplateLogin(user_uuid), tunnels.AgentKey), eps)
	return nil
}

func describeEndpoints(eps []*Endpoint) string {
	urls := make([]string, 0, len(eps))
	for _, ep := range eps {
		urls = append(urls, ep.URL().String())
	}
	return strings.Join(urls, ", ")
}
