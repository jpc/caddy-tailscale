// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: Apache-2.0

package tscaddy

// service.go contains the listener for Tailscale Services
// (https://tailscale.com/kb/1552/tailscale-services).

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	proxyproto "github.com/pires/go-proxyproto"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
)

func init() {
	caddy.RegisterNetwork("tailscale+svc", getServiceListener)
}

// getServiceListener returns a listener that advertises a Tailscale Service
// from a tsnet node. The address format is:
//
//	tailscale+svc/<service>@<node>:<port>
//
// where <service> is the Service name with or without the "svc:" prefix
// (e.g. "research"), and <node> is the name of a node configured in the
// tailscale app (the node hosting the Service must be tagged).
//
// Multiple nodes (typically on different machines) can advertise the same
// Service; Tailscale routes clients to a healthy host, which provides failover.
//
// tailscaled terminates TLS for the Service's FQDN, so the listener yields
// plaintext HTTP connections. Do not configure TLS connection policies for a
// server using this listener. The original peer address is recovered via the
// PROXY protocol, so r.RemoteAddr is the client's Tailscale IP and the
// tailscale authentication provider works as usual.
func getServiceListener(c context.Context, network string, host string, portRange string, portOffset uint, _ net.ListenConfig) (any, error) {
	ctx, ok := c.(caddy.Context)
	if !ok {
		return nil, fmt.Errorf("context is not a caddy.Context: %T", c)
	}

	na, err := caddy.ParseNetworkAddress(caddy.JoinNetworkAddress(network, host, portRange))
	if err != nil {
		return nil, err
	}

	addr := na.JoinHostPort(portOffset)
	_, host, port, err := caddy.SplitNetworkAddress(addr)
	if err != nil {
		return nil, err
	}

	svc, nodeName, ok := strings.Cut(host, "@")
	if !ok || svc == "" || nodeName == "" {
		return nil, fmt.Errorf("invalid Tailscale Service address %q: expected tailscale+svc/<service>@<node>:<port>", addr)
	}
	svcName := tailcfg.ServiceName("svc:" + strings.TrimPrefix(svc, "svc:"))
	if err := svcName.Validate(); err != nil {
		return nil, err
	}

	portNum, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNum == 0 {
		return nil, fmt.Errorf("invalid port %q for Tailscale Service %s", port, svcName)
	}

	// Get node reference for this listener (increments node reference count)
	node, err := getNode(ctx, nodeName)
	if err != nil {
		return nil, err
	}

	lnKey := fmt.Sprintf("tailscale+svc/%s@%s:%s", svcName.WithoutPrefix(), nodeName, port)

	sharedLn, _, err := tailscaleListeners.LoadOrNew(lnKey, func() (caddy.Destructor, error) {
		ln, err := node.ListenService(svcName.String(), tsnet.ServiceModeTCP{
			Port:                 uint16(portNum),
			TerminateTLS:         true,
			PROXYProtocolVersion: 2,
		})
		if err != nil {
			return nil, fmt.Errorf("listening on Tailscale Service %s: %w", svcName, err)
		}

		return &tailscaleSharedListener{
			Listener: &serviceListener{
				Listener: &proxyproto.Listener{
					Listener: ln,
					// The listener is bound to localhost and only tailscaled
					// should connect to it; always require the PROXY header so
					// a missing one can't masquerade as a local peer.
					ConnPolicy: func(proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
						return proxyproto.REQUIRE, nil
					},
				},
				server: node.Server,
			},
			key: lnKey,
		}, nil
	})
	if err != nil {
		_, _ = nodes.Delete(nodeName) // release the node reference taken above
		return nil, err
	}

	return &tailscaleFakeCloseListener{
		tailscaleSharedListener: sharedLn.(*tailscaleSharedListener),
		node:                    &fakeCloseNode{nodeName: nodeName, node: node},
	}, nil
}

// serviceListener wraps a Tailscale Service listener and exposes the tsnet
// server it belongs to, so the tailscale auth provider can find the right
// LocalClient for WhoIs lookups.
type serviceListener struct {
	net.Listener
	server *tsnet.Server
}

func (l *serviceListener) Server() *tsnet.Server { return l.server }
