// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: Apache-2.0

// Package tscaddy provides a set of Caddy modules to integrate Tailscale into Caddy.
package tscaddy

// module.go contains the Tailscale network listeners for caddy
// as well as some shared logic for registered Tailscale nodes.

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/certmagic"
	"github.com/tailscale/tscert"
	"go.uber.org/zap"
	"tailscale.com/client/local"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn"
	"tailscale.com/tsnet"
	"tailscale.com/util/mak"
)

func init() {
	caddy.RegisterNetwork("tailscale", getTCPListener)
	caddy.RegisterNetwork("tailscale+tls", getTLSListener)
	caddy.RegisterNetwork("tailscale+funnel", getFunnelListener)
	caddy.RegisterNetwork("tailscale+funnel-only", getFunnelOnlyListener)
	caddy.RegisterNetwork("tailscale/udp", getUDPListener)
	caddyhttp.RegisterNetworkHTTP3("tailscale/udp", "tailscale/udp")
	caddyhttp.RegisterNetworkHTTP3("tailscale", "tailscale/udp")

	// Caddy uses tscert to get certificates for Tailscale hostnames.
	// Update the tscert transport to send requests to the correct tsnet server,
	// rather than just always connecting to the local machine's tailscaled.
	tscert.TailscaledTransport = &tsnetMuxTransport{}
	hostinfo.SetApp("caddy")
}

func getTCPListener(c context.Context, network string, host string, portRange string, portOffset uint, _ net.ListenConfig) (any, error) {
	ctx, ok := c.(caddy.Context)
	if !ok {
		return nil, fmt.Errorf("context is not a caddy.Context: %T", c)
	}

	na, err := caddy.ParseNetworkAddress(caddy.JoinNetworkAddress(network, host, portRange))
	if err != nil {
		return nil, err
	}

	addr := na.JoinHostPort(portOffset)
	network, host, port, err := caddy.SplitNetworkAddress(addr)
	if err != nil {
		return nil, err
	}

	if network == "" {
		network = "tcp"
	}

	// Get node reference for this listener (increments node reference count)
	node, err := getNode(ctx, host)
	if err != nil {
		return nil, err
	}

	// Follow Caddy's standard listener pooling mechanism
	lnKey := fmt.Sprintf("tailscale/%s:%s:%s", host, network, port)

	sharedLn, _, err := tailscaleListeners.LoadOrNew(lnKey, func() (caddy.Destructor, error) {
		ln, err := node.Listen(network, ":"+port)
		if err != nil {
			return nil, err
		}

		return &tailscaleSharedListener{
			Listener: ln,
			key:      lnKey,
		}, nil
	})
	if err != nil {
		return nil, err
	}

	return &tailscaleFakeCloseListener{
		tailscaleSharedListener: sharedLn.(*tailscaleSharedListener),
		node:                    &fakeCloseNode{nodeName: host, node: node},
	}, nil
}

func getTLSListener(c context.Context, network string, host string, portRange string, portOffset uint, _ net.ListenConfig) (any, error) {
	ctx, ok := c.(caddy.Context)
	if !ok {
		return nil, fmt.Errorf("context is not a caddy.Context: %T", c)
	}

	na, err := caddy.ParseNetworkAddress(caddy.JoinNetworkAddress(network, host, portRange))
	if err != nil {
		return nil, err
	}

	addr := na.JoinHostPort(portOffset)
	network, host, port, err := caddy.SplitNetworkAddress(addr)
	if err != nil {
		return nil, err
	}

	if network == "" {
		network = "tcp"
	}

	// Get node reference for this listener (increments node reference count)
	node, err := getNode(ctx, host)
	if err != nil {
		return nil, err
	}

	// Follow Caddy's standard listener pooling mechanism
	lnKey := fmt.Sprintf("tailscale+tls/%s:%s:%s", host, network, port)

	sharedLn, _, err := tailscaleListeners.LoadOrNew(lnKey, func() (caddy.Destructor, error) {
		ln, err := node.Listen(network, ":"+port)
		if err != nil {
			return nil, err
		}

		localClient, _ := node.LocalClient()
		tlsLn := tls.NewListener(ln, &tls.Config{
			GetCertificate: localClient.GetCertificate,
		})

		return &tailscaleSharedListener{
			Listener: tlsLn,
			key:      lnKey,
		}, nil
	})
	if err != nil {
		return nil, err
	}

	return &tailscaleFakeCloseListener{
		tailscaleSharedListener: sharedLn.(*tailscaleSharedListener),
		node:                    &fakeCloseNode{nodeName: host, node: node},
	}, nil
}

// funnelPorts are the only TCP ports Tailscale Funnel currently accepts.
// See https://tailscale.com/kb/1223/funnel for the canonical list.
var funnelPorts = map[string]struct{}{
	"443":   {},
	"8443":  {},
	"10000": {},
}

// getFunnelListener returns a TLS-terminated listener that accepts traffic
// from the public internet via Tailscale Funnel AND from the local tailnet,
// matching tsnet.Server.ListenFunnel's default behaviour.
//
// Funnel must be enabled in the tailnet ACL and on the specific node.
// Only the three TCP ports Tailscale Funnel supports are accepted.
func getFunnelListener(c context.Context, network string, host string, portRange string, portOffset uint, _ net.ListenConfig) (any, error) {
	return getFunnelListenerImpl(c, network, host, portRange, portOffset, false)
}

// getFunnelOnlyListener is the same as getFunnelListener but applies the
// tsnet.FunnelOnly option, rejecting connections from inside the tailnet.
// Useful when you want a separate tailnet-only listener with caddytail's
// auth headers and a strictly-public funnel listener that bypasses them.
func getFunnelOnlyListener(c context.Context, network string, host string, portRange string, portOffset uint, _ net.ListenConfig) (any, error) {
	return getFunnelListenerImpl(c, network, host, portRange, portOffset, true)
}

func getFunnelListenerImpl(c context.Context, network string, host string, portRange string, portOffset uint, funnelOnly bool) (any, error) {
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

	if _, ok := funnelPorts[port]; !ok {
		return nil, fmt.Errorf("tailscale funnel only supports TCP ports 443, 8443, 10000 (got %q)", port)
	}

	// Get node reference for this listener (increments node reference count)
	node, err := getNode(ctx, host)
	if err != nil {
		return nil, err
	}

	// Funnel-only and Funnel-plus-tailnet need separate pool keys so they
	// don't accidentally share a listener.
	mode := "both"
	if funnelOnly {
		mode = "only"
	}
	lnKey := fmt.Sprintf("tailscale+funnel/%s:%s:%s:%s", host, "tcp", port, mode)

	sharedLn, _, err := tailscaleListeners.LoadOrNew(lnKey, func() (caddy.Destructor, error) {
		var opts []tsnet.FunnelOption
		if funnelOnly {
			opts = append(opts, tsnet.FunnelOnly())
		}
		ln, err := node.ListenFunnel("tcp", ":"+port, opts...)
		if err != nil {
			return nil, fmt.Errorf("tailscale+funnel listen: %w", err)
		}

		// Workaround for a tsnet race: ListenFunnel calls Up() which wipes
		// the persisted serve config to {}, then ListenFunnel writes
		// AllowFunnel back. Between those two writes a netmap/prefs update
		// can fire reloadServeConfigLocked, which re-reads the stale {}
		// from disk and reverts in-memory state — IngressEnabled flips
		// false ~60ms after going true and the funnel relay stops
		// accepting traffic until next restart. Empirically reproduced 5/5
		// on tailscale.com v1.90.9. The watcher polls and re-asserts
		// AllowFunnel whenever it goes missing.
		var logger *zap.Logger
		if appIface, _ := ctx.App("tailscale"); appIface != nil {
			if app, ok := appIface.(*App); ok && app.logger != nil {
				logger = app.logger
			}
		}
		go watchAndRestoreFunnel(node.Server, port, logger)

		return &tailscaleSharedListener{
			Listener: ln,
			key:      lnKey,
		}, nil
	})
	if err != nil {
		return nil, err
	}

	return &tailscaleFakeCloseListener{
		tailscaleSharedListener: sharedLn.(*tailscaleSharedListener),
		node:                    &fakeCloseNode{nodeName: host, node: node},
	}, nil
}

func getUDPListener(c context.Context, network string, host string, portRange string, portOffset uint, _ net.ListenConfig) (any, error) {
	ctx, ok := c.(caddy.Context)
	if !ok {
		return nil, fmt.Errorf("context is not a caddy.Context: %T", c)
	}

	na, err := caddy.ParseNetworkAddress(caddy.JoinNetworkAddress(network, host, portRange))
	if err != nil {
		return nil, err
	}

	addr := na.JoinHostPort(portOffset)
	network, host, port, err := caddy.SplitNetworkAddress(addr)
	if err != nil {
		return nil, err
	}

	if network == "" {
		network = "udp"
	}

	// Get node reference for this listener (increments node reference count)
	node, err := getNode(ctx, host)
	if err != nil {
		return nil, err
	}

	// Follow Caddy's standard listener pooling mechanism
	lnKey := fmt.Sprintf("tailscale/udp/%s:%s:%s", host, network, port)

	sharedPc, _, err := tailscaleListeners.LoadOrNew(lnKey, func() (caddy.Destructor, error) {
		st, err := node.Up(context.Background())
		if err != nil {
			return nil, err
		}

		// We can only return one listener and MagicDNS returns IPv4 addresses unless IPv4 is disabled
		// Prefer IPv4 if available unless IPv6 was explicitly requested
		// TODO(will): watch for Tailscale IP changes and update listener
		var ap netip.AddrPort

		// First pass: look for IPv4 tsnet address if IPv4 was implicitly ("udp") or explicitly ("udp4") requested
		if network == "udp" || network == "udp4" {
			for _, ip := range st.TailscaleIPs {
				if ip.Is4() {
					p, _ := strconv.Atoi(port)
					ap = netip.AddrPortFrom(ip, uint16(p))
					network = "udp4" // Update network for tsnet
					break
				}
			}
		}

		// Second pass: look for IPv6 tsnet address if IPv6 was implicitly ("udp") or explicitly ("udp6") requested
		if !ap.IsValid() && (network == "udp" || network == "udp6") {
			for _, ip := range st.TailscaleIPs {
				if ip.Is6() {
					p, _ := strconv.Atoi(port)
					ap = netip.AddrPortFrom(ip, uint16(p))
					network = "udp6" // Update network for tsnet
					break
				}
			}
		}

		if !ap.IsValid() {
			return nil, fmt.Errorf("no suitable Tailscale IP address found for UDP listener")
		}

		pc, err := node.ListenPacket(network, ap.String())
		if err != nil {
			return nil, err
		}

		return &tailscaleSharedPacketConn{
			PacketConn: pc,
			key:        lnKey,
		}, nil
	})
	if err != nil {
		return nil, err
	}

	return &tailscaleFakeClosePacketConn{
		tailscaleSharedPacketConn: sharedPc.(*tailscaleSharedPacketConn),
		node:                      &fakeCloseNode{nodeName: host, node: node},
	}, nil
}

// nodes are the Tailscale nodes that have been configured and started.
// Node configuration comes from the global Tailscale Caddy app.
// When nodes are no longer in used (e.g. all listeners have been closed), they are shutdown.
//
// Callers should use getNode() to get a node by name, rather than accessing this pool directly.
var nodes = caddy.NewUsagePool()

// tailscaleListeners tracks individual tailscale listeners to enable proper cleanup during config reloads.
// This ensures listeners are properly closed when removed from configuration.
var tailscaleListeners = caddy.NewUsagePool()

// getNode returns a tailscale node for Caddy apps to interface with.
//
// The specified name will be used to lookup the node configuration from the tailscale caddy app,
// used to register the node the first time it is used.
// Only one tailscale node is created per name, even if multiple listeners are created for the node.
func getNode(ctx caddy.Context, name string) (*tailscaleNode, error) {
	appIface, err := ctx.App("tailscale")
	if err != nil {
		return nil, err
	}
	app := appIface.(*App)

	s, _, err := nodes.LoadOrNew(name, func() (caddy.Destructor, error) {
		s := &tsnet.Server{
			Logf: func(format string, args ...any) {
				app.logger.Sugar().Debugf(format, args...)
			},
			UserLogf: func(format string, args ...any) {
				app.logger.Sugar().Infof(format, args...)
			},
			Ephemeral:     getEphemeral(name, app),
			RunWebClient:  getWebUI(name, app),
			Port:          getPort(name, app),
			AdvertiseTags: getTags(name, app),
		}

		if s.AuthKey, err = getAuthKey(name, app); err != nil {
			return nil, err
		}
		if s.ControlURL, err = getControlURL(name, app); err != nil {
			return nil, err
		}
		if s.Hostname, err = getHostname(name, app); err != nil {
			return nil, err
		}

		if s.Dir, err = getStateDir(name, app); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(s.Dir, 0700); err != nil {
			return nil, err
		}

		return &tailscaleNode{
			s,
		}, nil
	})
	if err != nil {
		return nil, err
	}

	return s.(*tailscaleNode), nil
}

var repl = caddy.NewReplacer()

func getAuthKey(name string, app *App) (string, error) {
	if node, ok := app.Nodes[name]; ok {
		if node.AuthKey != "" {
			return repl.ReplaceOrErr(node.AuthKey, true, true)
		}
	}

	if app.DefaultAuthKey != "" {
		return repl.ReplaceOrErr(app.DefaultAuthKey, true, true)
	}

	// Set authkey to "TS_AUTHKEY_<HOST>".
	// If empty, fall back to "TS_AUTHKEY".
	authKey := os.Getenv("TS_AUTHKEY_" + strings.ToUpper(name))
	if authKey != "" {
		app.logger.Warn("Relying on TS_AUTHKEY_{HOST} env var is deprecated. Set caddy config instead.", zap.Any("host", name))
		return authKey, nil
	}

	return os.Getenv("TS_AUTHKEY"), nil
}

func getControlURL(name string, app *App) (string, error) {
	if node, ok := app.Nodes[name]; ok {
		if node.ControlURL != "" {
			return repl.ReplaceOrErr(node.ControlURL, true, true)
		}
	}
	return repl.ReplaceOrErr(app.ControlURL, true, true)
}

func getEphemeral(name string, app *App) bool {
	if node, ok := app.Nodes[name]; ok {
		if v, ok := node.Ephemeral.Get(); ok {
			return v
		}
	}
	return app.Ephemeral
}

func getHostname(name string, app *App) (string, error) {
	if app == nil {
		return name, nil
	}
	if node, ok := app.Nodes[name]; ok {
		if node.Hostname != "" {
			return repl.ReplaceOrErr(node.Hostname, true, true)
		}
	}

	return name, nil
}

func getPort(name string, app *App) uint16 {
	if node, ok := app.Nodes[name]; ok {
		return node.Port
	}

	return 0
}

func getStateDir(name string, app *App) (string, error) {
	if node, ok := app.Nodes[name]; ok {
		if node.StateDir != "" {
			return repl.ReplaceOrErr(node.StateDir, true, true)
		}
	}

	if app.StateDir != "" {
		s, err := repl.ReplaceOrErr(app.StateDir, true, true)
		if err != nil {
			return "", err
		}
		return filepath.Join(s, name), nil
	}

	// By default, tsnet will use the name of the running program in the state directory,
	// but we also include the hostname so that a single caddy instance can have multiple nodes.
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, "tsnet-caddy-"+name), nil
}

func getWebUI(name string, app *App) bool {
	if node, ok := app.Nodes[name]; ok {
		if v, ok := node.WebUI.Get(); ok {
			return v
		}
	}
	return app.WebUI
}

func getTags(name string, app *App) []string {
	if node, ok := app.Nodes[name]; ok {
		if node.Tags != nil {
			return node.Tags
		}
	}
	return app.Tags
}

// tailscaleNode is a wrapper around a tsnet.Server that provides a fully self-contained Tailscale node.
// This node can listen on the tailscale network interface, or be used to connect to other nodes in the tailnet.
type tailscaleNode struct {
	*tsnet.Server
}

func (t tailscaleNode) Destruct() error {
	return t.Close()
}

// fakeCloseNode is similar to fakeCloseListener but for node references.
// It allows listeners to hold references to nodes without affecting the
// actual node reference count until the listener is truly destroyed.
type fakeCloseNode struct {
	nodeName string
	node     *tailscaleNode
}

func (fcn *fakeCloseNode) Close() error {
	_, _ = nodes.Delete(fcn.nodeName)
	return nil
}

// tailscaleSharedListener is similar to Caddy's sharedListener but for tailscale listeners
type tailscaleSharedListener struct {
	net.Listener
	key string
}

func (tsl *tailscaleSharedListener) Destruct() error {
	return tsl.Close()
}

// tailscaleFakeCloseListener is similar to Caddy's fakeCloseListener
type tailscaleFakeCloseListener struct {
	closed atomic.Bool
	*tailscaleSharedListener
	node *fakeCloseNode
}

func (tfcl *tailscaleFakeCloseListener) Accept() (net.Conn, error) {
	// if the listener is already closed, return error
	if tfcl.closed.Load() {
		return nil, &net.OpError{
			Op:   "accept",
			Net:  tfcl.Addr().Network(),
			Addr: tfcl.Addr(),
			Err:  fmt.Errorf("listener 'closed'"),
		}
	}

	return tfcl.tailscaleSharedListener.Accept()
}

func (tfcl *tailscaleFakeCloseListener) Close() error {
	if tfcl.closed.CompareAndSwap(false, true) {
		_, _ = tailscaleListeners.Delete(tfcl.key)
		return tfcl.node.Close()
	}
	return nil
}

func (tfcl *tailscaleFakeCloseListener) Unwrap() net.Listener {
	return tfcl.Listener
}

// tailscaleSharedPacketConn is similar to tailscaleSharedListener but for packet connections
type tailscaleSharedPacketConn struct {
	net.PacketConn
	key string
}

func (tspc *tailscaleSharedPacketConn) Destruct() error {
	return tspc.Close()
}

// tailscaleFakeClosePacketConn is similar to tailscaleFakeCloseListener but for packet connections
type tailscaleFakeClosePacketConn struct {
	closed atomic.Bool
	*tailscaleSharedPacketConn
	node *fakeCloseNode
}

func (tfcpc *tailscaleFakeClosePacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	// if the connection is already closed, return error
	if tfcpc.closed.Load() {
		return 0, nil, &net.OpError{
			Op:   "readfrom",
			Net:  tfcpc.LocalAddr().Network(),
			Addr: tfcpc.LocalAddr(),
			Err:  fmt.Errorf("connection 'closed'"),
		}
	}

	return tfcpc.tailscaleSharedPacketConn.ReadFrom(p)
}

func (tfcpc *tailscaleFakeClosePacketConn) Close() error {
	if tfcpc.closed.CompareAndSwap(false, true) {
		_, _ = tailscaleListeners.Delete(tfcpc.key)
		return tfcpc.node.Close()
	}
	return nil
}

func (tfcpc *tailscaleFakeClosePacketConn) Unwrap() net.PacketConn {
	return tfcpc.PacketConn
}

// tsnetMuxTransport is an [http.RoundTripper] that sends requests to the LocalAPI
// for the tsnet server that matches the ClientHelloInfo server name.
// If no tsnet server matches, a default Transport is used.
type tsnetMuxTransport struct {
	defaultTransport     *http.Transport
	defaultTransportOnce sync.Once
}

func (t *tsnetMuxTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	var rt http.RoundTripper

	clientHello, ok := ctx.Value(certmagic.ClientHelloInfoCtxKey).(*tls.ClientHelloInfo)
	if ok && clientHello != nil {
		nodes.Range(func(key, value any) bool {
			if n, ok := value.(*tailscaleNode); ok && n != nil {
				for _, d := range n.CertDomains() {
					// Tailscale doesn't do wildcard certs, but caddy uses MatchWildcard
					// for the built-in Tailscale cert manager, so we do so here as well.
					if certmagic.MatchWildcard(clientHello.ServerName, d) {
						if lc, err := n.LocalClient(); err == nil {
							rt = &localAPITransport{lc}
						}
						return false
					}
				}
			}
			return true
		})
	}

	if rt == nil {
		t.defaultTransportOnce.Do(func() {
			t.defaultTransport = &http.Transport{
				DialContext: tscert.TailscaledDialer,
			}
		})
		rt = t.defaultTransport
	}
	return rt.RoundTrip(req)
}

// localAPITransport is an [http.RoundTripper] that sends requests to a [local.Client]'s LocalAPI.
type localAPITransport struct {
	*local.Client
}

func (t *localAPITransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.DoLocalRequest(req)
}

// watchAndRestoreFunnel keeps the funnel listener for (node, port) alive in
// the face of a tsnet bug where the in-memory serve config can revert to {}
// shortly after ListenFunnel returns (see the call site for the full
// explanation). It runs as a background goroutine for the lifetime of the
// process; on every tick, if the AllowFunnel entry for this hostport is
// missing, it re-asserts it via SetServeConfig.
//
// The polling cadence is deliberately tight (1s) because the bug's repair
// window matters: until AllowFunnel is restored, the public funnel relay
// closes the TCP connection at TLS, so any user-visible request during the
// outage just errors. 1s of downtime per regression is acceptable; 30s is
// not. CPU/IO cost is negligible (one localapi call per second per funnel
// listener — there is one per process in practice).
func watchAndRestoreFunnel(s *tsnet.Server, port string, logger *zap.Logger) {
	if s == nil {
		return
	}
	ctx := context.Background()
	lc, err := s.LocalClient()
	if err != nil {
		if logger != nil {
			logger.Warn("funnel-watchdog: LocalClient failed", zap.Error(err))
		}
		return
	}
	// Resolve the cert domain once; it shouldn't change for the life of
	// the node. If Status fails transiently, retry briefly.
	var domain string
	for i := 0; i < 30 && domain == ""; i++ {
		st, err := lc.Status(ctx)
		if err == nil && st != nil && len(st.CertDomains) > 0 {
			domain = st.CertDomains[0]
			break
		}
		time.Sleep(time.Second)
	}
	if domain == "" {
		if logger != nil {
			logger.Warn("funnel-watchdog: no cert domain after 30s; not watching",
				zap.String("port", port))
		}
		return
	}
	hp := ipn.HostPort(domain + ":" + port)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	restoredCount := 0
	for range ticker.C {
		sc, err := lc.GetServeConfig(ctx)
		if err != nil {
			continue
		}
		if sc == nil {
			sc = &ipn.ServeConfig{}
		}
		if sc.AllowFunnel[hp] {
			continue
		}
		mak.Set(&sc.AllowFunnel, hp, true)
		if err := lc.SetServeConfig(ctx, sc); err != nil {
			if logger != nil {
				logger.Warn("funnel-watchdog: SetServeConfig failed",
					zap.String("hostport", string(hp)), zap.Error(err))
			}
			continue
		}
		restoredCount++
		if logger != nil {
			// Throttle: log first 3 restores per process, then once per
			// 100 to surface chronic flapping without spamming.
			if restoredCount <= 3 || restoredCount%100 == 0 {
				logger.Info("funnel-watchdog: restored AllowFunnel",
					zap.String("hostport", string(hp)),
					zap.Int("restore_count", restoredCount))
			}
		}
	}
}
