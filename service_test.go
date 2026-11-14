// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: Apache-2.0

package tscaddy

import (
	"net"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"tailscale.com/util/must"
)

func Test_ServiceListenerAddressValidation(t *testing.T) {
	must.Do(caddy.Run(new(caddy.Config)))
	ctx := caddy.ActiveContext()

	for _, host := range []string{
		"research",       // missing node
		"@node",          // missing service
		"research@",      // empty node
		"bad_name!@node", // invalid service name
	} {
		if _, err := getServiceListener(ctx, "tailscale+svc", host, "443", 0, net.ListenConfig{}); err == nil {
			t.Errorf("expected error for host %q", host)
		}
		if _, exists := nodes.References("node"); exists {
			t.Errorf("host %q: node reference leaked", host)
		}
	}
}
