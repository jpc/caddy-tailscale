// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: Apache-2.0

package tscaddy

import (
	"io"
	"os"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

// watchStdin blocks reading stdin until EOF (indicating the parent process has
// exited or closed its end of the pipe), then triggers a graceful Caddy
// shutdown. It is intended to be called as a goroutine.
func watchStdin() {
	watchStdinReader(os.Stdin, func() {
		caddy.Log().Info("stdin closed, shutting down", zap.String("module", "tailscale"))
		_ = caddy.Stop()
		os.Exit(0)
	})
}

// watchStdinReader is the testable core of watchStdin. It reads from r until
// EOF, then calls the shutdown function.
func watchStdinReader(r io.Reader, shutdown func()) {
	_, _ = io.Copy(io.Discard, r)
	shutdown()
}
