// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: Apache-2.0

package tscaddy

import (
	"io"
	"testing"
	"time"
)

func TestWatchStdinReader(t *testing.T) {
	t.Run("shutdown on close", func(t *testing.T) {
		r, w := io.Pipe()
		done := make(chan struct{})
		go watchStdinReader(r, func() {
			close(done)
		})
		w.Close()
		select {
		case <-done:
			// success
		case <-time.After(5 * time.Second):
			t.Fatal("shutdown was not called after stdin closed")
		}
	})

	t.Run("shutdown after data then close", func(t *testing.T) {
		r, w := io.Pipe()
		done := make(chan struct{})
		go watchStdinReader(r, func() {
			close(done)
		})
		// Write some data first, then close.
		w.Write([]byte("hello\n"))
		w.Close()
		select {
		case <-done:
			// success
		case <-time.After(5 * time.Second):
			t.Fatal("shutdown was not called after stdin closed")
		}
	})

	t.Run("blocks while open", func(t *testing.T) {
		r, w := io.Pipe()
		defer w.Close()
		done := make(chan struct{})
		go watchStdinReader(r, func() {
			close(done)
		})
		select {
		case <-done:
			t.Fatal("shutdown called while stdin is still open")
		case <-time.After(100 * time.Millisecond):
			// expected: still blocking
		}
	})
}
