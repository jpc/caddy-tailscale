// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: Apache-2.0

package tscaddy

import (
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func TestDecoderReadsOneObject(t *testing.T) {
	// Simulate a stream where a JSON config object is followed by
	// additional data (representing the still-open stdin pipe).
	// json.NewDecoder must consume only the first object.
	input := `{"admin":{"disabled":true}}` + "\ngarbage that should remain"
	dec := json.NewDecoder(strings.NewReader(input))

	var obj map[string]any
	if err := dec.Decode(&obj); err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if _, ok := obj["admin"]; !ok {
		t.Fatal("expected 'admin' key in decoded object")
	}

	// The decoder's internal buffer may have consumed more bytes from the
	// underlying reader than the JSON object itself. What matters is that
	// the Buffered() reader plus the underlying reader still contain the
	// remaining data — i.e., the decoder did not require EOF.
	remaining, err := io.ReadAll(io.MultiReader(dec.Buffered(), strings.NewReader("")))
	if err != nil {
		t.Fatalf("reading remaining: %v", err)
	}
	if !strings.Contains(string(remaining), "garbage") {
		t.Fatalf("expected remaining data after first object, got %q", remaining)
	}
}

func TestDecoderWithPipe(t *testing.T) {
	// More realistic test: use a pipe where the writer stays open.
	r, w := io.Pipe()
	defer w.Close()

	done := make(chan error, 1)
	var obj map[string]any

	go func() {
		dec := json.NewDecoder(r)
		done <- dec.Decode(&obj)
	}()

	// Write a complete JSON object but do NOT close the pipe.
	_, err := w.Write([]byte(`{"apps":{}}` + "\n"))
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}

	// Decode should complete without EOF.
	if err := <-done; err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if _, ok := obj["apps"]; !ok {
		t.Fatal("expected 'apps' key in decoded object")
	}
}
