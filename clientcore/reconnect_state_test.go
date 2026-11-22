// Copyright (c) 2026 NewNetGuard
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package clientcore

import (
	"context"
	"sync/atomic"
	"testing"
)

func TestTransportProtocolIsPinnedToHTTP2(t *testing.T) {
	for _, configured := range []string{"", "auto", "http2", "http3"} {
		if got := normalizeProtocol(configured); got != "http2" {
			t.Fatalf("normalizeProtocol(%q) = %q, want http2", configured, got)
		}
	}
}

func TestHTTP2ConnectionStatusTracksCarrierReconnect(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	transport := &Transport{
		protocol:      "http2",
		streamEnabled: true,
		uplinkEnabled: true,
		ctx:           ctx,
	}
	connection := &Connection{transport: transport}
	connection.connected.Store(true)

	if connection.IsConnected() {
		t.Fatal("dead persistent carriers were reported as connected")
	}
	atomic.StoreInt32(&transport.streamLive, 1)
	if connection.IsConnected() {
		t.Fatal("one-way carrier was reported as a healthy tunnel")
	}
	atomic.StoreInt32(&transport.uplinkLive, 1)
	if !connection.IsConnected() {
		t.Fatal("restored bidirectional carriers were not reported as connected")
	}
	atomic.StoreInt32(&transport.streamLive, 0)
	if connection.IsConnected() {
		t.Fatal("carrier loss did not clear connected status")
	}
	atomic.StoreInt32(&transport.streamLive, 1)
	if !connection.IsConnected() {
		t.Fatal("carrier reconnection did not restore connected status")
	}
	cancel()
	if connection.IsConnected() {
		t.Fatal("closed transport was reported as connected")
	}
}
