// Copyright (c) 2026 NewNetGuard
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build linux

package tcprelay

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"
)

func TestRelayResetsTheDeviceWhenTheStreamCannotOpen(t *testing.T) {
	addr := startRelay(t, func(context.Context, netip.AddrPort, []byte) (Stream, error) {
		return nil, errors.New("refused")
	})
	conn, err := net.Dial("tcp4", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Read(make([]byte, 1))
	if !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("device saw %v, want a connection reset", err)
	}
}
