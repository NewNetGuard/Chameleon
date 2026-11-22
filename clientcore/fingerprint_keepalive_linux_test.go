// Copyright (c) 2026 NewNetGuard
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build linux

package clientcore

import (
	"net"
	"syscall"
	"testing"
)

// The carrier socket really carries the profile's keepalive: TCP_KEEPIDLE
// and TCP_KEEPINTVL as Chrome sets them, read back from the kernel.
func TestCarrierSocketKeepAliveIsChromes(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		if conn, err := listener.Accept(); err == nil {
			defer conn.Close()
			_, _ = conn.Read(make([]byte, 1))
		}
	}()
	conn, err := profileDialer(desktopFingerprintProfiles[0]).Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	raw, err := conn.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var keepalive, idle, interval int
	_ = raw.Control(func(fd uintptr) {
		keepalive, _ = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE)
		idle, _ = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_KEEPIDLE)
		interval, _ = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_KEEPINTVL)
	})
	if keepalive != 1 || idle != 45 || interval != 45 {
		t.Fatalf("socket keepalive=%d idle=%ds interval=%ds, want 1/45/45", keepalive, idle, interval)
	}
}
