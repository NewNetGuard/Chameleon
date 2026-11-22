// Copyright (c) 2026 NewNetGuard
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build linux

package shared

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func tcpRawConn(conn net.Conn) (syscall.RawConn, bool) {
	for range 8 {
		if syscallConn, ok := conn.(syscall.Conn); ok {
			raw, err := syscallConn.SyscallConn()
			return raw, err == nil
		}
		if netConn, ok := conn.(interface{ NetConn() net.Conn }); ok {
			next := netConn.NetConn()
			if next == nil || next == conn {
				return nil, false
			}
			conn = next
			continue
		}
		if underlying, ok := conn.(interface{ GetUnderlyingConn() net.Conn }); ok {
			next := underlying.GetUnderlyingConn()
			if next == nil || next == conn {
				return nil, false
			}
			conn = next
			continue
		}
		return nil, false
	}
	return nil, false
}

func readTCPPacingTelemetry(conn net.Conn) (tcpPacingTelemetry, bool) {
	raw, ok := tcpRawConn(conn)
	if !ok {
		return tcpPacingTelemetry{}, false
	}
	var info *unix.TCPInfo
	var getErr error
	if err := raw.Control(func(fd uintptr) {
		info, getErr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
	}); err != nil || getErr != nil || info == nil {
		return tcpPacingTelemetry{}, false
	}
	return tcpPacingTelemetry{
		DeliveryRateBytesPerSecond: info.Delivery_rate,
		NotSentBytes:               info.Notsent_bytes,
	}, true
}
