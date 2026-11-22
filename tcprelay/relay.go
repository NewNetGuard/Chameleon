// Copyright (c) 2026 NewNetGuard
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package tcprelay carries device TCP connections as Chameleon TCP streams.
//
// The platform clients capture device connections their own way and hand
// them over as net.Conn values whose local address is the destination the
// device dialled: the Linux client gets them from a transparent (TPROXY)
// listener, the Windows client from a userspace TCP stack on its adapter.
package tcprelay

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"time"

	"chameleon/clientcore"
)

// MaxRelayed bounds concurrently relayed device connections; beyond it new
// connections are refused instead of growing goroutines and buffers.
const MaxRelayed = 1024

// EarlyDataWait bounds how long the relay waits for a device's first data
// before opening the stream. Client-first protocols (TLS above all) send it at
// once; server-first ones (SMTP, SSH banners from the server) send nothing and
// their stream opens after this wait.
const EarlyDataWait = 20 * time.Millisecond

// Stream is the part of clientcore.TCPStream the relay uses.
type Stream interface {
	io.ReadWriter
	CloseWrite() error
	Close() error
}

// Opener opens a stream to target; early is the device's first data.
type Opener func(ctx context.Context, target netip.AddrPort, early []byte) (Stream, error)

// ClientOpener adapts the client core, keeping a nil stream a nil interface.
func ClientOpener(client *clientcore.MobileClient) Opener {
	return func(ctx context.Context, target netip.AddrPort, early []byte) (Stream, error) {
		stream, err := client.OpenTCPStream(ctx, target, early)
		if err != nil {
			return nil, err
		}
		return stream, nil
	}
}

// Serve accepts device connections and carries each one as a TCP stream until
// ctx ends.
func Serve(ctx context.Context, listener net.Listener, opener Opener) {
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	slots := make(chan struct{}, MaxRelayed)
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			clientcore.LogOperationalFailure("tcp", "accept failed", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			clientcore.LogRateLimitedEvent("tcp", "device connection refused: relay limit reached")
			Reset(conn)
			continue
		}
		go func() {
			defer func() { <-slots }()
			Relay(ctx, conn, opener)
		}()
	}
}

// Relay carries one device connection. The connection's local address is the
// destination the device dialled.
func Relay(ctx context.Context, device net.Conn, opener Opener) {
	defer device.Close()
	target, err := netip.ParseAddrPort(device.LocalAddr().String())
	if err != nil {
		Reset(device)
		return
	}
	early, err := readEarlyData(device)
	if err != nil {
		Reset(device)
		return
	}
	stream, err := opener(ctx, target, early)
	if err != nil {
		clientcore.LogOperationalFailure("tcp", "stream open failed", err)
		Reset(device)
		return
	}
	defer stream.Close()

	done := make(chan struct{}, 2)
	go func() {
		buf := make([]byte, 32<<10)
		_, _ = io.CopyBuffer(stream, onlyReader{device}, buf)
		_ = stream.CloseWrite()
		done <- struct{}{}
	}()
	go func() {
		buf := make([]byte, 32<<10)
		_, _ = io.CopyBuffer(onlyWriter{device}, stream, buf)
		if half, ok := device.(interface{ CloseWrite() error }); ok {
			_ = half.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}

// readEarlyData returns what the device sent right after connecting, so it
// can leave with the stream request: the site gets it one round trip sooner
// and the carrier shows a single request instead of an opening exchange
// followed by the device's first message.
func readEarlyData(device net.Conn) ([]byte, error) {
	buf := make([]byte, 16<<10)
	_ = device.SetReadDeadline(time.Now().Add(EarlyDataWait))
	n, err := device.Read(buf)
	_ = device.SetReadDeadline(time.Time{})
	if n > 0 {
		return buf[:n], nil
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return nil, nil
	}
	if err == nil {
		return nil, nil
	}
	return nil, err
}

// Reset closes with RST where the connection supports it, so the device sees
// an immediate failure rather than a clean end of an empty connection.
func Reset(conn net.Conn) {
	switch c := conn.(type) {
	case *net.TCPConn:
		_ = c.SetLinger(0)
	case interface{ Abort() }:
		c.Abort()
		return
	}
	_ = conn.Close()
}

// onlyReader/onlyWriter hide ReadFrom/WriteTo so CopyBuffer uses the bounded
// buffer instead of splice paths that do not apply to a TCPStream.
type onlyReader struct{ io.Reader }
type onlyWriter struct{ io.Writer }
