// Copyright (c) 2026 NewNetGuard
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tcprelay

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// echoStream echoes everything written to it after a half-close.
type echoStream struct {
	r  *io.PipeReader
	w  *io.PipeWriter
	in bytes.Buffer
}

func newEchoStream() *echoStream {
	r, w := io.Pipe()
	return &echoStream{r: r, w: w}
}
func (s *echoStream) Read(p []byte) (int, error)  { return s.r.Read(p) }
func (s *echoStream) Write(p []byte) (int, error) { return s.in.Write(p) }
func (s *echoStream) CloseWrite() error {
	go func() { _, _ = s.w.Write(s.in.Bytes()); _ = s.w.Close() }()
	return nil
}
func (s *echoStream) Close() error { _ = s.r.Close(); return nil }

func startRelay(t *testing.T, opener Opener) net.Addr {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go Serve(ctx, listener, opener)
	return listener.Addr()
}

func TestRelayCarriesDeviceBytesToTheStreamAndBack(t *testing.T) {
	targets := make(chan netip.AddrPort, 1)
	addr := startRelay(t, func(_ context.Context, target netip.AddrPort, early []byte) (Stream, error) {
		targets <- target
		stream := newEchoStream()
		_, _ = stream.Write(early) // the server delivers early data first
		return stream, nil
	})
	conn, err := net.Dial("tcp4", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload := bytes.Repeat([]byte("relay"), 50000)
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = conn.(*net.TCPConn).CloseWrite()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(conn)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("echoed %d bytes (%v), want %d", len(got), err, len(payload))
	}
	if target := <-targets; target.String() != addr.String() {
		t.Fatalf("stream opened for %s, want the accepted local address %s", target, addr)
	}
}

// A client-first protocol's opening message (a TLS ClientHello) leaves with
// the stream request; nothing is lost or reordered.
func TestRelaySendsTheDevicesFirstDataWithTheOpen(t *testing.T) {
	earlies := make(chan []byte, 1)
	addr := startRelay(t, func(_ context.Context, _ netip.AddrPort, early []byte) (Stream, error) {
		earlies <- append([]byte(nil), early...)
		stream := newEchoStream()
		_, _ = stream.Write(early)
		return stream, nil
	})
	conn, err := net.Dial("tcp4", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	hello := bytes.Repeat([]byte{0x16, 0x03, 0x01}, 600)
	rest := bytes.Repeat([]byte("after the hello "), 4000)
	if _, err := conn.Write(hello); err != nil {
		t.Fatal(err)
	}
	if early := <-earlies; !bytes.Equal(early, hello) {
		t.Fatalf("early data %d bytes, want the %d-byte opening message", len(early), len(hello))
	}
	if _, err := conn.Write(rest); err != nil {
		t.Fatal(err)
	}
	_ = conn.(*net.TCPConn).CloseWrite()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(conn)
	if want := append(append([]byte(nil), hello...), rest...); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("relayed %d bytes (%v), want %d in order", len(got), err, len(want))
	}
}

const smtpGreeting = "220 mail.example ESMTP\r\n"

// A server-first protocol sends nothing at first; its stream opens after the
// short wait, without early data, and the server's greeting reaches it.
func TestRelayOpensServerFirstProtocolsAfterTheWait(t *testing.T) {
	opened := make(chan time.Duration, 1)
	start := time.Now()
	addr := startRelay(t, func(_ context.Context, _ netip.AddrPort, early []byte) (Stream, error) {
		if len(early) != 0 {
			t.Errorf("unexpected early data %q", early)
		}
		opened <- time.Since(start)
		stream := newEchoStream()
		_, _ = stream.Write([]byte(smtpGreeting))
		_ = stream.CloseWrite()
		return stream, nil
	})
	conn, err := net.Dial("tcp4", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if waited := <-opened; waited > EarlyDataWait+500*time.Millisecond {
		t.Fatalf("stream opened after %v", waited)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	greeting := make([]byte, len(smtpGreeting))
	if _, err := io.ReadFull(conn, greeting); err != nil || !strings.HasPrefix(string(greeting), "220 ") {
		t.Fatalf("greeting %q (%v)", greeting, err)
	}
}
