// Copyright (c) 2026 NewNetGuard
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build windows

package main

import (
	"bytes"
	"context"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"

	"chameleon/tcprelay"
)

// echoStream returns everything written to it once the writer half-closes.
type echoStream struct {
	r  *io.PipeReader
	w  *io.PipeWriter
	mu sync.Mutex
	in bytes.Buffer
}

func newEchoStream() *echoStream {
	r, w := io.Pipe()
	return &echoStream{r: r, w: w}
}
func (s *echoStream) Read(p []byte) (int, error) { return s.r.Read(p) }
func (s *echoStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.in.Write(p)
}
func (s *echoStream) CloseWrite() error {
	s.mu.Lock()
	data := append([]byte(nil), s.in.Bytes()...)
	s.mu.Unlock()
	go func() { _, _ = s.w.Write(data); _ = s.w.Close() }()
	return nil
}
func (s *echoStream) Close() error { _ = s.r.Close(); return nil }

// An application stack (standing in for Windows) dials an internet address
// through the "adapter"; the stream stack must accept it as that address and
// relay the bytes through a stream.
func TestStreamStackCarriesApplicationTCPAsStreams(t *testing.T) {
	app := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	defer app.Close()
	appLink := channel.New(1024, tunnelMTU, "")
	if err := app.CreateNIC(1, appLink); err != nil {
		t.Fatal(err)
	}
	local := tcpip.AddrFrom4([4]byte{10, 10, 0, 2})
	if err := app.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: local.WithPrefix()}, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	app.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})

	targets := make(chan netip.AddrPort, 1)
	var ss *streamStack
	var err error
	ss, err = newStreamStack(func(pkt []byte) {
		p := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(pkt)})
		appLink.InjectInbound(ipv4.ProtocolNumber, p)
		p.DecRef()
	}, func(_ context.Context, target netip.AddrPort, early []byte) (tcprelay.Stream, error) {
		targets <- target
		s := newEchoStream()
		_, _ = s.Write(early)
		return s, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ss.close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() {
		for {
			pkt := appLink.ReadContext(ctx)
			if pkt == nil {
				return
			}
			view := pkt.ToView()
			pkt.DecRef()
			if !isIPv4TCP(view.AsSlice()) {
				t.Errorf("non-TCP packet from the application")
			}
			ss.inject(view.AsSlice())
			view.Release()
		}
	}()

	remote := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{93, 184, 216, 34}), Port: 443}
	conn, err := gonet.DialContextTCP(ctx, app, remote, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("dial through the stream stack: %v", err)
	}
	defer conn.Close()
	payload := bytes.Repeat([]byte("chameleon stream "), 60000) // ~1 MB, many windows
	go func() {
		_, _ = conn.Write(payload)
		_ = conn.CloseWrite()
	}()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	got, err := io.ReadAll(conn)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("echoed %d bytes (%v), want %d", len(got), err, len(payload))
	}
	if target := <-targets; target != netip.MustParseAddrPort("93.184.216.34:443") {
		t.Fatalf("stream opened for %s", target)
	}
}

func TestIsIPv4TCP(t *testing.T) {
	tcpPkt := make([]byte, 40)
	tcpPkt[0], tcpPkt[9] = 0x45, 6
	udpPkt := append([]byte(nil), tcpPkt...)
	udpPkt[9] = 17
	v6 := append([]byte(nil), tcpPkt...)
	v6[0] = 0x60
	if !isIPv4TCP(tcpPkt) || isIPv4TCP(udpPkt) || isIPv4TCP(v6) || isIPv4TCP(tcpPkt[:10]) {
		t.Fatal("classification wrong")
	}
}

// sourceStream sends n bytes as fast as the reader takes them.
type sourceStream struct{ left int }

func (s *sourceStream) Read(p []byte) (int, error) {
	if s.left <= 0 {
		return 0, io.EOF
	}
	n := min(len(p), s.left)
	s.left -= n
	return n, nil
}
func (s *sourceStream) Write(p []byte) (int, error) { return len(p), nil }
func (s *sourceStream) CloseWrite() error           { return nil }
func (s *sourceStream) Close() error                { return nil }

// BenchmarkStreamStackDownload measures site -> application throughput of the
// stream stack alone (no adapter, no carrier).
func BenchmarkStreamStackDownload(b *testing.B) {
	const size = 100 << 20
	app := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	defer app.Close()
	appLink := channel.New(1024, tunnelMTU, "")
	_ = app.CreateNIC(1, appLink)
	local := tcpip.AddrFrom4([4]byte{10, 10, 0, 2})
	_ = app.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: local.WithPrefix()}, stack.AddressProperties{})
	app.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	ss, err := newStreamStack(func(pkt []byte) {
		p := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(pkt)})
		appLink.InjectInbound(ipv4.ProtocolNumber, p)
		p.DecRef()
	}, func(context.Context, netip.AddrPort, []byte) (tcprelay.Stream, error) {
		return &sourceStream{left: size}, nil
	})
	if err != nil {
		b.Fatal(err)
	}
	defer ss.close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for {
			pkt := appLink.ReadContext(ctx)
			if pkt == nil {
				return
			}
			view := pkt.ToView()
			pkt.DecRef()
			ss.inject(view.AsSlice())
			view.Release()
		}
	}()
	b.SetBytes(size)
	for i := 0; i < b.N; i++ {
		conn, err := gonet.DialContextTCP(ctx, app, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{93, 184, 216, 34}), Port: 443}, ipv4.ProtocolNumber)
		if err != nil {
			b.Fatal(err)
		}
		_, _ = conn.Write([]byte("GET"))
		n, _ := io.Copy(io.Discard, conn)
		conn.Close()
		if n != size {
			b.Fatalf("got %d bytes", n)
		}
	}
}
