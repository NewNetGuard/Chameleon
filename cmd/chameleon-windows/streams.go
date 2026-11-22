// Copyright (c) 2026 NewNetGuard
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build windows

package main

import (
	"context"
	"fmt"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"

	"chameleon/clientcore"
	"chameleon/tcprelay"
)

// streamStack is the Windows counterpart of the Linux TPROXY listener: a
// userspace TCP stack that terminates the applications' TCP connections
// arriving on the Chameleon adapter, so each one travels as its own TCP
// stream instead of packets inside the carrier. Its local address for a
// connection is the destination the application dialled, as with TPROXY.
type streamStack struct {
	stack  *stack.Stack
	ep     *channel.Endpoint
	cancel context.CancelFunc
	slots  chan struct{}
}

func newStreamStack(write func([]byte), opener tcprelay.Opener) (*streamStack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	fail := func(what string, err tcpip.Error) (*streamStack, error) {
		s.Close()
		return nil, fmt.Errorf("TCP stream stack: %s: %v", what, err)
	}
	sack := tcpip.TCPSACKEnabled(true)
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); err != nil {
		return fail("SACK", err)
	}
	moderate := tcpip.TCPModerateReceiveBufferOption(true)
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &moderate); err != nil {
		return fail("receive buffer moderation", err)
	}
	recv := tcpip.TCPReceiveBufferSizeRangeOption{Min: 4 << 10, Default: 1 << 20, Max: 8 << 20}
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &recv); err != nil {
		return fail("receive buffer", err)
	}
	send := tcpip.TCPSendBufferSizeRangeOption{Min: 4 << 10, Default: 1 << 20, Max: 8 << 20}
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &send); err != nil {
		return fail("send buffer", err)
	}

	ep := channel.New(1024, tunnelMTU, "")
	if err := s.CreateNIC(1, ep); err != nil {
		return fail("adapter", err)
	}
	// Accept connections to any address and answer from it.
	if err := s.SetPromiscuousMode(1, true); err != nil {
		return fail("promiscuous mode", err)
	}
	if err := s.SetSpoofing(1, true); err != nil {
		return fail("spoofing", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})

	ctx, cancel := context.WithCancel(context.Background())
	ss := &streamStack{stack: s, ep: ep, cancel: cancel, slots: make(chan struct{}, tcprelay.MaxRelayed)}

	forwarder := tcp.NewForwarder(s, 0, 2048, func(r *tcp.ForwarderRequest) {
		select {
		case ss.slots <- struct{}{}:
		default:
			clientcore.LogRateLimitedEvent("tcp", "application connection refused: relay limit reached")
			r.Complete(true)
			return
		}
		var wq waiter.Queue
		endpoint, err := r.CreateEndpoint(&wq)
		if err != nil {
			<-ss.slots
			r.Complete(true)
			return
		}
		r.Complete(false)
		conn := gonet.NewTCPConn(&wq, endpoint)
		go func() {
			defer func() { <-ss.slots }()
			tcprelay.Relay(ctx, conn, opener)
		}()
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, forwarder.HandlePacket)

	// The stack's own packets (handshakes, acknowledgements, the sites' data)
	// go back to the applications through the adapter.
	go func() {
		for {
			pkt := ep.ReadContext(ctx)
			if pkt == nil {
				return
			}
			view := pkt.ToView()
			pkt.DecRef()
			write(view.AsSlice())
			view.Release()
		}
	}()
	return ss, nil
}

// inject hands one application packet (IPv4 TCP) to the stack.
func (ss *streamStack) inject(packet []byte) {
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
	ss.ep.InjectInbound(ipv4.ProtocolNumber, pkt)
	pkt.DecRef()
}

func (ss *streamStack) close() {
	ss.cancel()
	ss.ep.Close()
	ss.stack.Close()
}

// isIPv4TCP reports whether an adapter packet is IPv4 TCP.
func isIPv4TCP(packet []byte) bool {
	return len(packet) >= header.IPv4MinimumSize && packet[0]>>4 == 4 && packet[9] == uint8(header.TCPProtocolNumber)
}
