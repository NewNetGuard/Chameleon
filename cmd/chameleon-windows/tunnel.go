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
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"chameleon/clientcore"
	"chameleon/tcprelay"
)

const (
	tunnelMTU = 1420
)

var (
	tunnelAddress = netip.MustParsePrefix("10.10.0.2/32")
	// Two halves instead of one default route: more specific than any default
	// route of the uplink, whatever its metric.
	tunnelRoutes = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1")}
	// Resolvers used through the tunnel, the same as the Linux DNS proxy's.
	tunnelDNS = []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("9.9.9.9")}
)

// tunnel is one running Chameleon tunnel: the Wintun adapter, its routes, the
// direct route to the server and the client core moving packets.
type tunnel struct {
	cfg    *tunnelConfig
	dev    *tun.NativeTun
	luid   winipcfg.LUID
	client atomic.Pointer[clientcore.MobileClient]
	stop   chan struct{}
	wg     sync.WaitGroup

	routeMu   sync.Mutex
	hostRoute *uplinkRoute

	// streams carries application TCP as TCP streams while the server
	// offers them (streamsOn); otherwise TCP stays on the packet tunnel.
	streams   *streamStack
	streamsOn atomic.Bool
}

type uplinkRoute struct {
	luid winipcfg.LUID
	gw   netip.Addr
}

func retryNotFound(op func() error) error {
	var err error
	for i := 0; i < 10; i++ {
		if err = op(); !errors.Is(err, windows.ERROR_NOT_FOUND) {
			return err
		}
		time.Sleep(300 * time.Millisecond)
	}
	return err
}

func startTunnel(cfg *tunnelConfig) (*tunnel, error) {
	tun.WintunTunnelType = "Chameleon"
	// A previous process that did not shut down cleanly leaves its adapter.
	if stale, err := wintun.OpenAdapter(adapterName); err == nil {
		_ = stale.Close()
	}
	dev, err := tun.CreateTUNWithRequestedGUID(adapterName, &adapterGUID, tunnelMTU)
	if err != nil {
		return nil, fmt.Errorf("create adapter: %w", err)
	}
	nt := dev.(*tun.NativeTun)
	t := &tunnel{cfg: cfg, dev: nt, luid: winipcfg.LUID(nt.LUID()), stop: make(chan struct{})}
	go func() {
		for range nt.Events() {
		}
	}()
	if err := t.configureInterface(); err != nil {
		_ = nt.Close()
		return nil, err
	}
	if err := t.updateHostRoute(); err != nil {
		_ = nt.Close()
		return nil, err
	}
	streams, err := newStreamStack(t.writePacket, t.openStream)
	if err != nil {
		_ = nt.Close()
		t.removeHostRoute()
		return nil, err
	}
	t.streams = streams
	t.wg.Add(5)
	go t.uplink()
	go t.downlink()
	go t.runClient()
	go t.watchUplink()
	go t.watchStreams()
	flushDNSCache()
	clientcore.LogState("tun", "adapter configured, all traffic routed into the tunnel")
	return t, nil
}

func (t *tunnel) configureInterface() error {
	luid := t.luid
	// Routes first, then the address. SetRoutesForFamily flushes every IPv4
	// route of the interface, including the local host route Windows creates
	// for an assigned address. Without that route Windows drops every packet
	// delivered to 10.10.0.2 as "not locally destined" (seen on Windows 11
	// 24H2), so the tunnel connects but nothing comes back.
	routes := make([]*winipcfg.RouteData, 0, len(tunnelRoutes))
	for _, prefix := range tunnelRoutes {
		routes = append(routes, &winipcfg.RouteData{Destination: prefix, NextHop: netip.IPv4Unspecified()})
	}
	if err := retryNotFound(func() error { return luid.SetRoutesForFamily(windows.AF_INET, routes) }); err != nil {
		return fmt.Errorf("set routes: %w", err)
	}
	if err := retryNotFound(func() error {
		return luid.SetIPAddressesForFamily(windows.AF_INET, []netip.Prefix{tunnelAddress})
	}); err != nil {
		return fmt.Errorf("set address: %w", err)
	}
	if err := retryNotFound(func() error {
		ipif, err := luid.IPInterface(windows.AF_INET)
		if err != nil {
			return err
		}
		ipif.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
		ipif.DadTransmits = 0
		ipif.ManagedAddressConfigurationSupported = false
		ipif.OtherStatefulConfigurationSupported = false
		ipif.NLMTU = tunnelMTU
		ipif.UseAutomaticMetric = false
		ipif.Metric = 0
		return ipif.Set()
	}); err != nil {
		return fmt.Errorf("set metric and MTU: %w", err)
	}
	if err := retryNotFound(func() error { return luid.SetDNS(windows.AF_INET, tunnelDNS, nil) }); err != nil {
		return fmt.Errorf("set DNS: %w", err)
	}
	return nil
}

// bestUplink finds the ordinary default route of this computer: the one the
// server must be reached through.
func bestUplink(exclude winipcfg.LUID) (*uplinkRoute, error) {
	rows, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return nil, err
	}
	var best *uplinkRoute
	bestMetric := ^uint32(0)
	for i := range rows {
		row := &rows[i]
		if row.DestinationPrefix.PrefixLength != 0 || row.InterfaceLUID == exclude {
			continue
		}
		iface, err := row.InterfaceLUID.Interface()
		if err != nil || iface.OperStatus != winipcfg.IfOperStatusUp {
			continue
		}
		ipif, err := row.InterfaceLUID.IPInterface(windows.AF_INET)
		if err != nil || !ipif.Connected {
			continue
		}
		metric := row.Metric + ipif.Metric
		if metric < bestMetric {
			bestMetric = metric
			best = &uplinkRoute{luid: row.InterfaceLUID, gw: row.NextHop.Addr()}
		}
	}
	if best == nil {
		return nil, errors.New("no network connection")
	}
	return best, nil
}

// updateHostRoute keeps the server reachable outside the tunnel through the
// current uplink (Wi-Fi to cable and back).
func (t *tunnel) updateHostRoute() error {
	t.routeMu.Lock()
	defer t.routeMu.Unlock()
	up, err := bestUplink(t.luid)
	if err != nil {
		return err
	}
	if t.hostRoute != nil && *t.hostRoute == *up {
		return nil
	}
	dest := netip.PrefixFrom(t.cfg.serverIP, 32)
	if t.hostRoute != nil {
		_ = t.hostRoute.luid.DeleteRoute(dest, t.hostRoute.gw)
		t.hostRoute = nil
	}
	gw := up.gw
	if !gw.IsValid() {
		gw = netip.IPv4Unspecified()
	}
	if err := up.luid.AddRoute(dest, gw, 0); err != nil && !errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
		return fmt.Errorf("route to server: %w", err)
	}
	t.hostRoute = &uplinkRoute{luid: up.luid, gw: gw}
	clientcore.LogState("route", "server reached through the current network connection")
	return nil
}

func (t *tunnel) removeHostRoute() {
	t.routeMu.Lock()
	defer t.routeMu.Unlock()
	if t.hostRoute != nil {
		_ = t.hostRoute.luid.DeleteRoute(netip.PrefixFrom(t.cfg.serverIP, 32), t.hostRoute.gw)
		t.hostRoute = nil
	}
}

func (t *tunnel) watchUplink() {
	defer t.wg.Done()
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-t.stop:
			return
		case <-ticker.C:
			if err := t.updateHostRoute(); err != nil {
				clientcore.LogOperationalFailure("route", "server route update failed", err)
			}
		}
	}
}

// uplink: applications -> adapter -> tunnel.
func (t *tunnel) uplink() {
	defer t.wg.Done()
	bufs := [][]byte{make([]byte, 65535)}
	sizes := []int{0}
	for {
		n, err := t.dev.Read(bufs, sizes, 0)
		if err != nil {
			if errors.Is(err, os.ErrClosed) {
				return
			}
			clientcore.LogOperationalFailure("uplink", "adapter read failed", err)
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if n == 0 || sizes[0] <= 0 {
			continue
		}
		if t.streamsOn.Load() && isIPv4TCP(bufs[0][:sizes[0]]) {
			t.streams.inject(bufs[0][:sizes[0]]) // copies the packet
			continue
		}
		c := t.client.Load()
		if c == nil {
			continue // not connected yet: the packet is dropped
		}
		pkt := make([]byte, sizes[0])
		copy(pkt, bufs[0][:sizes[0]])
		_ = c.PushPacket(pkt)
	}
}

// writePacket hands one packet to the applications through the adapter.
func (t *tunnel) writePacket(pkt []byte) {
	if _, err := t.dev.Write([][]byte{pkt}, 0); err != nil && !errors.Is(err, os.ErrClosed) {
		clientcore.LogOperationalFailure("downlink", "adapter write failed", err)
	}
}

// openStream opens a TCP stream on the current connection.
func (t *tunnel) openStream(ctx context.Context, target netip.AddrPort, early []byte) (tcprelay.Stream, error) {
	c := t.client.Load()
	if c == nil {
		return nil, errors.New("not connected")
	}
	return tcprelay.ClientOpener(c)(ctx, target, early)
}

// watchStreams sends application TCP to the stream stack only while the
// server offers streams, so a server without them never cuts the network.
func (t *tunnel) watchStreams() {
	defer t.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		c := t.client.Load()
		want := c != nil && c.TCPStreamsAvailable()
		if t.streamsOn.Swap(want) != want {
			if want {
				clientcore.LogState("tcp", "application TCP carried as streams")
			} else {
				clientcore.LogState("tcp", "application TCP on the packet tunnel")
			}
		}
		select {
		case <-t.stop:
			t.streamsOn.Store(false)
			return
		case <-ticker.C:
		}
	}
}

// downlink: tunnel -> adapter -> applications.
func (t *tunnel) downlink() {
	defer t.wg.Done()
	one := make([][]byte, 1)
	write := func(pkt []byte) bool {
		one[0] = pkt
		if _, err := t.dev.Write(one, 0); err != nil {
			if errors.Is(err, os.ErrClosed) {
				return false
			}
			clientcore.LogOperationalFailure("downlink", "adapter write failed", err)
		}
		return true
	}
	for {
		select {
		case <-t.stop:
			return
		default:
		}
		c := t.client.Load()
		if c == nil {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		if pkt := c.WaitPacket(50); pkt != nil {
			if !write(pkt) {
				return
			}
		}
		batch := c.PullPacketBatch(64, 256*1024)
		for off := 0; off+2 <= len(batch); {
			plen := int(binary.BigEndian.Uint16(batch[off : off+2]))
			off += 2
			if plen <= 0 || off+plen > len(batch) {
				break
			}
			if !write(batch[off : off+plen]) {
				return
			}
			off += plen
		}
	}
}

// runClient connects the client core and keeps retrying until stopped. While
// it is not connected the kill switch keeps every application offline.
func (t *tunnel) runClient() {
	defer t.wg.Done()
	backoff := 2 * time.Second
	for {
		select {
		case <-t.stop:
			return
		default:
		}
		c := clientcore.NewMobileClient()
		if e := c.SetConfigJSON(string(t.cfg.clientJSON)); e != "" {
			clientcore.WriteFailureStatus(statusFile(), t.cfg.server, e)
			clientcore.LogState("client", "configuration rejected")
			return
		}
		clientcore.LogState("client", "connecting")
		if e := c.StartClient(); e != "" {
			clientcore.WriteFailureStatus(statusFile(), t.cfg.server, e)
			clientcore.LogState("client", "start failed: "+e)
			select {
			case <-t.stop:
				return
			case <-time.After(backoff):
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		select {
		case <-t.stop:
			c.StopClient()
			return
		default:
		}
		_ = os.Remove(statusFile())
		t.client.Store(c)
		clientcore.LogState("client", "connected")
		<-t.stop
		t.client.Store(nil)
		c.StopClient()
		return
	}
}

func (t *tunnel) stats() string {
	if c := t.client.Load(); c != nil {
		return c.GetStats()
	}
	return ""
}

func (t *tunnel) close() {
	close(t.stop)
	if c := t.client.Swap(nil); c != nil {
		c.StopClient()
	}
	t.streamsOn.Store(false)
	t.streams.close()
	_ = t.dev.Close() // removes the adapter with its routes
	t.removeHostRoute()
	done := make(chan struct{})
	go func() { t.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
	flushDNSCache()
	clientcore.LogState("tun", "adapter removed")
}

var procDnsFlushResolverCache = windows.NewLazySystemDLL("dnsapi.dll").NewProc("DnsFlushResolverCache")

func flushDNSCache() {
	if procDnsFlushResolverCache.Find() == nil {
		_, _, _ = procDnsFlushResolverCache.Call()
	}
}
