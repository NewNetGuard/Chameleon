// Copyright (c) 2026 NewNetGuard
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build linux

package main

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// recordRoutes replaces ip(8) and records each command as one string.
func recordRoutes(t *testing.T) chan string {
	t.Helper()
	calls := make(chan string, 64)
	previous := routeCommand
	routeCommand = func(args ...string) error {
		calls <- strings.Join(args, " ")
		return nil
	}
	t.Cleanup(func() { routeCommand = previous })
	return calls
}

func nextRoute(t *testing.T, calls chan string) string {
	t.Helper()
	select {
	case call := <-calls:
		return call
	case <-time.After(3 * streamRouteCheckInterval):
		t.Fatal("no route change")
	}
	return ""
}

var testStreamRoute = tcpStreamRoute{Table: 51824, Via: "169.254.77.2", Dev: "chtcp0"}

// Device TCP may use streams only while the server offers them; otherwise
// (and after the client stops) it must fall back to the packet tunnel.
func TestStreamRouteFollowsServerSupport(t *testing.T) {
	calls := recordRoutes(t)
	var available atomic.Bool
	available.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		manageStreamRoute(ctx, testStreamRoute, available.Load)
		close(done)
	}()
	if call := nextRoute(t, calls); call != "route del default table 51824" {
		t.Fatalf("first command %q, want removal of a stale route", call)
	}
	if call := nextRoute(t, calls); call != "route replace default via 169.254.77.2 dev chtcp0 table 51824" {
		t.Fatalf("streams available: %q", call)
	}
	available.Store(false)
	if call := nextRoute(t, calls); call != "route del default table 51824" {
		t.Fatalf("streams withdrawn: %q", call)
	}
	available.Store(true)
	if call := nextRoute(t, calls); !strings.HasPrefix(call, "route replace") {
		t.Fatalf("streams back: %q", call)
	}
	cancel()
	<-done
	if call := nextRoute(t, calls); call != "route del default table 51824" {
		t.Fatalf("client stop: %q", call)
	}
}

func TestStreamRouteNeverInstalledWithoutServerSupport(t *testing.T) {
	calls := recordRoutes(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		manageStreamRoute(ctx, testStreamRoute, func() bool { return false })
		close(done)
	}()
	nextRoute(t, calls) // stale-route removal
	time.Sleep(2*streamRouteCheckInterval + 100*time.Millisecond)
	cancel()
	<-done
	select {
	case call := <-calls:
		t.Fatalf("unexpected route command %q", call)
	default:
	}
}

func TestStreamRouteConfigIsValidated(t *testing.T) {
	for _, route := range []tcpStreamRoute{
		{Table: 0, Via: "169.254.77.2", Dev: "chtcp0"},
		{Table: 51824, Via: "not-an-ip", Dev: "chtcp0"},
		{Table: 51824, Via: "fe80::1", Dev: "chtcp0"},
		{Table: 51824, Via: "169.254.77.2", Dev: "chtcp0; reboot"},
		{Table: 51824, Via: "169.254.77.2", Dev: "a-very-long-interface-name"},
	} {
		if route.valid() {
			t.Fatalf("accepted %+v", route)
		}
	}
	if !testStreamRoute.valid() {
		t.Fatal("rejected the netctl route")
	}
}
