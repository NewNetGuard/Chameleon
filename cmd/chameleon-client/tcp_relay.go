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
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"time"

	"chameleon/clientcore"
)

// activatedTCPListener returns the transparent listener systemd passed with
// socket activation, or nil when none was passed. chameleon-netctl creates it
// inside the TCP-stream network namespace, where TPROXY delivers the computer's
// connections that already passed the routing policy; this process keeps its
// own limited privileges and never enters that namespace.
func activatedTCPListener() (net.Listener, error) {
	if os.Getenv("LISTEN_PID") != strconv.Itoa(os.Getpid()) {
		return nil, nil
	}
	count, err := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	if err != nil || count < 1 {
		return nil, nil
	}
	for _, name := range []string{"LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"} {
		_ = os.Unsetenv(name)
	}
	file := os.NewFile(3, "tcp-streams")
	defer file.Close()
	return net.FileListener(file)
}

// tcpStreamRoute is the route chameleon-netctl reserves for TCP: a default route
// in a dedicated table towards the namespace with the transparent listener.
// While it is absent, the same TCP falls through to the packet tunnel's table.
type tcpStreamRoute struct {
	Table int    `json:"table"`
	Via   string `json:"via"`
	Dev   string `json:"dev"`
}

var routeDevPattern = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)

func (r tcpStreamRoute) valid() bool {
	via, err := netip.ParseAddr(r.Via)
	return r.Table > 0 && r.Table < 1<<31 && err == nil && via.Is4() && routeDevPattern.MatchString(r.Dev)
}

// routeCommand runs ip(8); tests replace it.
var routeCommand = func(args ...string) error {
	return exec.Command("ip", args...).Run()
}

const streamRouteCheckInterval = 2 * time.Second

// manageStreamRoute keeps device TCP on streams only while the server offers
// them: the route is installed when streams become available and removed when
// they are not (an older server, a renegotiated connection without them) and
// when the client stops. Without the route device TCP takes the packet tunnel,
// so a missing stream feature never cuts the network.
func manageStreamRoute(ctx context.Context, route tcpStreamRoute, available func() bool) {
	table := strconv.Itoa(route.Table)
	installed := false
	apply := func(want bool) {
		var err error
		if want {
			err = routeCommand("route", "replace", "default", "via", route.Via, "dev", route.Dev, "table", table)
		} else {
			err = routeCommand("route", "del", "default", "table", table)
		}
		if err != nil && want {
			clientcore.LogOperationalFailure("tcp", "stream route not installed; TCP stays on the packet tunnel", err)
			return
		}
		installed = want
		if want {
			clientcore.LogState("tcp", "device TCP carried as streams")
		} else {
			clientcore.LogState("tcp", "device TCP on the packet tunnel")
		}
	}
	// A route left by a previous run must not outlive a server without streams.
	apply(false)
	ticker := time.NewTicker(streamRouteCheckInterval)
	defer ticker.Stop()
	for {
		if want := available(); want != installed {
			apply(want)
		}
		select {
		case <-ctx.Done():
			if installed {
				apply(false)
			}
			return
		case <-ticker.C:
		}
	}
}
