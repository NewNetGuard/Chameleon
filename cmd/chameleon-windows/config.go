// Copyright (c) 2026 NewNetGuard
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build windows

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// The panel writes its client settings into its own data directory; the
// service accepts exactly that file and rebuilds a clean configuration from
// it, the way chameleon-netctl does on Linux.

var (
	hexKey    = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	hostLabel = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
)

type tunnelConfig struct {
	clientJSON []byte     // configuration for clientcore
	serverIP   netip.Addr // public IPv4 the carrier dials
	server     string     // host:port shown in the status
}

func validHost(value string) bool {
	if value == "" || len(value) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return true
	}
	labels := strings.Split(strings.TrimSuffix(value, "."), ".")
	for _, label := range labels {
		if !hostLabel.MatchString(label) {
			return false
		}
	}
	return len(labels) > 0
}

func publicIPv4(addr netip.Addr) bool {
	return addr.Is4() && addr.IsGlobalUnicast() && !addr.IsPrivate()
}

func samePath(a, b string) bool {
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

func loadTunnelConfig(path string) (*tunnelConfig, error) {
	if !samePath(path, panelConfFile()) {
		return nil, errors.New("unexpected configuration path")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, errors.New("client configuration not found")
	}
	if !info.Mode().IsRegular() || info.Size() > 64*1024 {
		return nil, errors.New("invalid source config")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("client configuration unreadable")
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, errors.New("config must be a JSON object")
	}
	str := func(key string) string {
		if v, ok := raw[key].(string); ok {
			return strings.TrimSpace(v)
		}
		return ""
	}
	num := func(key string, def int) int {
		switch v := raw[key].(type) {
		case float64:
			return int(v)
		case string:
			if n, err := strconv.Atoi(v); err == nil {
				return n
			}
			return -1
		}
		return def
	}

	psk := str("psk_key")
	transportKey := str("transport_key")
	if transportKey == "" {
		transportKey = psk
	}
	reality := str("reality_server_public_key")
	if !hexKey.MatchString(psk) || !hexKey.MatchString(transportKey) || !hexKey.MatchString(reality) {
		return nil, errors.New("invalid tunnel key")
	}
	if str("reality_shield_preset") != "ip" {
		return nil, errors.New("only IP Shield is supported")
	}
	if v, _ := raw["verify_server_certificate"].(bool); !v {
		return nil, errors.New("IP Shield requires server certificate verification")
	}
	doh := str("doh_domain")
	if doh != "" && !validHost(doh) {
		return nil, errors.New("invalid DoH domain")
	}
	bufferSize := num("buffer_size", 1000)
	reconnect := num("reconnect_interval", 5)
	mode := strings.ToLower(str("fingerprint_mode"))
	if mode == "" {
		mode = "auto"
	}
	if bufferSize < 64 || bufferSize > 65535 {
		return nil, errors.New("invalid buffer size")
	}
	if reconnect < 1 || reconnect > 300 {
		return nil, errors.New("invalid reconnect interval")
	}
	if mode != "auto" && mode != "mobile" && mode != "desktop" {
		return nil, errors.New("invalid fingerprint mode")
	}

	host, portText, err := net.SplitHostPort(str("server_address"))
	if err != nil || !validHost(host) {
		return nil, errors.New("invalid endpoint")
	}
	if portText != "443" {
		return nil, errors.New("IP Shield endpoint must use port 443")
	}
	var routeIP netip.Addr
	if value := str("server_route_ip"); value != "" {
		if routeIP, err = netip.ParseAddr(value); err != nil || !publicIPv4(routeIP) {
			return nil, errors.New("server route must be a public IPv4 address")
		}
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		if routeIP.IsValid() {
			address = routeIP
		} else {
			ips, lookupErr := net.LookupIP(host)
			if lookupErr != nil {
				return nil, errors.New("cannot resolve server endpoint")
			}
			for _, ip := range ips {
				if v4 := ip.To4(); v4 != nil {
					address = netip.AddrFrom4([4]byte(v4))
					break
				}
			}
		}
	}
	if !publicIPv4(address) {
		return nil, errors.New("server endpoint must resolve to a public IPv4 address")
	}
	if routeIP.IsValid() && routeIP != address {
		return nil, errors.New("server route does not match the endpoint address")
	}
	endpoint := net.JoinHostPort(host, "443")
	clean := map[string]any{
		"server_address":            endpoint,
		"server_dial_address":       fmt.Sprintf("%s:443", address),
		"psk_key":                   strings.ToLower(psk),
		"transport_key":             strings.ToLower(transportKey),
		"protocol":                  "http2",
		"reality_server_public_key": strings.ToLower(reality),
		"reality_shield_preset":     "ip",
		"verify_server_certificate": true,
		"doh_domain":                doh,
		"buffer_size":               bufferSize,
		"reconnect_interval":        reconnect,
		"fingerprint_mode":          mode,
	}
	out, err := json.Marshal(clean)
	if err != nil {
		return nil, err
	}
	return &tunnelConfig{clientJSON: out, serverIP: address, server: endpoint}, nil
}
