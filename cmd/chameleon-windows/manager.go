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
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/windows"

	"chameleon/clientcore"
	"chameleon/cmd/chameleon-windows/winfw"
)

// policyState is what survives restarts: whether this computer must stay
// behind the tunnel (the kill switch) and how.
type policyState struct {
	Enabled   bool   `json:"enabled"`
	BlockQUIC bool   `json:"block_quic"`
	ServerIP  string `json:"server_ip,omitempty"`
}

func readPolicy() policyState {
	var p policyState
	if data, err := os.ReadFile(policyFile()); err == nil {
		_ = json.Unmarshal(data, &p)
	}
	return p
}

func writePolicy(p policyState) error {
	data, _ := json.Marshal(p)
	if err := os.MkdirAll(filepath.Dir(policyFile()), 0o700); err != nil {
		return err
	}
	tmp := policyFile() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, policyFile())
}

// manager is the privileged side of the panel: the Windows counterpart of
// chameleon-netctl.
type manager struct {
	mu       sync.Mutex
	t        *tunnel
	policy   policyState
	panelSID *windows.SID
}

func newManager() *manager {
	m := &manager{policy: readPolicy()}
	if sid, _, _, err := windows.LookupSID("", panelAccount); err == nil {
		m.panelSID = sid
	}
	return m
}

func (m *manager) firewallPolicy() winfw.Policy {
	p := winfw.Policy{BlockQUIC: m.policy.BlockQUIC, PanelUser: m.panelSID}
	if addr, err := netip.ParseAddr(m.policy.ServerIP); err == nil {
		p.Server = addr
	}
	if m.t != nil {
		p.TunnelLUID = uint64(m.t.luid)
	}
	return p
}

func errorResult(err error) map[string]any {
	return map[string]any{"success": false, "error": err.Error()}
}

// up starts (or restarts) the tunnel. The kill switch goes in first, so
// nothing leaves directly while the tunnel starts or if it cannot.
func (m *manager) up(confPath string, blockQUIC bool) map[string]any {
	cfg, err := loadTunnelConfig(confPath)
	if err != nil {
		return errorResult(err)
	}
	m.mu.Lock()
	m.policy = policyState{Enabled: true, BlockQUIC: blockQUIC, ServerIP: cfg.serverIP.String()}
	if err := writePolicy(m.policy); err != nil {
		m.mu.Unlock()
		return errorResult(err)
	}
	if m.t != nil {
		m.t.close()
		m.t = nil
	}
	if err := winfw.Apply(m.firewallPolicy()); err != nil {
		m.mu.Unlock()
		clientcore.LogState("firewall", "kill switch failed: "+err.Error())
		return errorResult(errors.New("kill switch could not be installed"))
	}
	t, err := startTunnel(cfg)
	if err != nil {
		m.mu.Unlock()
		clientcore.LogState("tun", "start failed: "+err.Error())
		res := m.status()
		res["error"] = err.Error()
		return res
	}
	m.t = t
	if err := winfw.Apply(m.firewallPolicy()); err != nil {
		clientcore.LogState("firewall", "kill switch update failed: "+err.Error())
	}
	m.mu.Unlock()

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if st := m.status(); st["connected"] == true {
			return st
		}
		time.Sleep(500 * time.Millisecond)
	}
	return m.status()
}

// down stops the tunnel and removes the kill switch: the computer uses the
// internet directly again.
func (m *manager) down() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policy.Enabled = false
	_ = writePolicy(m.policy)
	if m.t != nil {
		m.t.close()
		m.t = nil
	}
	if err := winfw.Remove(); err != nil {
		return errorResult(err)
	}
	_ = os.Remove(statusFile())
	flushDNSCache()
	clientcore.LogState("client", "disabled")
	return map[string]any{"success": true}
}

// resume restores an enabled tunnel when the service starts (boot, restart,
// update). The persistent kill switch already blocks the internet meanwhile.
func (m *manager) resume() {
	m.mu.Lock()
	enabled := m.policy.Enabled
	if enabled {
		if err := winfw.Apply(m.firewallPolicy()); err != nil {
			clientcore.LogState("firewall", "kill switch failed: "+err.Error())
		}
	}
	m.mu.Unlock()
	if !enabled {
		return
	}
	for attempt := 0; ; attempt++ {
		res := m.up(panelConfFile(), m.policy.BlockQUIC)
		if res["running"] == true {
			return
		}
		if attempt >= 20 {
			return // the panel's reconcile loop keeps trying
		}
		time.Sleep(15 * time.Second)
	}
}

// shutdown stops the tunnel when the service stops. The kill switch stays.
func (m *manager) shutdown() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.t != nil {
		m.t.close()
		m.t = nil
	}
}

func (m *manager) status() map[string]any {
	m.mu.Lock()
	t := m.t
	policy := m.policy
	m.mu.Unlock()

	res := map[string]any{
		"success": true, "running": t != nil, "connected": false, "server": "",
		"fingerprint": "", "behavior": "", "shield": "", "bytes_sent": 0, "bytes_recv": 0,
		"killswitch": false, "dns_protected": false, "quic_blocked": false, "tcp_streams": false,
		"failure_code": "", "health_error": "", "failed_at": "",
	}
	var stats map[string]any
	if t != nil {
		if s := t.stats(); s != "" {
			_ = json.Unmarshal([]byte(s), &stats)
		}
	}
	if stats == nil {
		if data, err := os.ReadFile(statusFile()); err == nil {
			_ = json.Unmarshal(data, &stats)
		}
	}
	for key, from := range map[string]string{
		"connected": "connected", "server": "server_addr", "fingerprint": "fingerprint",
		"behavior": "behavior", "shield": "shield_domain", "bytes_sent": "bytes_sent",
		"bytes_recv": "bytes_recv", "failure_code": "failure_code",
		"health_error": "health_error", "failed_at": "failed_at", "tcp_streams": "tcp_streams",
	} {
		if v, ok := stats[from]; ok && v != nil {
			res[key] = v
		}
	}
	if t == nil && policy.Enabled && res["failure_code"] == "" {
		res["failure_code"] = "client_stopped"
		res["health_error"] = "The kill switch is active, but the Chameleon client is not connected"
	}
	if policy.Enabled && winfw.Active() {
		res["killswitch"] = true
		res["dns_protected"] = true
		res["quic_blocked"] = policy.BlockQUIC
	}
	return res
}
