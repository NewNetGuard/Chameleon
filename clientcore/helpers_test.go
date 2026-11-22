// Copyright (c) 2026 NewNetGuard
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package clientcore

import "time"

// DefaultConfig returns sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		ServerAddress:       "127.0.0.1:443",
		PSKKey:              "",
		Protocol:            "http2",
		DNSListenAddr:       "127.0.0.1:53",
		BufferSize:          1000,
		ReconnectInterval:   5,
		FingerprintMode:     "auto",
		RealityShieldPreset: "ip",
	}
}

func (t *connectionTracker) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.conns)
}

func resetPrivacyLogLimiterForTest() {
	privacyLogs.mu.Lock()
	privacyLogs.last = make(map[string]time.Time)
	privacyLogs.mu.Unlock()
}
