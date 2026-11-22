// Copyright (c) 2026 NewNetGuard
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package clientcore

import (
	"encoding/hex"
)

// Config holds the client configuration.
type Config struct {
	ServerAddress           string `json:"server_address"`
	ServerDialAddress       string `json:"server_dial_address,omitempty"` // optional validated IP:port used only for the TCP dial
	PSKKey                  string `json:"psk_key"`                       // hex-encoded PSK
	TransportKey            string `json:"transport_key,omitempty"`       // routing/cover marker only, not session authentication
	Protocol                string `json:"protocol"`                      // fixed to "http2"
	DoHDomain               string `json:"doh_domain"`                    // Domain for DoH polling
	DNSListenAddr           string `json:"dns_listen_addr"`               // Local DNS proxy address, e.g. "127.0.0.1:53"
	BufferSize              int    `json:"buffer_size"`
	ReconnectInterval       int    `json:"reconnect_interval"`        // seconds
	FingerprintMode         string `json:"fingerprint_mode"`          // auto, mobile, or desktop
	BootstrapCertSHA256     string `json:"bootstrap_cert_sha256"`     // optional SHA-256 pin for tunnel TLS cert
	VerifyServerCertificate bool   `json:"verify_server_certificate"` // verify public CA + endpoint IP/DNS identity

	// REALITY settings
	RealityServerPublicKey string `json:"reality_server_public_key"` // hex-encoded
	RealityShieldPreset    string `json:"reality_shield_preset"`     // compatibility field; only "ip" is accepted
	RealityShieldDomain    string `json:"reality_shield_domain"`     // compatibility field; must be empty for IP Shield
}

func normalizeProtocol(_ string) string {
	// Single stable transport mode.
	return "http2"
}

// GetPSKBytes returns the PSK key as raw bytes from hex encoding.
func (c *Config) GetPSKBytes() ([]byte, error) {
	return hex.DecodeString(c.PSKKey)
}
