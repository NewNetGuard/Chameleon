// Copyright (c) 2026 NewNetGuard
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build !windows

package clientcore

// applyWindowsDNS is a no-op on non-Windows platforms.
// On Linux/macOS, DNS can be redirected via resolv.conf or system settings.
func applyWindowsDNS(dnsListenIP string) ([]dnsAdapterState, error) {
	return nil, nil
}

// restoreWindowsDNS is a no-op on non-Windows platforms.
func restoreWindowsDNS(states []dnsAdapterState) {}

// dnsAdapterState placeholder for cross-platform compilation.
type dnsAdapterState struct{}
