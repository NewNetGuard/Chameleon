// Copyright (c) 2026 NewNetGuard
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package clientcore

import (
	"time"
)

// ProfileParams defines the packet characteristics for a traffic profile.
type ProfileParams struct {
	MinPacketSize int
	MaxPacketSize int
	MinInterval   time.Duration
	MaxInterval   time.Duration
	BurstSize     int // how many packets to send in a burst without pause
}

// Predefined traffic profiles
var (
	BrowsingProfile = ProfileParams{
		MinPacketSize: 200,
		MaxPacketSize: 1400,
		MinInterval:   50 * time.Millisecond,
		MaxInterval:   300 * time.Millisecond,
		BurstSize:     3,
	}

	VideoProfile = ProfileParams{
		MinPacketSize: 1000,
		MaxPacketSize: 1500,
		MinInterval:   5 * time.Millisecond,
		MaxInterval:   30 * time.Millisecond,
		BurstSize:     10,
	}

	SystemProfile = ProfileParams{
		MinPacketSize: 64,
		MaxPacketSize: 300,
		MinInterval:   500 * time.Millisecond,
		MaxInterval:   5000 * time.Millisecond,
		BurstSize:     1,
	}

	IdleProfile = ProfileParams{
		MinPacketSize: 64,
		MaxPacketSize: 150,
		MinInterval:   2000 * time.Millisecond,
		MaxInterval:   10000 * time.Millisecond,
		BurstSize:     1,
	}
)
