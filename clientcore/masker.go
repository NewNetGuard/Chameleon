// Copyright (c) 2026 NewNetGuard
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package clientcore

import (
	"fmt"
	"sync/atomic"

	"chameleon/shared"
)

// Masker handles packet preparation for HTTP transport.
type Masker struct {
	cipher *Cipher
	psk    []byte
}

// NewMasker creates a new Masker instance.
func NewMasker(cipher *Cipher, psk []byte) *Masker {
	return &Masker{cipher: cipher, psk: psk}
}

// PadBatch copies VPN packets into their padded plaintext form (see
// padPacketBinary). The copies are
// safe to keep after the caller reuses its buffers; SealBatch encrypts them
// once the write they travel in is known.
//
// Fast path rationale:
// - Transport channel is already protected by TLS.
// - Per-packet HMAC/chunk framing costs significant CPU on mobile devices.
// - We keep payloads as raw IP packets and batch at transport layer.
func (m *Masker) PadBatch(vpnPackets [][]byte) [][]byte {
	padded := make([][]byte, 0, len(vpnPackets))
	for _, vpnPacket := range vpnPackets {
		if len(vpnPacket) == 0 {
			continue
		}
		padded = append(padded, padPacketBinary(vpnPacket))
	}
	return padded
}

// SealBatch encrypts the padded packets of one uplink write, in order. Padding
// is applied before encryption so the authenticated ciphertext hides both the
// packet contents and its exact original length from transport relays; the
// packets of a small write also get the random bucket raise
// (shared.PacketPaddingStepUp).
func (m *Masker) SealBatch(padded [][]byte) ([][]byte, error) {
	total := 0
	for _, packet := range padded {
		total += paddedPacketLength(packet)
	}
	stepUp := shared.PacketPaddingStepUp(total)

	sealed := make([][]byte, 0, len(padded))
	for _, packet := range padded {
		if len(packet) == 0 {
			continue
		}
		if stepUp {
			packet = raisePaddedPacket(packet)
		}
		encrypted, err := m.cipher.Encrypt(packet)
		if err != nil {
			return nil, fmt.Errorf("encrypt tunnel packet: %w", err)
		}
		sealed = append(sealed, encrypted)
	}
	return sealed, nil
}

// _ is a compile-time check that atomic is imported.
var _ = atomic.AddUint32
