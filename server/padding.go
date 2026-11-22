// Copyright (c) 2026 NewNetGuard
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"crypto/rand"

	"chameleon/shared"
)

// serverBinPaddingBuckets mirrors the client's binPaddingBuckets. Kept identical
// so downlink packets are normalized to the same small set of on-wire sizes.
var serverBinPaddingBuckets = []int{128, 256, 512, 768, 1024, 1280, 1456, 1600}

func serverAdaptivePaddingTarget(need int, entropy byte) int {
	base := -1
	for i, bucket := range serverBinPaddingBuckets {
		if bucket >= need {
			base = i
			break
		}
	}
	if base < 0 {
		return need
	}

	steps := 0
	switch r := entropy & 0x0f; {
	case r >= 14:
		steps = 2
	case r >= 8:
		steps = 1
	}
	maxSteps := 1
	if need <= 256 {
		maxSteps = 2
	}
	if steps > maxSteps {
		steps = maxSteps
	}
	if base+steps >= len(serverBinPaddingBuckets) {
		steps = len(serverBinPaddingBuckets) - base - 1
	}
	return serverBinPaddingBuckets[base+steps]
}

// serverBatchStepUp applies shared.PacketPaddingStepUp to the raw packets of
// one downlink write.
func serverBatchStepUp(batch [][]byte) bool {
	total := 0
	for _, packet := range batch {
		total += len(packet)
	}
	return shared.PacketPaddingStepUp(total)
}

func serverRandomPaddingTarget(need int) int {
	var entropy [1]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return serverAdaptivePaddingTarget(need, 0)
	}
	return serverAdaptivePaddingTarget(need, entropy[0])
}

// serverPadPacketBinary wraps one raw tunnel packet as
//
//	[2-byte big-endian real length][packet][random padding]
//
// padded up to the next serverBinPaddingBuckets size. Mirror of the client's
// padPacketBinary; used on the downlink so transport frame lengths do not leak
// exact IP packet sizes. Oversized packets are length-prefixed but unpadded.
// The packet is sent on its own, so its bucket gets the random raise.
func serverPadPacketBinary(pkt []byte) []byte {
	return serverPadPacketInBatch(pkt, true)
}

// serverPadPacketInBatch pads one packet of a write; stepUp comes from
// shared.PacketPaddingStepUp for the whole write (see serverBatchStepUp).
func serverPadPacketInBatch(pkt []byte, stepUp bool) []byte {
	need := 2 + len(pkt)
	target := serverAdaptivePaddingTarget(need, 0)
	if stepUp {
		target = serverRandomPaddingTarget(need)
	}
	target = max(target, shared.InnerHandshakePaddingTarget(pkt, need))
	buf := make([]byte, target)
	buf[0] = byte(len(pkt) >> 8)
	buf[1] = byte(len(pkt))
	copy(buf[2:], pkt)
	if target > need {
		rand.Read(buf[need:])
	}
	return buf
}

// serverUnpadPacketBinary reverses serverPadPacketBinary (and the client's
// padPacketBinary). ok is false when the blob is not a valid padded packet, so the
// caller can fall back to treating the bytes as-is.
func serverUnpadPacketBinary(blob []byte) (pkt []byte, ok bool) {
	if len(blob) < 2 {
		return nil, false
	}
	n := int(blob[0])<<8 | int(blob[1])
	if n <= 0 || 2+n > len(blob) {
		return nil, false
	}
	return blob[2 : 2+n], true
}
