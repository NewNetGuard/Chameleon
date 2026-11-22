// Copyright (c) 2026 NewNetGuard
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package clientcore

import (
	"crypto/rand"

	"chameleon/shared"
)

// binPaddingBuckets is the size ladder (bytes, including the 2-byte length prefix)
// used to normalize INDIVIDUAL tunnel packets in the fast binary path. Kept tight
// around the tunnel MTU so overhead stays low: small control packets collapse onto
// a handful of sizes and full-MTU packets land on one bucket. Must stay identical
// to the server's serverBinPaddingBuckets.
var binPaddingBuckets = []int{128, 256, 512, 768, 1024, 1280, 1456, 1600}

// adaptivePaddingTarget keeps the compact bucket format while avoiding a
// deterministic packet-size -> wire-size mapping. Small packets may advance by
// two buckets; larger packets by one. entropy is passed in so the policy can be
// tested without weakening runtime randomness.
func adaptivePaddingTarget(need int, buckets []int, entropy byte) int {
	base := -1
	for i, bucket := range buckets {
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
	if base+steps >= len(buckets) {
		steps = len(buckets) - base - 1
	}
	return buckets[base+steps]
}

// padPacketBinary wraps one raw tunnel packet as
//
//	[2-byte big-endian real length][packet][random padding]
//
// padded up to its binPaddingBuckets size, so the length that surfaces in the
// transport's binary frame header is quantized to a small set of values instead of
// leaking the exact IP packet size to size-based classifiers. Oversized packets
// (larger than the top bucket) are sent length-prefixed but unpadded. Returns a
// fresh buffer (safe to retain / send).
//
// The random bucket raise is left to raisePaddedPacket: whether it is needed
// depends on the write the packet ends up in (shared.PacketPaddingStepUp).
func padPacketBinary(pkt []byte) []byte {
	need := 2 + len(pkt)
	target := adaptivePaddingTarget(need, binPaddingBuckets, 0)
	target = max(target, shared.InnerHandshakePaddingTarget(pkt, need))
	buf := make([]byte, target)
	buf[0] = byte(len(pkt) >> 8)
	buf[1] = byte(len(pkt))
	copy(buf[2:], pkt)
	if target > need {
		rand.Read(buf[need:]) // random tail, indistinguishable from ciphertext
	}
	return buf
}

// paddedPacketLength returns the real packet length of a padPacketBinary buffer.
func paddedPacketLength(padded []byte) int {
	if len(padded) < 2 {
		return 0
	}
	return int(padded[0])<<8 | int(padded[1])
}

// raisePaddedPacket gives a padPacketBinary buffer the random bucket raise of
// adaptivePaddingTarget. The result has exactly the size distribution a packet
// padded with the raise in one step would have.
func raisePaddedPacket(padded []byte) []byte {
	var entropy [1]byte
	_, _ = rand.Read(entropy[:])
	target := adaptivePaddingTarget(2+paddedPacketLength(padded), binPaddingBuckets, entropy[0])
	if target <= len(padded) {
		return padded
	}
	raised := make([]byte, target)
	copy(raised, padded)
	rand.Read(raised[len(padded):])
	return raised
}

// unpadPacketBinary reverses padPacketBinary. ok is false when the blob is not a
// valid padded packet (e.g. an un-padded payload from a legacy peer), letting the
// caller fall back to treating the bytes as-is.
func unpadPacketBinary(blob []byte) (pkt []byte, ok bool) {
	if len(blob) < 2 {
		return nil, false
	}
	n := int(blob[0])<<8 | int(blob[1])
	if n <= 0 || 2+n > len(blob) {
		return nil, false
	}
	return blob[2 : 2+n], true
}
