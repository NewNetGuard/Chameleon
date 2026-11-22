// Copyright (c) 2026 NewNetGuard
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package shared

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	ErrAuthFailed     = errors.New("HMAC authentication failed")
	ErrPacketTooSmall = errors.New("packet too small")
	ErrPayloadLength  = errors.New("payload length mismatch")
)

// DeriveRoutePrefix derives a deterministic 8-character alphanumeric URL prefix
// from the shared PSK. Since both server and client know the PSK, they will
// always compute the same prefix — no manual configuration sync required.
//
// The derived prefix changes only when the PSK changes, which is the desired
// behaviour: rotating the PSK automatically rotates all API paths.
func DeriveRoutePrefix(psk []byte) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte("chameleon-route-prefix-v1"))
	sum := mac.Sum(nil)

	result := make([]byte, 8)
	for i := range result {
		// Two bytes of HMAC output per character → uniform distribution over alphabet.
		idx := binary.BigEndian.Uint16(sum[i*2 : i*2+2])
		result[i] = alphabet[idx%uint16(len(alphabet))]
	}
	return string(result)
}

// packetHMAC computes HMAC-SHA256(psk, header||payload) and returns the first
// HMACPrefixSize bytes. This replaces the old static Magic Number.
func packetHMAC(psk, header, payload []byte) []byte {
	mac := hmac.New(sha256.New, psk)
	mac.Write(header)
	mac.Write(payload)
	sum := mac.Sum(nil)
	return sum[:HMACPrefixSize]
}

// Unpack parses and authenticates a raw wire packet.
// Returns the header and payload on success, or an error if auth fails.
func Unpack(psk, raw []byte) (PacketHeader, []byte, error) {
	if len(raw) < WireHeaderSize {
		return PacketHeader{}, nil, fmt.Errorf("%w: got %d bytes, need at least %d",
			ErrPacketTooSmall, len(raw), WireHeaderSize)
	}

	receivedHMAC := raw[:HMACPrefixSize]
	header := raw[HMACPrefixSize:WireHeaderSize]
	rest := raw[WireHeaderSize:]

	payloadLen := binary.BigEndian.Uint32(header[8:12])
	if uint32(len(rest)) < payloadLen {
		return PacketHeader{}, nil, fmt.Errorf("%w: header says %d, got %d",
			ErrPayloadLength, payloadLen, len(rest))
	}
	payload := rest[:payloadLen]

	// Verify HMAC.
	expectedHMAC := packetHMAC(psk, header, payload)
	if !hmac.Equal(receivedHMAC, expectedHMAC) {
		return PacketHeader{}, nil, ErrAuthFailed
	}

	ph := PacketHeader{
		PacketID:    binary.BigEndian.Uint32(header[0:4]),
		ChunkIndex:  binary.BigEndian.Uint16(header[4:6]),
		TotalChunks: binary.BigEndian.Uint16(header[6:8]),
		PayloadLen:  payloadLen,
		Type:        PacketType(header[12]),
	}

	return ph, payload, nil
}

// RouteForPrefix returns a full API path for the given suffix using the deployment prefix.
// e.g. RouteForPrefix("aBc3f1Xy", EndpointSuffixPush) → "/aBc3f1Xy/push"
func RouteForPrefix(prefix, suffix string) string {
	return "/" + prefix + suffix
}
