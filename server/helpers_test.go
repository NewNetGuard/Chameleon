// Copyright (c) 2026 NewNetGuard
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"chameleon/shared"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"time"
)

func resetPrivacyLogLimiterForTest() {
	privacyLogs.mu.Lock()
	privacyLogs.last = make(map[string]time.Time)
	privacyLogs.mu.Unlock()
}

func privacyStructuredLogger(component string) *slog.Logger {
	return slog.New(slog.NewTextHandler(privacyErrorWriter{component: component}, nil))
}

func GenerateSessionAuthHeader(
	authKey []byte,
	sessionID, nonce, clientID, method, path string,
) string {
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	mac := shared.ComputeSessionRequestMAC(authKey, timestamp, nonce, clientID, sessionID, method, path)
	return fmt.Sprintf("Bearer %s:%s:%s:%s:%s", hex.EncodeToString(mac), timestamp, nonce, clientID, sessionID)
}

// writeTCPStreamFrame encrypts plaintext and writes one frame, as a client does.
func writeTCPStreamFrame(w io.Writer, cipher *shared.InnerCipher, plaintext []byte) error {
	if len(plaintext) > shared.TCPStreamMaxPlaintext {
		return shared.ErrTCPStreamFrameTooLarge
	}
	sealed, err := cipher.Encrypt(plaintext)
	if err != nil {
		return err
	}
	frame := make([]byte, 4+len(sealed))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(sealed)))
	copy(frame[4:], sealed)
	_, err = w.Write(frame)
	return err
}

// pack builds a packet in the chunked wire format the server still accepts as a
// fallback (HMAC prefix, header, payload); no shipping client sends it.
func pack(psk []byte, id uint32, chunkIndex, totalChunks uint16, packetType shared.PacketType, data []byte) []byte {
	header := make([]byte, shared.HeaderSize)
	binary.BigEndian.PutUint32(header[0:4], id)
	binary.BigEndian.PutUint16(header[4:6], chunkIndex)
	binary.BigEndian.PutUint16(header[6:8], totalChunks)
	binary.BigEndian.PutUint32(header[8:12], uint32(len(data)))
	header[12] = uint8(packetType)
	mac := hmac.New(sha256.New, psk)
	mac.Write(header)
	mac.Write(data)
	buf := make([]byte, 0, shared.WireHeaderSize+len(data))
	buf = append(buf, mac.Sum(nil)[:shared.HMACPrefixSize]...)
	buf = append(buf, header...)
	return append(buf, data...)
}
