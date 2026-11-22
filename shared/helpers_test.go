// Copyright (c) 2026 NewNetGuard
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package shared

import (
	"encoding/binary"
	"io"
)

// WriteTCPStreamFrame encrypts plaintext and writes one frame.
func WriteTCPStreamFrame(w io.Writer, cipher *InnerCipher, plaintext []byte) error {
	if len(plaintext) > TCPStreamMaxPlaintext {
		return ErrTCPStreamFrameTooLarge
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
