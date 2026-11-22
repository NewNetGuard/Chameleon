// Copyright (c) 2026 NewNetGuard
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package clientcore

import (
	"fmt"

	"chameleon/shared"
)

// Cipher provides end-to-end authenticated encryption inside the outer TLS
// transport. This keeps payloads confidential from TLS-terminating relays.
type Cipher struct {
	inner *shared.InnerCipher
}

func NewCipher(keys *shared.SessionKeys, sessionID string) (*Cipher, error) {
	if keys == nil {
		return nil, fmt.Errorf("session keys are required")
	}
	inner, err := shared.NewInnerCipher(
		keys.ClientToServerKey,
		keys.ServerToClientKey,
		keys.ClientToServerNonceBase,
		keys.ServerToClientNonceBase,
		sessionID,
		"client-to-server",
		"server-to-client",
	)
	if err != nil {
		return nil, err
	}
	return &Cipher{inner: inner}, nil
}

func (c *Cipher) Encrypt(data []byte) ([]byte, error) {
	return c.inner.Encrypt(data)
}

func (c *Cipher) Decrypt(data []byte) ([]byte, error) {
	return c.inner.Decrypt(data)
}
