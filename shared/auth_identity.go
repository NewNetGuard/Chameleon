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
	"encoding/hex"
)

const clientIdentityContext = "chameleon-client-identity-v1"

// ClientIDForPSK derives the only client identity accepted for an installation
// credential. A peer that knows one shared PSK cannot mint arbitrary client IDs
// to evade session quotas. The ID reveals no PSK material.
func ClientIDForPSK(psk []byte) string {
	mac := hmac.New(sha256.New, psk)
	_, _ = mac.Write([]byte(clientIdentityContext))
	return hex.EncodeToString(mac.Sum(nil)[:16])
}
