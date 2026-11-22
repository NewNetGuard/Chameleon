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
)

// MobilePSK is a device credential, never a public routing/marker key.
func MobilePSK(master []byte, deviceID string) []byte {
	mac := hmac.New(sha256.New, master)
	mac.Write([]byte("easypi/mobile-auth/v1/" + deviceID))
	return mac.Sum(nil)
}
