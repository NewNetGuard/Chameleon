// Copyright (c) 2026 NewNetGuard
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package shared

import "testing"

func TestClientIDForPSKIsStableAndCredentialBound(t *testing.T) {
	first := ClientIDForPSK([]byte("first-secret"))
	if first != ClientIDForPSK([]byte("first-secret")) {
		t.Fatal("client identity is not deterministic")
	}
	if first == ClientIDForPSK([]byte("second-secret")) {
		t.Fatal("different credentials produced the same client identity")
	}
	if len(first) != 32 {
		t.Fatalf("unexpected client identity length: %d", len(first))
	}
}
