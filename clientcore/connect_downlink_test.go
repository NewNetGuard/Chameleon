// Copyright (c) 2026 NewNetGuard
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package clientcore

import (
	"bytes"
	"context"
	"testing"
)

func TestPollDrainsConnectDownlinkDuringReconnect(t *testing.T) {
	transport := &Transport{
		ctx: context.Background(), streamEnabled: true, streamRx: make(chan []byte, 1),
	}
	transport.connectCarrierEnabled.Store(true)
	want := []byte("queued reply")
	transport.streamRx <- want

	got, err := transport.Poll()
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("Poll() = %q, %v; want %q", got, err, want)
	}
}
