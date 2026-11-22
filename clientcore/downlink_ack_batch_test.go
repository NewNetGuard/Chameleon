// Copyright (c) 2026 NewNetGuard
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package clientcore

import (
	"testing"
	"time"
)

func TestDownlinkAckDelaySpreadsAcrossTheWholeWindow(t *testing.T) {
	batcher := newDownlinkAckBatcher(&Transport{}, nil)
	low, high := time.Hour, time.Duration(0)
	for range 256 {
		delay := batcher.nextDelay()
		if delay < downlinkAckMinDelay || delay > downlinkAckMaxDelay {
			t.Fatalf("delay %v outside [%v, %v]", delay, downlinkAckMinDelay, downlinkAckMaxDelay)
		}
		low, high = min(low, delay), max(high, delay)
	}
	if high-low < (downlinkAckMaxDelay-downlinkAckMinDelay)/2 {
		t.Fatalf("ACK delays are not spread: %v..%v", low, high)
	}
}
