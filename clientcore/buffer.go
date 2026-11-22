// Copyright (c) 2026 NewNetGuard
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package clientcore

import (
	"sync"
)

// Buffer provides a thread-safe packet buffer for storing packets
// when the connection is down.
type Buffer struct {
	queue   [][]byte
	maxSize int
	mu      sync.Mutex
}

// NewBuffer creates a new Buffer with the given maximum capacity.
func NewBuffer(maxSize int) *Buffer {
	return &Buffer{
		queue:   make([][]byte, 0, maxSize),
		maxSize: maxSize,
	}
}

// Add appends a packet to the buffer.
// If the buffer is full, the oldest packet is removed.
func (b *Buffer) Add(packet []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.queue) >= b.maxSize {
		// Remove the oldest packet
		b.queue = b.queue[1:]
	}

	// Make a copy to avoid holding references to external memory
	pktCopy := make([]byte, len(packet))
	copy(pktCopy, packet)
	b.queue = append(b.queue, pktCopy)
}

// Flush returns all buffered packets and clears the buffer.
func (b *Buffer) Flush() [][]byte {
	b.mu.Lock()
	defer b.mu.Unlock()

	packets := b.queue
	b.queue = make([][]byte, 0, b.maxSize)
	return packets
}
