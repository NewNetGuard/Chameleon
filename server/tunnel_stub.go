// Copyright (c) 2026 NewNetGuard
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build !linux

package main

import "fmt"

type kernelTunnel struct{}

func (k *kernelTunnel) WritePacket(_ []byte) error {
	return fmt.Errorf("kernel tunnel is not supported on this platform")
}

func (k *kernelTunnel) ReadPacket(_ []byte) (int, error) {
	return 0, fmt.Errorf("kernel tunnel is not supported on this platform")
}

func (k *kernelTunnel) Close() error { return nil }

func startKernelTunnel(_ string, _ string, _ int, _ bool) (*kernelTunnel, error) {
	return nil, fmt.Errorf("kernel tunnel requires linux")
}
