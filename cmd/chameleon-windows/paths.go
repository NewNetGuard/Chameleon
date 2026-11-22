// Copyright (c) 2026 NewNetGuard
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build windows

package main

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

const (
	tunnelServiceName = "Chameleon"
	panelServiceName  = "ChameleonPanel"
	panelAccount      = `NT SERVICE\ChameleonPanel`
	controlPipe       = `\\.\pipe\ChameleonControl`
	panelPort         = 8443
	firewallRuleName  = "Chameleon Panel"
	adapterName       = "Chameleon"
)

// adapterGUID keeps the Chameleon adapter (and so its LUID) the same across
// restarts.
var adapterGUID = windows.GUID{Data1: 0x6c3d0a51, Data2: 0x8b2e, Data3: 0x4f0c, Data4: [8]byte{0x9a, 0x3e, 0x51, 0x7c, 0x48, 0x0d, 0x21, 0x10}}

// installDir is where this executable lives (Program Files\Chameleon once
// installed); the panel, Python and wintun.dll sit next to it.
func installDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

func programFilesDir() string {
	if dir := os.Getenv("ProgramFiles"); dir != "" {
		return filepath.Join(dir, "Chameleon")
	}
	return `C:\Program Files\Chameleon`
}

// dataRoot holds everything Chameleon writes. Its subdirectories carry their
// own access lists (see install.go).
func dataRoot() string {
	if dir := os.Getenv("ProgramData"); dir != "" {
		return filepath.Join(dir, "Chameleon")
	}
	return `C:\ProgramData\Chameleon`
}

func panelDataDir() string  { return filepath.Join(dataRoot(), "panel") }
func clientDir() string     { return filepath.Join(dataRoot(), "client") }
func policyFile() string    { return filepath.Join(dataRoot(), "policy", "policy.json") }
func credentialDir() string { return filepath.Join(dataRoot(), "credentials") }
func logDir() string        { return filepath.Join(dataRoot(), "logs") }
func clientLogFile() string { return filepath.Join(logDir(), "client.log") }
func tlsDir() string        { return filepath.Join(dataRoot(), "tls") }
func panelConfFile() string { return filepath.Join(panelDataDir(), "stealth_client.conf") }
func statusFile() string    { return filepath.Join(clientDir(), "status.json") }
func panelCertFile() string { return filepath.Join(tlsDir(), "panel.crt") }
func panelKeyFile() string  { return filepath.Join(tlsDir(), "panel.key") }
func pythonExe() string     { return filepath.Join(installDir(), "python", "python.exe") }
func panelLogFile() string  { return filepath.Join(panelDataDir(), "panel.log") }
