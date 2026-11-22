// Copyright (c) 2026 NewNetGuard
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build windows

// Command chameleon-svc is Chameleon for Windows: one executable that is
//
//	service    the tunnel service (LocalSystem): Wintun adapter, routes, kill
//	           switch, DNS through the tunnel, client core, control pipe
//	panel      the panel service (NT SERVICE\ChameleonPanel): runs the web panel
//	ctl        the panel's way to the tunnel service (like sudo chameleon-runner
//	           on Linux)
//	install    install or update from an unpacked release (administrator)
//	recover    give this computer its direct internet back (administrator)
//	uninstall  remove Chameleon; --purge also removes its settings
package main

import (
	"fmt"
	"io"
	"log"
	"os"

	"golang.org/x/sys/windows/svc"
)

func usage() int {
	fmt.Fprintln(os.Stderr, "usage: chameleon-svc <install [--source DIR] | panel-fingerprint | recover | uninstall [--purge] | ctl TOOL ARGS...>")
	return 2
}

func run() int {
	if len(os.Args) < 2 {
		return usage()
	}
	switch os.Args[1] {
	case "service", "panel":
		isService, err := svc.IsWindowsService()
		if err != nil || !isService {
			fmt.Fprintln(os.Stderr, "this command runs only as a Windows service")
			return 2
		}
		var handler svc.Handler = tunnelService{}
		name := tunnelServiceName
		if os.Args[1] == "panel" {
			handler, name = panelService{}, panelServiceName
		}
		if err := svc.Run(name, handler); err != nil {
			return 1
		}
		return 0
	case "ctl":
		return runCtl(os.Args[2:])
	case "panel-fingerprint":
		fingerprint, err := panelCertificateFingerprint()
		if err != nil {
			fmt.Fprintln(os.Stderr, "Cannot read panel certificate:", err)
			return 1
		}
		fmt.Println(fingerprint)
		return 0
	case "install":
		source := installDir()
		if len(os.Args) >= 4 && os.Args[2] == "--source" {
			source = os.Args[3]
		}
		if err := runInstall(source); err != nil {
			fmt.Fprintln(os.Stderr, "Installation failed:", err)
			return 1
		}
		return 0
	case "recover":
		log.SetOutput(io.Discard) // Wintun's driver messages are not for this console
		if err := runRecover(); err != nil {
			fmt.Fprintln(os.Stderr, "Recovery failed:", err)
			return 1
		}
		fmt.Println("Chameleon is disabled; this computer uses the internet directly.")
		return 0
	case "uninstall":
		log.SetOutput(io.Discard)
		purge := len(os.Args) >= 3 && os.Args[2] == "--purge"
		if err := runUninstall(purge); err != nil {
			fmt.Fprintln(os.Stderr, "Uninstall failed:", err)
			return 1
		}
		fmt.Println("Chameleon has been removed.")
		return 0
	}
	return usage()
}

func main() {
	os.Exit(run())
}
