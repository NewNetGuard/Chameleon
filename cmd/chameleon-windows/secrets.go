// Copyright (c) 2026 NewNetGuard
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Credential broker of the panel (the Windows chameleon-secrets): SSH
// credentials are encrypted with DPAPI under the service's SYSTEM account and
// kept in a directory only SYSTEM and Administrators can open. The panel can
// store, read and delete them only through the control pipe.

var secretEntropy = []byte("chameleon-panel-credential-v1")

func secretPath(name string) (string, error) {
	switch name {
	case "ssh-password", "ssh-private-key":
		return filepath.Join(credentialDir(), "chameleon-panel-"+name+".dpapi"), nil
	}
	return "", errors.New("unsupported credential name")
}

func validateSecret(name, value string) error {
	if value == "" || strings.ContainsRune(value, 0) || !utf8.ValidString(value) {
		return errors.New("invalid credential")
	}
	switch name {
	case "ssh-password":
		if len(value) > 4096 || strings.ContainsAny(value, "\r\n") {
			return errors.New("invalid SSH password")
		}
	case "ssh-private-key":
		if len(value) > 32768 || !strings.HasPrefix(value, "-----BEGIN OPENSSH PRIVATE KEY-----\n") ||
			!strings.HasSuffix(strings.TrimRight(value, "\r\n"), "-----END OPENSSH PRIVATE KEY-----") {
			return errors.New("invalid SSH private key")
		}
	}
	return nil
}

func blob(data []byte) *windows.DataBlob {
	if len(data) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
}

func dpapi(protect bool, in []byte) ([]byte, error) {
	var out windows.DataBlob
	var err error
	if protect {
		err = windows.CryptProtectData(blob(in), nil, blob(secretEntropy), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	} else {
		err = windows.CryptUnprotectData(blob(in), nil, blob(secretEntropy), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	}
	if err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	result := make([]byte, out.Size)
	copy(result, unsafe.Slice(out.Data, out.Size))
	return result, nil
}

func secretCommand(action, name, stdin string) (string, error) {
	path, err := secretPath(name)
	if err != nil {
		return "", err
	}
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return "", errors.New("credential path must be a regular file")
	}
	switch action {
	case "store":
		if err := validateSecret(name, stdin); err != nil {
			return "", err
		}
		sealed, err := dpapi(true, []byte(stdin))
		if err != nil {
			return "", err
		}
		if err := os.MkdirAll(credentialDir(), 0o700); err != nil {
			return "", err
		}
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, sealed, 0o600); err != nil {
			return "", err
		}
		return "", os.Rename(tmp, path)
	case "read":
		sealed, err := os.ReadFile(path)
		if err != nil || len(sealed) == 0 {
			return "", errors.New("credential is not stored")
		}
		plain, err := dpapi(false, sealed)
		if err != nil {
			return "", err
		}
		return string(plain), nil
	case "exists":
		if info, err := os.Stat(path); err == nil && info.Size() > 0 {
			return "true", nil
		}
		return "false", nil
	case "delete":
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return "", err
		}
		return "", nil
	case "mode":
		if _, err := os.Stat(path); err == nil {
			return "dpapi", nil
		}
		return "none", nil
	}
	return "", errors.New("unsupported credential action")
}
