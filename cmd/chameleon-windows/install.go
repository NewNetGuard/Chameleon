// Copyright (c) 2026 NewNetGuard
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build windows

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"golang.zx2c4.com/wintun"

	"chameleon/cmd/chameleon-windows/winfw"
)

// ── access lists ────────────────────────────────────────────────────────────

const (
	aceFull   = "FA"
	aceModify = "0x1301bf"
	aceRead   = "0x1200a9"
)

func protectedDir(path string, panel *windows.SID, panelRights string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	sddl := "D:P(A;OICI;" + aceFull + ";;;SY)(A;OICI;" + aceFull + ";;;BA)"
	if panel != nil && panelRights != "" {
		sddl += "(A;OICI;" + panelRights + ";;;" + panel.String() + ")"
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

func prepareDataDirs(panel *windows.SID) error {
	steps := []struct {
		path   string
		rights string
	}{
		{dataRoot(), ""},
		{clientDir(), ""},
		{filepath.Dir(policyFile()), ""},
		{credentialDir(), ""},
		{panelDataDir(), aceModify},
		{logDir(), aceRead},
		{tlsDir(), aceRead},
	}
	for _, step := range steps {
		if err := protectedDir(step.path, panel, step.rights); err != nil {
			return fmt.Errorf("%s: %w", step.path, err)
		}
	}
	return nil
}

// ── panel certificate ───────────────────────────────────────────────────────

func panelCertificateFingerprint() (string, error) {
	data, err := os.ReadFile(panelCertFile())
	if err != nil {
		return "", err
	}
	cert, _ := pem.Decode(data)
	if cert == nil || cert.Type != "CERTIFICATE" {
		return "", errors.New("invalid panel certificate")
	}
	return fmt.Sprintf("%X", sha256.Sum256(cert.Bytes)), nil
}

func ensurePanelCertificate() error {
	if _, err := os.Stat(panelCertFile()); err == nil {
		if _, err := os.Stat(panelKeyFile()); err == nil {
			return nil
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	host, _ := os.Hostname()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Chameleon Panel"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	if host != "" {
		tmpl.DNSNames = append(tmpl.DNSNames, host, strings.ToLower(host)+".local")
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil && ipnet.IP.IsPrivate() {
				tmpl.IPAddresses = append(tmpl.IPAddresses, ipnet.IP)
			}
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(panelKeyFile(), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return err
	}
	return os.WriteFile(panelCertFile(), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

// ── services ────────────────────────────────────────────────────────────────

func stopService(m *mgr.Mgr, name string) {
	s, err := m.OpenService(name)
	if err != nil {
		return
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil || st.State == svc.Stopped {
		return
	}
	_, _ = s.Control(svc.Stop)
	for i := 0; i < 60; i++ {
		time.Sleep(250 * time.Millisecond)
		if st, err := s.Query(); err != nil || st.State == svc.Stopped {
			return
		}
	}
}

func startService(m *mgr.Mgr, name string) error {
	s, err := m.OpenService(name)
	if err != nil {
		return err
	}
	defer s.Close()
	if st, err := s.Query(); err == nil && st.State == svc.Running {
		return nil
	}
	if err := s.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return err
	}
	return nil
}

func ensureService(m *mgr.Mgr, name, display, description, account string, deps []string, arg string) error {
	exe := filepath.Join(programFilesDir(), "chameleon-svc.exe")
	cfg := mgr.Config{
		DisplayName:      display,
		Description:      description,
		StartType:        mgr.StartAutomatic,
		ServiceStartName: account,
		SidType:          windows.SERVICE_SID_TYPE_UNRESTRICTED,
		Dependencies:     deps,
	}
	s, err := m.OpenService(name)
	if err == nil {
		old, err := s.Config()
		if err == nil {
			old.BinaryPathName = syscall.EscapeArg(exe) + " " + arg
			old.DisplayName, old.Description, old.StartType = cfg.DisplayName, cfg.Description, cfg.StartType
			old.ServiceStartName, old.SidType, old.Dependencies = account, cfg.SidType, deps
			err = s.UpdateConfig(old)
		}
		if err != nil {
			s.Close()
			return err
		}
	} else {
		if s, err = m.CreateService(name, exe, cfg, arg); err != nil {
			return err
		}
	}
	defer s.Close()
	actions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 2 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
	}
	return s.SetRecoveryActions(actions, 86400)
}

func deleteService(m *mgr.Mgr, name string) {
	s, err := m.OpenService(name)
	if err != nil {
		return
	}
	defer s.Close()
	_ = s.Delete()
}

// ── files ───────────────────────────────────────────────────────────────────

func copyTree(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			out.Close()
			return err
		}
		return out.Close()
	})
}

func installFiles(source string) error {
	target := programFilesDir()
	if samePath(source, target) {
		return nil
	}
	if _, err := os.Stat(filepath.Join(source, "chameleon-svc.exe")); err != nil {
		return errors.New("the release folder is incomplete")
	}
	old := ""
	if _, err := os.Stat(target); err == nil {
		old = target + ".old-" + strconv.FormatInt(time.Now().Unix(), 10)
		var renameErr error
		for i := 0; i < 20; i++ { // files may stay locked for a moment after stopping
			if renameErr = os.Rename(target, old); renameErr == nil {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		if renameErr != nil {
			return fmt.Errorf("replace %s: %w", target, renameErr)
		}
	}
	if err := copyTree(source, target); err != nil {
		_ = os.RemoveAll(target)
		if old != "" {
			_ = os.Rename(old, target)
		}
		return err
	}
	if old != "" {
		_ = os.RemoveAll(old)
	}
	return nil
}

func netsh(args ...string) error {
	cmd := exec.Command("netsh", append([]string{"advfirewall", "firewall"}, args...)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run()
}

func installFirewallRule() error {
	_ = netsh("delete", "rule", "name="+firewallRuleName)
	return netsh("add", "rule", "name="+firewallRuleName, "dir=in", "action=allow", "protocol=TCP",
		"localport="+strconv.Itoa(panelPort), "remoteip=localsubnet", "profile=any",
		"program="+filepath.Join(programFilesDir(), "python", "python.exe"))
}

// ── commands ────────────────────────────────────────────────────────────────

func runInstall(source string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("administrator rights are required: %w", err)
	}
	defer m.Disconnect()

	fmt.Println("Installing Chameleon...")
	stopService(m, panelServiceName)
	stopService(m, tunnelServiceName)
	if err := installFiles(source); err != nil {
		return err
	}
	if err := ensureService(m, tunnelServiceName, "Chameleon",
		"Chameleon tunnel: routes all internet traffic of this computer through your server.",
		"LocalSystem", []string{"BFE", "nsi"}, "service"); err != nil {
		return fmt.Errorf("tunnel service: %w", err)
	}
	if err := ensureService(m, panelServiceName, "Chameleon Panel",
		"Chameleon web panel, reachable from this computer and the local network only.",
		panelAccount, nil, "panel"); err != nil {
		return fmt.Errorf("panel service: %w", err)
	}
	panelSID, _, _, err := windows.LookupSID("", panelAccount)
	if err != nil {
		return fmt.Errorf("panel account: %w", err)
	}
	if err := prepareDataDirs(panelSID); err != nil {
		return err
	}
	if err := ensurePanelCertificate(); err != nil {
		return fmt.Errorf("panel certificate: %w", err)
	}
	if err := installFirewallRule(); err != nil {
		return fmt.Errorf("Windows Firewall rule: %w", err)
	}
	if err := startService(m, tunnelServiceName); err != nil {
		return fmt.Errorf("start tunnel service: %w", err)
	}
	if err := startService(m, panelServiceName); err != nil {
		return fmt.Errorf("start panel service: %w", err)
	}
	return nil
}

// disableInPanelSettings marks the tunnel as disabled in the panel's settings
// (stealth_meta.json), keeping every other field.
func disableInPanelSettings() error {
	path := filepath.Join(panelDataDir(), "stealth_meta.json")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	var meta map[string]any
	if err := json.Unmarshal(data, &meta); err != nil {
		return err
	}
	if enabled, _ := meta["enabled"].(bool); !enabled {
		return nil
	}
	meta["enabled"] = false
	out, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// runRecover gives this computer its direct internet back without the panel:
// it disables the tunnel and removes the kill switch.
func runRecover() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("administrator rights are required: %w", err)
	}
	defer m.Disconnect()
	stopService(m, tunnelServiceName)
	p := readPolicy()
	p.Enabled = false
	_ = writePolicy(p)
	// The panel re-enables an enabled tunnel within 30 s: record the choice
	// in its settings too, as its own Disable does.
	if err := disableInPanelSettings(); err != nil {
		return fmt.Errorf("panel settings: %w", err)
	}
	if err := winfw.Remove(); err != nil {
		return err
	}
	if stale, err := wintun.OpenAdapter(adapterName); err == nil {
		_ = stale.Close()
	}
	flushDNSCache()
	return startService(m, tunnelServiceName)
}

func runUninstall(purge bool) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("administrator rights are required: %w", err)
	}
	defer m.Disconnect()
	stopService(m, panelServiceName)
	stopService(m, tunnelServiceName)
	_ = winfw.Remove()
	if stale, err := wintun.OpenAdapter(adapterName); err == nil {
		_ = stale.Close()
	}
	deleteService(m, panelServiceName)
	deleteService(m, tunnelServiceName)
	_ = netsh("delete", "rule", "name="+firewallRuleName)
	flushDNSCache()
	targets := []string{programFilesDir()}
	if purge {
		targets = append(targets, dataRoot())
	}
	// This executable may be one of the files: remove them after it exits.
	script := "ping -n 3 127.0.0.1 >nul"
	for _, t := range targets {
		script += ` & rmdir /s /q "` + t + `"`
	}
	// The command line is set verbatim: Go's default quoting turns the inner
	// quotes into \" which cmd.exe rejects, so rmdir would silently do nothing.
	cmd := exec.Command("cmd.exe")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CmdLine:       `/c "` + script + `"`,
		HideWindow:    true,
		CreationFlags: windows.DETACHED_PROCESS,
	}
	return cmd.Start()
}
