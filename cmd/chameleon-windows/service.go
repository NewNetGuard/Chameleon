// Copyright (c) 2026 NewNetGuard
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build windows

package main

import (
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

const maxLogSize = 4 << 20

// rotatingLog keeps the client log readable by the panel and bounded in size.
type rotatingLog struct {
	mu   sync.Mutex
	path string
	f    *os.File
}

func (r *rotatingLog) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
		if err != nil {
			return len(p), nil
		}
		r.f = f
	}
	if info, err := r.f.Stat(); err == nil && info.Size() > maxLogSize {
		_ = r.f.Close()
		_ = os.Rename(r.path, r.path+".1")
		f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
		if err != nil {
			r.f = nil
			return len(p), nil
		}
		r.f = f
	}
	return r.f.Write(p)
}

// ── tunnel service (LocalSystem) ────────────────────────────────────────────

type tunnelService struct{}

func (tunnelService) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	_ = os.MkdirAll(logDir(), 0o750)
	_ = os.MkdirAll(clientDir(), 0o700)
	log.SetOutput(&rotatingLog{path: clientLogFile()})
	log.SetFlags(log.LstdFlags)

	m := newManager()
	stop := make(chan struct{})
	controlDone := make(chan struct{})
	go func() {
		defer close(controlDone)
		if err := serveControl(m, stop); err != nil {
			log.Printf("[service] control pipe failed: %v", err)
		}
	}()
	go m.resume()

	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for req := range requests {
		switch req.Cmd {
		case svc.Interrogate:
			status <- req.CurrentStatus
		case svc.Stop, svc.Shutdown:
			status <- svc.Status{State: svc.StopPending}
			close(stop)
			m.shutdown()
			select {
			case <-controlDone:
			case <-time.After(3 * time.Second):
			}
			return false, 0
		}
	}
	return false, 0
}

// ── panel service (NT SERVICE\ChameleonPanel) ───────────────────────────────

type panelService struct{}

func panelEnv() []string {
	root := installDir()
	env := []string{
		"SystemRoot=" + os.Getenv("SystemRoot"),
		"TEMP=" + filepath.Join(panelDataDir(), "tmp"),
		"TMP=" + filepath.Join(panelDataDir(), "tmp"),
		"PYTHONDONTWRITEBYTECODE=1",
		"PYTHONUTF8=1",
		"CHAMELEON_PANEL_ROOT=" + root,
		"CHAMELEON_PANEL_DATA=" + panelDataDir(),
		"CHAMELEON_PANEL_RUNNER=" + filepath.Join(root, "chameleon-svc.exe"),
		"CHAMELEON_CLIENT_LOG=" + clientLogFile(),
		"CHAMELEON_PANEL_TLS_CERT=" + panelCertFile(),
		"CHAMELEON_PANEL_TLS_KEY=" + panelKeyFile(),
		"CHAMELEON_PANEL_PORT=" + strconv.Itoa(panelPort),
	}
	return env
}

// killOnCloseJob ends the panel's Python together with the service.
func killOnCloseJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		_ = windows.CloseHandle(job)
		return 0, err
	}
	return job, nil
}

func (panelService) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	_ = os.MkdirAll(filepath.Join(panelDataDir(), "tmp"), 0o700)
	job, err := killOnCloseJob()
	if err != nil {
		return true, 1
	}
	defer windows.CloseHandle(job)

	stop := make(chan struct{})
	var current *exec.Cmd
	var mu sync.Mutex
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			logFile, _ := os.OpenFile(panelLogFile(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
			cmd := exec.Command(pythonExe(), "-m", "chameleon_panel", "serve")
			cmd.Dir = installDir()
			cmd.Env = panelEnv()
			if logFile != nil {
				cmd.Stdout, cmd.Stderr = logFile, logFile
			} else {
				cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
			}
			if err := cmd.Start(); err == nil {
				if h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid)); err == nil {
					_ = windows.AssignProcessToJobObject(job, h)
					_ = windows.CloseHandle(h)
				}
				mu.Lock()
				current = cmd
				mu.Unlock()
				_ = cmd.Wait()
			}
			if logFile != nil {
				_ = logFile.Close()
			}
			select {
			case <-stop:
				return
			case <-time.After(3 * time.Second):
			}
		}
	}()

	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for req := range requests {
		switch req.Cmd {
		case svc.Interrogate:
			status <- req.CurrentStatus
		case svc.Stop, svc.Shutdown:
			status <- svc.Status{State: svc.StopPending}
			close(stop)
			mu.Lock()
			if current != nil && current.Process != nil {
				_ = current.Process.Kill()
			}
			mu.Unlock()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
			}
			return false, 0
		}
	}
	return false, 0
}
