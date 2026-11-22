// Copyright (c) 2026 NewNetGuard
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build windows

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/ipc/namedpipe"
)

// The panel reaches the privileged service through one named pipe, the way it
// reaches chameleon-runner through sudo on Linux: the same tool names, actions
// and JSON answers. Only SYSTEM, Administrators and the panel's own service
// account may open the pipe.

type controlRequest struct {
	Tool  string   `json:"tool"`
	Args  []string `json:"args"`
	Stdin string   `json:"stdin,omitempty"`
}

type controlResponse struct {
	Code   int    `json:"code"`
	Stdout string `json:"stdout"`
}

const maxControlRequest = 256 * 1024

func controlSecurityDescriptor() (*windows.SECURITY_DESCRIPTOR, error) {
	sddl := "O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)"
	if sid, _, _, err := windows.LookupSID("", panelAccount); err == nil {
		sddl += "(A;;GRGW;;;" + sid.String() + ")"
	}
	return windows.SecurityDescriptorFromString(sddl)
}

func serveControl(m *manager, stop <-chan struct{}) error {
	sd, err := controlSecurityDescriptor()
	if err != nil {
		return err
	}
	listener, err := (&namedpipe.ListenConfig{SecurityDescriptor: sd}).Listen(controlPipe)
	if err != nil {
		return err
	}
	go func() {
		<-stop
		_ = listener.Close()
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-stop:
				return nil
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			continue
		}
		go handleControl(m, conn)
	}
}

func handleControl(m *manager, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))
	line, err := bufio.NewReader(io.LimitReader(conn, maxControlRequest)).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return
	}
	var req controlRequest
	resp := controlResponse{Code: 2}
	if json.Unmarshal(line, &req) != nil {
		resp.Stdout = `{"success":false,"error":"bad request"}`
	} else {
		resp = dispatch(m, req)
	}
	data, _ := json.Marshal(resp)
	_, _ = conn.Write(append(data, '\n'))
}

func jsonOut(v map[string]any) controlResponse {
	data, _ := json.Marshal(v)
	return controlResponse{Code: 0, Stdout: string(data)}
}

func dispatch(m *manager, req controlRequest) controlResponse {
	arg := func(i int) string {
		if i < len(req.Args) {
			return req.Args[i]
		}
		return ""
	}
	switch req.Tool {
	case "chameleon-netctl":
		switch arg(0) {
		case "up":
			block := arg(2) != "0" && arg(2) != "false"
			return jsonOut(m.up(arg(1), block))
		case "down":
			return jsonOut(m.down())
		case "status", "":
			return jsonOut(m.status())
		case "guard", "resume":
			go m.resume()
			return jsonOut(map[string]any{"success": true})
		}
		return jsonOut(errorResult(errors.New("unknown subcommand")))
	case "chameleon-secrets":
		out, err := secretCommand(arg(0), arg(1), req.Stdin)
		if err != nil {
			return controlResponse{Code: 1, Stdout: ""}
		}
		return controlResponse{Code: 0, Stdout: out}
	}
	return controlResponse{Code: 2, Stdout: `{"success":false,"error":"unknown tool"}`}
}

// runCtl is the panel's side: `chameleon-svc ctl <tool> <args...>`. Secret
// values arrive on stdin, never in the command line.
func runCtl(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: ctl <tool> [args...]")
		return 2
	}
	req := controlRequest{Tool: args[0], Args: args[1:]}
	if req.Tool == "chameleon-secrets" && len(req.Args) > 0 && req.Args[0] == "store" {
		data, err := io.ReadAll(io.LimitReader(os.Stdin, 64*1024))
		if err != nil {
			return 1
		}
		req.Stdin = string(data)
	}
	conn, err := namedpipe.DialTimeout(controlPipe, 10*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stdout, `{"success":false,"error":"the Chameleon service is not running"}`)
		return 1
	}
	defer conn.Close()
	data, _ := json.Marshal(req)
	if _, err := conn.Write(append(data, '\n')); err != nil {
		return 1
	}
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return 1
	}
	var resp controlResponse
	if json.Unmarshal(line, &resp) != nil {
		return 1
	}
	if resp.Stdout != "" {
		fmt.Fprint(os.Stdout, strings.TrimRight(resp.Stdout, "\n")+"\n")
	}
	return resp.Code
}
