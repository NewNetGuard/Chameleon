// Copyright (c) 2026 NewNetGuard
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build windows

// Chameleon's Windows kill switch, built on the WireGuard for Windows WFP
// bindings in this package (MIT, see LICENSE.WireGuard).
//
// Unlike WireGuard's dynamic session, every object here is persistent: the
// filters stay in force while the Chameleon service is stopped, restarting or
// crashed, and across reboots, until Remove is called. Every object has a fixed
// key, so Apply replaces the whole policy in one transaction and Remove finds
// everything a previous process installed.

package winfw

import (
	"errors"
	"net/netip"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	providerKey = windows.GUID{Data1: 0x6c3d0a51, Data2: 0x8b2e, Data3: 0x4f0c, Data4: [8]byte{0x9a, 0x3e, 0x51, 0x7c, 0x48, 0x0d, 0x21, 0x01}}
	sublayerKey = windows.GUID{Data1: 0x6c3d0a51, Data2: 0x8b2e, Data3: 0x4f0c, Data4: [8]byte{0x9a, 0x3e, 0x51, 0x7c, 0x48, 0x0d, 0x21, 0x02}}
	// Filter keys: this base with the filter's index in Data1.
	filterKeyBase = windows.GUID{Data1: 0, Data2: 0x8b2f, Data3: 0x4f0c, Data4: [8]byte{0x9a, 0x3e, 0x51, 0x7c, 0x48, 0x0d, 0x21, 0x03}}
)

const (
	maxFilters = 256

	fwpEFilterNotFound   = 0x80320003
	fwpEProviderNotFound = 0x80320005
	fwpESublayerNotFound = 0x80320007

	providerFlagPersistent = 0x00000001
)

var (
	procFwpmFilterDeleteByKey0   = modfwpuclnt.NewProc("FwpmFilterDeleteByKey0")
	procFwpmSubLayerDeleteByKey0 = modfwpuclnt.NewProc("FwpmSubLayerDeleteByKey0")
	procFwpmProviderDeleteByKey0 = modfwpuclnt.NewProc("FwpmProviderDeleteByKey0")
	procFwpmProviderGetByKey0    = modfwpuclnt.NewProc("FwpmProviderGetByKey0")
)

type wfpObjectInstaller func(uintptr) error

// baseObjects are the provider and sublayer every filter belongs to.
type baseObjects struct {
	provider windows.GUID
	filters  windows.GUID
}

// mu serializes transactions; nextFilter numbers the filters of the running one.
var (
	mu         sync.Mutex
	nextFilter uint32
)

func filterKey(index uint32) windows.GUID {
	key := filterKeyBase
	key.Data1 = index
	return key
}

// fwpmFilterAdd0 is what the copied WireGuard rules call: every filter gets the
// next fixed key and is made persistent.
func fwpmFilterAdd0(engineHandle uintptr, filter *wtFwpmFilter0, sd uintptr, id *uint64) error {
	if nextFilter >= maxFilters {
		return errors.New("too many firewall filters")
	}
	filter.filterKey = filterKey(nextFilter)
	nextFilter++
	filter.flags |= cFWPM_FILTER_FLAG_PERSISTENT
	return fwpmFilterAddRaw(engineHandle, filter, sd, id)
}

func callStatus(proc *windows.LazyProc, args ...uintptr) syscall.Errno {
	r1, _, _ := syscall.SyscallN(proc.Addr(), args...)
	return syscall.Errno(r1)
}

func openSession() (uintptr, error) {
	displayData, err := createWtFwpmDisplayData0("Chameleon", "Chameleon kill switch")
	if err != nil {
		return 0, err
	}
	session := wtFwpmSession0{
		displayData:          *displayData,
		txnWaitTimeoutInMSec: windows.INFINITE,
	}
	handle := uintptr(0)
	if err := fwpmEngineOpen0(nil, cRPC_C_AUTHN_WINNT, nil, &session, unsafe.Pointer(&handle)); err != nil {
		return 0, wrapErr(err)
	}
	return handle, nil
}

func removeObjects(session uintptr) error {
	for i := uint32(0); i < maxFilters; i++ {
		key := filterKey(i)
		if st := callStatus(procFwpmFilterDeleteByKey0, session, uintptr(unsafe.Pointer(&key))); st != 0 && st != fwpEFilterNotFound {
			return wrapErr(st)
		}
	}
	if st := callStatus(procFwpmSubLayerDeleteByKey0, session, uintptr(unsafe.Pointer(&sublayerKey))); st != 0 && st != fwpESublayerNotFound {
		return wrapErr(st)
	}
	if st := callStatus(procFwpmProviderDeleteByKey0, session, uintptr(unsafe.Pointer(&providerKey))); st != 0 && st != fwpEProviderNotFound {
		return wrapErr(st)
	}
	return nil
}

func registerPersistentBase(session uintptr) (*baseObjects, error) {
	bo := &baseObjects{provider: providerKey, filters: sublayerKey}
	displayData, err := createWtFwpmDisplayData0("Chameleon", "Chameleon kill switch provider")
	if err != nil {
		return nil, err
	}
	provider := wtFwpmProvider0{providerKey: bo.provider, displayData: *displayData, flags: providerFlagPersistent}
	if err := fwpmProviderAdd0(session, &provider, 0); err != nil {
		return nil, wrapErr(err)
	}
	displayData, err = createWtFwpmDisplayData0("Chameleon filters", "Permissive and blocking filters")
	if err != nil {
		return nil, err
	}
	sublayer := wtFwpmSublayer0{
		subLayerKey: bo.filters,
		displayData: *displayData,
		flags:       cFWPM_SUBLAYER_FLAG_PERSISTENT,
		providerKey: &bo.provider,
		weight:      ^uint16(0),
	}
	if err := fwpmSubLayerAdd0(session, &sublayer, 0); err != nil {
		return nil, wrapErr(err)
	}
	return bo, nil
}

// Policy is the complete kill switch of this computer.
type Policy struct {
	// TunnelLUID is the Chameleon adapter; 0 while it does not exist, which
	// blocks every internet connection.
	TunnelLUID uint64
	BlockQUIC  bool
	// PanelUser and Server let the panel reach its server directly (SSH,
	// deployment) while the tunnel is down.
	PanelUser *windows.SID
	Server    netip.Addr
}

// Apply replaces the installed policy atomically. It must run inside the
// Chameleon service: the service's own permit is bound to its service SID.
func Apply(p Policy) error {
	mu.Lock()
	defer mu.Unlock()
	session, err := openSession()
	if err != nil {
		return err
	}
	defer fwpmEngineClose0(session)
	return runTransaction(session, func(s uintptr) error {
		if err := removeObjects(s); err != nil {
			return err
		}
		nextFilter = 0
		bo, err := registerPersistentBase(s)
		if err != nil {
			return err
		}
		if err := permitWireGuardService(s, bo, 15); err != nil {
			return err
		}
		if p.PanelUser != nil && p.Server.Is4() {
			if err := permitUserToAddress(s, bo, 15, p.PanelUser, p.Server); err != nil {
				return err
			}
		}
		if p.TunnelLUID != 0 {
			if err := permitDNSOnInterface(s, bo, 15, p.TunnelLUID); err != nil {
				return err
			}
		}
		if err := blockAllDNS(s, bo, 14); err != nil {
			return err
		}
		if err := permitLoopback(s, bo, 13); err != nil {
			return err
		}
		if p.BlockQUIC {
			if err := blockQUIC(s, bo, 12); err != nil {
				return err
			}
		}
		if p.TunnelLUID != 0 {
			if err := permitTunInterface(s, bo, 11, p.TunnelLUID); err != nil {
				return err
			}
		}
		if err := permitLocalNetwork(s, bo, 11); err != nil {
			return err
		}
		if err := permitDHCPIPv4(s, bo, 11); err != nil {
			return err
		}
		// No IPv6 permit beyond loopback: the tunnel carries IPv4 only, so
		// IPv6 stays closed, in the local network too.
		return blockAll(s, bo, 0)
	})
}

// Remove deletes the whole policy; the computer reaches the internet directly
// again. Safe to call when nothing is installed.
func Remove() error {
	mu.Lock()
	defer mu.Unlock()
	session, err := openSession()
	if err != nil {
		return err
	}
	defer fwpmEngineClose0(session)
	return runTransaction(session, removeObjects)
}

// Active reports whether the kill switch is installed.
func Active() bool {
	session, err := openSession()
	if err != nil {
		return false
	}
	defer fwpmEngineClose0(session)
	var provider unsafe.Pointer
	if st := callStatus(procFwpmProviderGetByKey0, session, uintptr(unsafe.Pointer(&providerKey)), uintptr(unsafe.Pointer(&provider))); st != 0 {
		return false
	}
	fwpmFreeMemory0(unsafe.Pointer(&provider))
	return true
}

var (
	connectLayers = []windows.GUID{cFWPM_LAYER_ALE_AUTH_CONNECT_V4, cFWPM_LAYER_ALE_AUTH_CONNECT_V6}
)

func addFilters(session uintptr, bo *baseObjects, name string, layers []windows.GUID, weight uint8, action wtFwpActionType, conditions []wtFwpmFilterCondition0) error {
	displayData, err := createWtFwpmDisplayData0(name, "")
	if err != nil {
		return err
	}
	filter := wtFwpmFilter0{
		displayData:         *displayData,
		providerKey:         &bo.provider,
		subLayerKey:         bo.filters,
		weight:              filterWeight(weight),
		numFilterConditions: uint32(len(conditions)),
		action:              wtFwpmAction0{_type: action},
	}
	if len(conditions) > 0 {
		filter.filterCondition = &conditions[0]
	}
	for _, layer := range layers {
		filter.layerKey = layer
		id := uint64(0)
		if err := fwpmFilterAdd0(session, &filter, 0, &id); err != nil {
			return wrapErr(err)
		}
	}
	return nil
}

func uint8Condition(field windows.GUID, value uint8) wtFwpmFilterCondition0 {
	return wtFwpmFilterCondition0{fieldKey: field, matchType: cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{_type: cFWP_UINT8, value: uintptr(value)}}
}

func uint16Condition(field windows.GUID, value uint16) wtFwpmFilterCondition0 {
	return wtFwpmFilterCondition0{fieldKey: field, matchType: cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{_type: cFWP_UINT16, value: uintptr(value)}}
}

func dnsConditions() []wtFwpmFilterCondition0 {
	return []wtFwpmFilterCondition0{
		uint16Condition(cFWPM_CONDITION_IP_REMOTE_PORT, 53),
		uint8Condition(cFWPM_CONDITION_IP_PROTOCOL, uint8(cIPPROTO_UDP)),
		// The same field again is a logical OR.
		uint8Condition(cFWPM_CONDITION_IP_PROTOCOL, uint8(cIPPROTO_TCP)),
	}
}

// blockAllDNS: no DNS query leaves except through the tunnel, not even to a
// resolver in the local network.
func blockAllDNS(session uintptr, bo *baseObjects, weight uint8) error {
	return addFilters(session, bo, "Block DNS outside the Chameleon tunnel", connectLayers, weight, cFWP_ACTION_BLOCK, dnsConditions())
}

func permitDNSOnInterface(session uintptr, bo *baseObjects, weight uint8, luid uint64) error {
	conditions := append(dnsConditions(), wtFwpmFilterCondition0{
		fieldKey:       cFWPM_CONDITION_IP_LOCAL_INTERFACE,
		matchType:      cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{_type: cFWP_UINT64, value: uintptr(unsafe.Pointer(&luid))},
	})
	err := addFilters(session, bo, "Permit DNS through the Chameleon tunnel", connectLayers, weight, cFWP_ACTION_PERMIT, conditions)
	runtime.KeepAlive(&luid)
	return err
}

// blockQUIC: browsers fall back from QUIC (UDP 443) to TCP.
func blockQUIC(session uintptr, bo *baseObjects, weight uint8) error {
	conditions := []wtFwpmFilterCondition0{
		uint8Condition(cFWPM_CONDITION_IP_PROTOCOL, uint8(cIPPROTO_UDP)),
		uint16Condition(cFWPM_CONDITION_IP_REMOTE_PORT, 443),
	}
	return addFilters(session, bo, "Block QUIC", connectLayers, weight, cFWP_ACTION_BLOCK, conditions)
}

// permitLocalNetwork keeps the local IPv4 network reachable in both
// directions: the router, printers, shares and this panel from other devices.
// The local network over IPv6 stays closed.
func permitLocalNetwork(session uintptr, bo *baseObjects, weight uint8) error {
	v4 := []wtFwpV4AddrAndMask{
		{0x0a000000, 0xff000000}, // 10.0.0.0/8
		{0xac100000, 0xfff00000}, // 172.16.0.0/12
		{0xc0a80000, 0xffff0000}, // 192.168.0.0/16
		{0xa9fe0000, 0xffff0000}, // 169.254.0.0/16
		{0xe0000000, 0xf0000000}, // 224.0.0.0/4 multicast
		{0xffffffff, 0xffffffff}, // broadcast
	}
	conditions := make([]wtFwpmFilterCondition0, len(v4))
	for i := range v4 {
		conditions[i] = wtFwpmFilterCondition0{
			fieldKey:       cFWPM_CONDITION_IP_REMOTE_ADDRESS,
			matchType:      cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{_type: cFWP_V4_ADDR_MASK, value: uintptr(unsafe.Pointer(&v4[i]))},
		}
	}
	err := addFilters(session, bo, "Permit the local network (IPv4)",
		[]windows.GUID{cFWPM_LAYER_ALE_AUTH_CONNECT_V4, cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4},
		weight, cFWP_ACTION_PERMIT, conditions)
	runtime.KeepAlive(&v4)
	return err
}

// permitUserToAddress lets one account (the panel's service account) connect
// to one IPv4 address.
func permitUserToAddress(session uintptr, bo *baseObjects, weight uint8, user *windows.SID, address netip.Addr) error {
	access := []windows.EXPLICIT_ACCESS{{
		AccessPermissions: cFWP_ACTRL_MATCH_FILTER,
		AccessMode:        windows.GRANT_ACCESS,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(user),
		},
	}}
	dacl, err := windows.ACLFromEntries(access, nil)
	if err != nil {
		return err
	}
	sd, err := windows.NewSecurityDescriptor()
	if err != nil {
		return err
	}
	if err := sd.SetDACL(dacl, true, false); err != nil {
		return err
	}
	if sd, err = sd.ToSelfRelative(); err != nil {
		return err
	}
	sdBlob := wtFwpByteBlob{sd.Length(), (*byte)(unsafe.Pointer(sd))}
	raw := address.As4()
	remote := uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3])
	conditions := []wtFwpmFilterCondition0{
		{
			fieldKey:       cFWPM_CONDITION_ALE_USER_ID,
			matchType:      cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{_type: cFWP_SECURITY_DESCRIPTOR_TYPE, value: uintptr(unsafe.Pointer(&sdBlob))},
		},
		{
			fieldKey:       cFWPM_CONDITION_IP_REMOTE_ADDRESS,
			matchType:      cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{_type: cFWP_UINT32, value: uintptr(remote)},
		},
	}
	err = addFilters(session, bo, "Permit the Chameleon panel to reach its server",
		[]windows.GUID{cFWPM_LAYER_ALE_AUTH_CONNECT_V4}, weight, cFWP_ACTION_PERMIT, conditions)
	runtime.KeepAlive(&sdBlob)
	runtime.KeepAlive(sd)
	return err
}
