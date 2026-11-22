//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package winfw

import (
	"runtime"
	"unsafe"
)

// Known addresses.

func permitTunInterface(session uintptr, baseObjects *baseObjects, weight uint8, ifLUID uint64) error {
	ifaceCondition := wtFwpmFilterCondition0{
		fieldKey:  cFWPM_CONDITION_IP_LOCAL_INTERFACE,
		matchType: cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{
			_type: cFWP_UINT64,
			value: (uintptr)(unsafe.Pointer(&ifLUID)),
		},
	}

	filter := wtFwpmFilter0{
		providerKey:         &baseObjects.provider,
		subLayerKey:         baseObjects.filters,
		weight:              filterWeight(weight),
		numFilterConditions: 1,
		filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&ifaceCondition)),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_PERMIT,
		},
	}

	filterID := uint64(0)

	//
	// #1 Permit outbound IPv4 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit outbound IPv4 traffic on TUN", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Permit inbound IPv4 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit inbound IPv4 traffic on TUN", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #3 Permit outbound IPv6 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit outbound IPv6 traffic on TUN", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #4 Permit inbound IPv6 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit inbound IPv6 traffic on TUN", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	runtime.KeepAlive(ifLUID)
	return nil
}

func permitWireGuardService(session uintptr, baseObjects *baseObjects, weight uint8) error {
	var conditions [2]wtFwpmFilterCondition0

	//
	// First condition is the exe path of the current process.
	//
	appID, err := getCurrentProcessAppID()
	if err != nil {
		return wrapErr(err)
	}
	defer fwpmFreeMemory0(unsafe.Pointer(&appID))

	conditions[0] = wtFwpmFilterCondition0{
		fieldKey:  cFWPM_CONDITION_ALE_APP_ID,
		matchType: cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{
			_type: cFWP_BYTE_BLOB_TYPE,
			value: uintptr(unsafe.Pointer(appID)),
		},
	}

	//
	// Second condition is the SECURITY_DESCRIPTOR of the current process.
	// This prevents other processes hosted in the same exe from matching this filter.
	//
	sd, err := getCurrentProcessSecurityDescriptor()
	if err != nil {
		return wrapErr(err)
	}

	sdBlob := wtFwpByteBlob{sd.Length(), (*byte)(unsafe.Pointer(sd))}
	conditions[1] = wtFwpmFilterCondition0{
		fieldKey:  cFWPM_CONDITION_ALE_USER_ID,
		matchType: cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{
			_type: cFWP_SECURITY_DESCRIPTOR_TYPE,
			value: uintptr(unsafe.Pointer(&sdBlob)),
		},
	}

	//
	// Assemble the filter.
	//
	filter := wtFwpmFilter0{
		providerKey:         &baseObjects.provider,
		subLayerKey:         baseObjects.filters,
		weight:              filterWeight(weight),
		flags:               cFWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
		numFilterConditions: uint32(len(conditions)),
		filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&conditions)),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_PERMIT,
		},
	}

	filterID := uint64(0)

	//
	// #1 Permit outbound IPv4 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit unrestricted outbound traffic for WireGuard service (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Permit inbound IPv4 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit unrestricted inbound traffic for WireGuard service (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #3 Permit outbound IPv6 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit unrestricted outbound traffic for WireGuard service (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #4 Permit inbound IPv6 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit unrestricted inbound traffic for WireGuard service (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	runtime.KeepAlive(sdBlob)
	runtime.KeepAlive(sd)
	return nil
}

func permitLoopback(session uintptr, baseObjects *baseObjects, weight uint8) error {
	condition := wtFwpmFilterCondition0{
		fieldKey:  cFWPM_CONDITION_FLAGS,
		matchType: cFWP_MATCH_FLAGS_ALL_SET,
		conditionValue: wtFwpConditionValue0{
			_type: cFWP_UINT32,
			value: uintptr(cFWP_CONDITION_FLAG_IS_LOOPBACK),
		},
	}

	filter := wtFwpmFilter0{
		providerKey:         &baseObjects.provider,
		subLayerKey:         baseObjects.filters,
		weight:              filterWeight(weight),
		numFilterConditions: 1,
		filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&condition)),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_PERMIT,
		},
	}

	filterID := uint64(0)

	//
	// #1 Permit outbound IPv4 on loopback.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit outbound on loopback (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Permit inbound IPv4 on loopback.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit inbound on loopback (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #3 Permit outbound IPv6 on loopback.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit outbound on loopback (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #4 Permit inbound IPv6 on loopback.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit inbound on loopback (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	return nil
}

func permitDHCPIPv4(session uintptr, baseObjects *baseObjects, weight uint8) error {
	//
	// #1 Outbound DHCP request on IPv4.
	//
	{
		var conditions [4]wtFwpmFilterCondition0

		conditions[0].fieldKey = cFWPM_CONDITION_IP_PROTOCOL
		conditions[0].matchType = cFWP_MATCH_EQUAL
		conditions[0].conditionValue._type = cFWP_UINT8
		conditions[0].conditionValue.value = uintptr(cIPPROTO_UDP)

		conditions[1].fieldKey = cFWPM_CONDITION_IP_LOCAL_PORT
		conditions[1].matchType = cFWP_MATCH_EQUAL
		conditions[1].conditionValue._type = cFWP_UINT16
		conditions[1].conditionValue.value = uintptr(68)

		conditions[2].fieldKey = cFWPM_CONDITION_IP_REMOTE_PORT
		conditions[2].matchType = cFWP_MATCH_EQUAL
		conditions[2].conditionValue._type = cFWP_UINT16
		conditions[2].conditionValue.value = uintptr(67)

		conditions[3].fieldKey = cFWPM_CONDITION_IP_REMOTE_ADDRESS
		conditions[3].matchType = cFWP_MATCH_EQUAL
		conditions[3].conditionValue._type = cFWP_UINT32
		conditions[3].conditionValue.value = uintptr(0xffffffff)

		displayData, err := createWtFwpmDisplayData0("Permit outbound DHCP request (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter := wtFwpmFilter0{
			displayData:         *displayData,
			providerKey:         &baseObjects.provider,
			layerKey:            cFWPM_LAYER_ALE_AUTH_CONNECT_V4,
			subLayerKey:         baseObjects.filters,
			weight:              filterWeight(weight),
			numFilterConditions: uint32(len(conditions)),
			filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&conditions)),
			action: wtFwpmAction0{
				_type: cFWP_ACTION_PERMIT,
			},
		}

		filterID := uint64(0)

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Inbound DHCP response on IPv4.
	//
	{
		var conditions [3]wtFwpmFilterCondition0

		conditions[0].fieldKey = cFWPM_CONDITION_IP_PROTOCOL
		conditions[0].matchType = cFWP_MATCH_EQUAL
		conditions[0].conditionValue._type = cFWP_UINT8
		conditions[0].conditionValue.value = uintptr(cIPPROTO_UDP)

		conditions[1].fieldKey = cFWPM_CONDITION_IP_LOCAL_PORT
		conditions[1].matchType = cFWP_MATCH_EQUAL
		conditions[1].conditionValue._type = cFWP_UINT16
		conditions[1].conditionValue.value = uintptr(68)

		conditions[2].fieldKey = cFWPM_CONDITION_IP_REMOTE_PORT
		conditions[2].matchType = cFWP_MATCH_EQUAL
		conditions[2].conditionValue._type = cFWP_UINT16
		conditions[2].conditionValue.value = uintptr(67)

		displayData, err := createWtFwpmDisplayData0("Permit inbound DHCP response (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter := wtFwpmFilter0{
			displayData:         *displayData,
			providerKey:         &baseObjects.provider,
			layerKey:            cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
			subLayerKey:         baseObjects.filters,
			weight:              filterWeight(weight),
			numFilterConditions: uint32(len(conditions)),
			filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&conditions)),
			action: wtFwpmAction0{
				_type: cFWP_ACTION_PERMIT,
			},
		}

		filterID := uint64(0)

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	return nil
}

// Block all traffic except what is explicitly permitted by other rules.
func blockAll(session uintptr, baseObjects *baseObjects, weight uint8) error {
	filter := wtFwpmFilter0{
		providerKey: &baseObjects.provider,
		subLayerKey: baseObjects.filters,
		weight:      filterWeight(weight),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_BLOCK,
		},
	}

	filterID := uint64(0)

	//
	// #1 Block outbound traffic on IPv4.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Block all outbound (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Block inbound traffic on IPv4.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Block all inbound (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #3 Block outbound traffic on IPv6.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Block all outbound (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #4 Block inbound traffic on IPv6.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Block all inbound (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	return nil
}
