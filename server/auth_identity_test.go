// Copyright (c) 2026 NewNetGuard
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthRejectsCallerSelectedClientIdentity(t *testing.T) {
	manager, session, _ := newTestCryptoPair(t, []byte("test-installation-secret"))
	nextCalled := false
	handler := SessionAuthMiddleware(manager, func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	})

	request := httptest.NewRequest(http.MethodGet, "https://example.test/poll", nil)
	request.Header.Set("Authorization", GenerateSessionAuthHeader(
		session.authKey,
		session.id,
		"00112233445566778899aabbccddeeff",
		"attacker-chosen-id",
		request.Method,
		requestPath(request),
	))
	response := httptest.NewRecorder()
	handler(response, request)

	if response.Code != http.StatusUnauthorized || nextCalled {
		t.Fatalf("caller-selected identity was accepted: status=%d called=%v", response.Code, nextCalled)
	}
}

func TestAuthAcceptsActiveSessionIdentity(t *testing.T) {
	manager, session, _ := newTestCryptoPair(t, []byte("test-installation-secret"))
	nextCalled := false
	handler := SessionAuthMiddleware(manager, func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	})

	request := httptest.NewRequest(http.MethodGet, "https://example.test/poll", nil)
	request.Header.Set("Authorization", GenerateSessionAuthHeader(
		session.authKey,
		session.id,
		"ffeeddccbbaa99887766554433221100",
		session.clientID,
		request.Method,
		requestPath(request),
	))
	response := httptest.NewRecorder()
	handler(response, request)

	if response.Code != http.StatusNoContent || !nextCalled {
		t.Fatalf("active session identity was rejected: status=%d called=%v", response.Code, nextCalled)
	}
}
