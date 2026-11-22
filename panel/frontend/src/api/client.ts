// Copyright (c) 2026 NewNetGuard
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import axios from 'axios'

// The session cookie is HttpOnly. Mutating requests also carry the session's
// CSRF token, which the panel hands out at sign-in and on page load.
let csrfToken = ''

export const setCsrfToken = (token: string) => {
  csrfToken = token
}

const api = axios.create({
  baseURL: '/api',
  withCredentials: true,
  timeout: 30_000,
})

api.interceptors.request.use((config) => {
  const method = (config.method || 'get').toLowerCase()
  if (!['get', 'head', 'options'].includes(method) && csrfToken) {
    config.headers.set('X-Chameleon-CSRF', csrfToken)
  }
  return config
})

api.interceptors.response.use(
  (response) => response,
  (error) => {
    // An expired or revoked session returns to the sign-in screen.
    if (error?.response?.status === 401 && !String(error?.config?.url || '').startsWith('/auth/')) {
      window.location.reload()
    }
    return Promise.reject(error)
  },
)

export interface SessionState {
  authenticated: boolean
  csrf?: string
  password_set?: boolean
  // The browser runs on the computer Chameleon runs on.
  same_machine?: boolean
}

export const getSession = async (): Promise<SessionState> => {
  const { data } = await api.get('/auth/session'); return data
}
export const login = async (password: string): Promise<SessionState> => {
  const { data } = await api.post('/auth/login', { password }); return data
}
export const setupPassword = async (code: string, password: string): Promise<SessionState> => {
  const { data } = await api.post('/auth/setup', { code, password }); return data
}
// Only works on the computer Chameleon runs on.
export const resetPassword = async (): Promise<SessionState> => {
  const { data } = await api.post('/auth/reset', {}); return data
}
export const logout = async (): Promise<SessionState> => {
  const { data } = await api.post('/auth/logout'); return data
}

export default api
