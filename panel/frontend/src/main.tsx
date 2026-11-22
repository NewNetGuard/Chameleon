// Copyright (c) 2026 NewNetGuard
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Toaster } from 'react-hot-toast'
import App from './App'
import './index.css'

// The panel talks only to its own backend on this machine or the local
// network, never to the internet. Chameleon itself switches the network (kill
// switch, reconnects), which makes browsers report "offline"; with the default
// networkMode TanStack Query would then pause every request and button until
// a page reload. Always send requests: a real failure still surfaces as an error.
const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: 1, refetchOnWindowFocus: false, networkMode: 'always' },
    mutations: { networkMode: 'always' },
  },
})

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <App />
        <Toaster position="top-right" toastOptions={{ style: { background: '#1f2937', color: '#f3f4f6' } }} />
      </BrowserRouter>
    </QueryClientProvider>
  </React.StrictMode>,
)
