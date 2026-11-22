// Copyright (c) 2026 NewNetGuard
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// The Chameleon wordmark: the icon's green-to-blue gradient.
export default function Wordmark({ className = '' }: { className?: string }) {
  return (
    <span
      className={`bg-gradient-to-r from-emerald-300 via-emerald-400 to-cyan-400 bg-clip-text font-extrabold tracking-tight text-transparent ${className}`}
    >
      Chameleon
    </span>
  )
}
