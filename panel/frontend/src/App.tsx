// Copyright (c) 2026 NewNetGuard
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useEffect, useState, type FormEvent, type ReactNode } from 'react'
import { KeyRound, Loader2, LogOut, Lock } from 'lucide-react'
import { getSession, login, logout, resetPassword, setCsrfToken, setupPassword } from './api/client'
import { apiErrorMessage } from './utils/errors'
import Stealth from './pages/Stealth'

type Gate = 'loading' | 'setup' | 'signed-out' | 'signed-in'

const MIN_PASSWORD = 10

export default function App() {
  const [gate, setGate] = useState<Gate>('loading')
  const [sameMachine, setSameMachine] = useState(false)

  useEffect(() => {
    getSession()
      .then((s) => {
        if (s.authenticated && s.csrf) {
          setCsrfToken(s.csrf)
          setGate('signed-in')
        } else {
          setSameMachine(!!s.same_machine)
          setGate(s.password_set === false ? 'setup' : 'signed-out')
        }
      })
      .catch(() => setGate('signed-out'))
  }, [])

  if (gate === 'loading') {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <Loader2 className="h-6 w-6 animate-spin text-gray-400" />
      </div>
    )
  }
  if (gate === 'setup') {
    return <Setup sameMachine={sameMachine} onDone={() => setGate('signed-in')} onExists={() => setGate('signed-out')} />
  }
  if (gate === 'signed-out') {
    return <Login sameMachine={sameMachine} onSignedIn={() => setGate('signed-in')} onReset={() => setGate('setup')} />
  }
  return (
    <Stealth
      headerActions={
        <button
          type="button"
          onClick={() => logout().finally(() => window.location.reload())}
          className="inline-flex items-center gap-1.5 rounded-lg px-3 py-2.5 text-sm text-gray-400 hover:bg-white/10 hover:text-gray-200"
          title="Sign out"
        >
          <LogOut className="h-4 w-4" /> Sign out
        </button>
      }
    />
  )
}

function AuthLayout({ children }: { children: ReactNode }) {
  return (
    <div className="min-h-screen flex items-center justify-center bg-dark-950 px-4 py-10">
      <div className="pointer-events-none fixed inset-0 bg-[radial-gradient(ellipse_at_top,rgba(16,185,129,0.12),transparent_60%)]" />
      <div className="relative w-full max-w-3xl">
        <div className="flex flex-col items-center text-center">
          <h1 className="w-full">
            <img
              src="/banner.webp"
              alt="Chameleon — Adaptive Stealth Networking"
              className="w-full rounded-2xl border border-white/10 shadow-[0_0_40px_rgba(16,185,129,0.18)]"
            />
          </h1>
          <p className="mt-3 text-sm text-gray-400">Panel · local network only</p>
        </div>
        <div className="mx-auto mt-6 w-full max-w-sm rounded-2xl border border-white/10 bg-dark-900/80 p-6 shadow-xl backdrop-blur">
          {children}
        </div>
      </div>
    </div>
  )
}

function Field({ id, label, icon, ...input }: {
  id: string; label: string; icon: ReactNode
} & React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <div className="mt-4 first:mt-0">
      <label className="block text-sm text-gray-300" htmlFor={id}>{label}</label>
      <div className="mt-1 flex items-center gap-2 rounded-lg border border-white/10 bg-dark-800 px-3 focus-within:border-emerald-500/60">
        {icon}
        <input id={id} className="w-full bg-transparent py-2.5 text-sm outline-none" {...input} />
      </div>
    </div>
  )
}

function SubmitButton({ busy, disabled, children }: { busy: boolean; disabled: boolean; children: ReactNode }) {
  return (
    <button
      type="submit"
      disabled={busy || disabled}
      className="mt-5 inline-flex w-full items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-emerald-500 to-cyan-500 py-2.5 text-sm font-semibold text-white shadow-lg shadow-emerald-500/20 hover:from-emerald-400 hover:to-cyan-400 disabled:opacity-50"
    >
      {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : null} {children}
    </button>
  )
}

function Login({ sameMachine, onSignedIn, onReset }: {
  sameMachine: boolean; onSignedIn: () => void; onReset: () => void
}) {
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      const s = await login(password)
      if (s.csrf) setCsrfToken(s.csrf)
      setPassword('')
      onSignedIn()
    } catch (err) {
      setError(apiErrorMessage(err, 'Sign-in failed'))
    } finally {
      setBusy(false)
    }
  }

  const reset = async () => {
    if (!window.confirm('Reset the panel password? Every signed-in browser is signed out, and you create a new password.')) return
    setError('')
    try {
      await resetPassword()
      onReset()
    } catch (err) {
      setError(apiErrorMessage(err, 'The password could not be reset'))
    }
  }

  return (
    <AuthLayout>
      <form onSubmit={submit}>
        <Field id="password" label="Password" icon={<Lock className="h-4 w-4 text-gray-500" />}
          type="password" autoComplete="current-password" autoFocus
          value={password} onChange={(e) => setPassword(e.target.value)} />
        {error ? <p className="mt-3 text-sm text-red-400">{error}</p> : null}
        <SubmitButton busy={busy} disabled={!password}>Sign in</SubmitButton>
        {sameMachine ? (
          <button type="button" onClick={reset}
            className="mt-4 text-xs text-emerald-400 hover:text-emerald-300 hover:underline">
            Forgot password? Reset
          </button>
        ) : (
          <p className="mt-4 text-xs text-gray-500">
            Forgot the password? Reset it on the computer Chameleon runs on.
          </p>
        )}
      </form>
    </AuthLayout>
  )
}

function Setup({ sameMachine, onDone, onExists }: {
  sameMachine: boolean; onDone: () => void; onExists: () => void
}) {
  const [code, setCode] = useState('')
  const [password, setPassword] = useState('')
  const [repeat, setRepeat] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const mismatch = repeat.length > 0 && repeat !== password
  const tooShort = password.length > 0 && password.length < MIN_PASSWORD

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (password !== repeat) { setError('The passwords do not match'); return }
    setBusy(true)
    setError('')
    try {
      const s = await setupPassword(code.trim(), password)
      if (s.csrf) setCsrfToken(s.csrf)
      onDone()
    } catch (err: any) {
      if (err?.response?.status === 409) { onExists(); return }
      setError(apiErrorMessage(err, 'The password could not be created'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <AuthLayout>
      <form onSubmit={submit}>
        <h2 className="text-lg font-semibold text-white">Create your password</h2>
        <p className="mt-1 mb-5 text-sm text-gray-400">
          {sameMachine
            ? 'Choose a password for the panel.'
            : 'Enter the setup code shown on the server when Chameleon was installed, then choose a password.'}
          {' '}Write it down: it cannot be recovered, only reset.
        </p>
        {sameMachine ? null : (
          <Field id="code" label="Setup code" icon={<KeyRound className="h-4 w-4 text-gray-500" />}
            autoComplete="one-time-code" autoFocus placeholder="XXXX-XXXX" spellCheck={false}
            value={code} onChange={(e) => setCode(e.target.value.toUpperCase())} />
        )}
        <Field id="new-password" label={`New password (at least ${MIN_PASSWORD} characters)`}
          icon={<Lock className="h-4 w-4 text-gray-500" />} autoFocus={sameMachine}
          type="password" autoComplete="new-password"
          value={password} onChange={(e) => setPassword(e.target.value)} />
        <Field id="repeat-password" label="Repeat the password" icon={<Lock className="h-4 w-4 text-gray-500" />}
          type="password" autoComplete="new-password"
          value={repeat} onChange={(e) => setRepeat(e.target.value)} />
        {tooShort ? <p className="mt-3 text-sm text-amber-300">Use at least {MIN_PASSWORD} characters.</p> : null}
        {mismatch ? <p className="mt-3 text-sm text-amber-300">The passwords do not match.</p> : null}
        {error ? <p className="mt-3 text-sm text-red-400">{error}</p> : null}
        <SubmitButton busy={busy}
          disabled={(!sameMachine && !code.trim()) || password.length < MIN_PASSWORD || password !== repeat}>
          Create password
        </SubmitButton>
      </form>
    </AuthLayout>
  )
}
