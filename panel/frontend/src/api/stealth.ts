// Copyright (c) 2026 NewNetGuard
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import api from './client'

export interface StealthStatus {
  success?: boolean
  // tunnel
  running: boolean
  connected: boolean
  killswitch: boolean
  dns_protected: boolean
  quic_blocked: boolean
  fingerprint: string
  behavior: string
  shield: string
  bytes_sent: number
  bytes_recv: number
  server: string
  // client settings
  configured: boolean
  server_address: string
  transport: string
  cert_mode: string
  shield_preset: string
  reality_public: string
  has_psk: boolean
  doh_domain: string
  buffer_size: number
  reconnect_interval: number
  block_quic: boolean
  fingerprint_mode: 'auto' | 'mobile' | 'desktop'
  enabled: boolean
  // server SSH
  ssh_host: string
  ssh_user: string
  ssh_port: number
  has_password: boolean
  ssh_key_installed: boolean
  ssh_key_verified: boolean
  ssh_key_fingerprint: string
  credential_protection: string
  remote_path: string
  acme_terms_accepted: boolean
  ip_shield_deployed: boolean
  domain: string
  domain_tls_deployed: boolean
  shield_migration_required: boolean
  ssh_host_key_trusted: boolean
  ssh_host_key_fingerprint: string
  runtime_log: string
  error?: string
  warning?: string
  failure_code?: string
  health_error?: string
  failed_at?: string
  health_title?: string
  health_hint?: string
}

export interface DeployResult {
  success: boolean
  log: string
  error?: string
  active?: boolean
  needs_trust?: boolean
  fingerprint?: string
  key_type?: string
  busy?: boolean
  host_key_trusted?: boolean
  credentials_ready?: boolean
}

export const getStealthStatus = async (): Promise<StealthStatus> => {
  const { data } = await api.get('/stealth/status'); return data
}
export const saveStealthClient = async (body: Record<string, unknown>): Promise<StealthStatus> => {
  const { data } = await api.post('/stealth/client', body); return data
}
export const generatePsk = async (): Promise<{ psk_key: string }> => {
  const { data } = await api.post('/stealth/generate/psk'); return data
}
export const generateReality = async (): Promise<{ reality_public: string }> => {
  const { data } = await api.post('/stealth/generate/reality'); return data
}
export const enableStealth = async (): Promise<StealthStatus> => {
  const { data } = await api.post('/stealth/enable', undefined, { timeout: 55_000 }); return data
}
export const disableStealth = async (): Promise<StealthStatus> => {
  const { data } = await api.post('/stealth/disable', undefined, { timeout: 55_000 }); return data
}
export const deleteStealthConfig = async (): Promise<{ success: boolean; error?: string }> => {
  const { data } = await api.delete('/stealth/config', { timeout: 55_000 }); return data
}
export const saveStealthServer = async (body: {
  host: string; user: string; port: number; password?: string; remote_path: string; acme_terms_accepted: boolean
  domain: string
}): Promise<StealthStatus> => {
  const { data } = await api.post('/stealth/server', body); return data
}
// Check SSH and Trust host key may log in twice (password, then the new panel
// key) and call the credential broker several times. The shared 30-second
// timeout could report a failure while the operation still completes.
export const checkStealthSsh = async (): Promise<DeployResult> => {
  const { data } = await api.post('/stealth/server/check', undefined, { timeout: 300_000 }); return data
}
export const trustStealthSshHostKey = async (fingerprint: string): Promise<DeployResult> => {
  const { data } = await api.post(
    '/stealth/server/trust-host-key', { fingerprint }, { timeout: 300_000 },
  ); return data
}
export const deployStealthServer = async (): Promise<DeployResult> => {
  // A first deployment may install packages and issue the IP certificate.
  // Keep this operation bounded, but do not let the shared 30-second timeout
  // report a failure while the authenticated deployment continues on the VPS.
  const { data } = await api.post(
    '/stealth/server/deploy', undefined, { timeout: 900_000 },
  ); return data
}
export const configureStealthDomainTls = async (): Promise<DeployResult> => {
  // HTTP-01 validation and certificate migration may take more than the shared
  // 30-second API timeout. Keep this single operation bounded at 10 min.
  const { data } = await api.post(
    '/stealth/server/domain-tls', undefined, { timeout: 600_000 },
  ); return data
}
export const removeStealthDomainTls = async (): Promise<DeployResult> => {
  const { data } = await api.delete(
    '/stealth/server/domain-tls', { timeout: 300_000 },
  ); return data
}
export const stopStealthServer = async (): Promise<DeployResult> => {
  const { data } = await api.post('/stealth/server/stop', undefined, { timeout: 300_000 }); return data
}
export const uninstallStealthServer = async (): Promise<DeployResult> => {
  const { data } = await api.post('/stealth/server/uninstall', undefined, { timeout: 360_000 }); return data
}
export const fetchStealthServerLogs = async (): Promise<DeployResult> => {
  const { data } = await api.post('/stealth/server/logs'); return data
}
