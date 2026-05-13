// Private Pool V2 — public key registry client (privacy-wallet pattern).
//
// Maps `wallet_pubkey → (viewing_pk, spending_pk_field, payment_address)`
// so a sender can do a private transfer using the recipient's REGULAR
// Solana wallet pubkey instead of asking them for a long payment address.
//
// Registry stores only PUBLIC key material — no privacy leak. Per-payment
// unlinkability stays intact via the ADR-008 stealth address mechanism.
//
// Usage:
//   - On `/app/private` after `derivePrivatePoolKeys`, call
//     `registerInRegistry({ ..., signature })` once. Idempotent — subsequent
//     calls just refresh the `registered_at` timestamp.
//   - In send flows (`/app/private` Send, `/app/send` instant), call
//     `lookupInRegistry({ network, walletPubkey })` to resolve a wallet
//     pubkey into the keys needed for encryption.
//
// Both functions throw on network errors; lookup returns `null` on 404
// (= "this wallet hasn't registered yet").

import type { PrivatePoolKeyMaterial } from './keys'

export type RegistryEntry = {
  network: string
  wallet_pubkey: string
  viewing_pk_hex: string
  spending_pk_field: string
  payment_address: string
  registered_at: string
}

function buildUrl(apiBaseUrl: string, path: string): string {
  return new URL(path, apiBaseUrl.endsWith('/') ? apiBaseUrl : apiBaseUrl + '/').toString()
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = ''
  for (const b of bytes) hex += b.toString(16).padStart(2, '0')
  return hex
}

/// Build the time-bounded UPDATE challenge. MUST match
/// `server/src/routes/private-pool-v2.js` PATH B (audit C-5).
/// Used when re-registering an existing wallet with NEW keys —
/// without this, a leaked PATH-A signature could forever overwrite
/// the victim's registry entry and redirect future payments to the
/// attacker.
export function buildRegistryUpdateChallenge(params: {
  walletPubkey: string
  paymentAddress: string
  timestampMs: number
}): Uint8Array {
  const message =
    'RelAI Private Pool V2 — registry UPDATE\n\n'
    + `wallet=${params.walletPubkey}\n`
    + `payment_address=${params.paymentAddress}\n`
    + `timestamp=${params.timestampMs}\n`
  return new TextEncoder().encode(message)
}

/// POST registry entry — must be called by the wallet owner with their
/// signature over the canonical key challenge (the same `signature` that
/// `derivePrivatePoolKeys` was given). Backend Ed25519-verifies against
/// `walletPubkey`, so no impersonation is possible.
///
/// `signature` is the raw `Uint8Array` returned by `wallet.signMessage()`
/// at onboarding time. Caller is responsible for passing it in.
///
/// For RE-registration with NEW keys (audit C-5), the backend requires
/// a fresh time-bounded UPDATE signature. Pass `updateSignMessage` as
/// well; the SDK will probe the existing entry and prompt the wallet
/// for the second sig only when needed (so first-time onboarding stays
/// at one popup). When `updateSignMessage` is omitted, the SDK falls
/// back to PATH A and the backend will reject any update-with-different-keys
/// request with `update_timestamp_invalid` — the caller has to retry
/// with `updateSignMessage` provided.
export async function registerInRegistry(args: {
  apiBaseUrl: string
  network: string
  walletPubkey: string
  keys: PrivatePoolKeyMaterial
  signature: Uint8Array
  /// Optional. When provided, used to sign the UPDATE challenge IF the
  /// existing registry entry has a different `payment_address` than
  /// the one being submitted. Skipped on first-time registration.
  updateSignMessage?: (message: Uint8Array) => Promise<Uint8Array>
}): Promise<RegistryEntry> {
  const url = buildUrl(args.apiBaseUrl, 'api/private-pool/v2/registry')

  // Pre-flight: is there an existing entry, and does its payment_address
  // differ from what we're about to submit? If yes → UPDATE path.
  let needsUpdateSig = false
  if (args.updateSignMessage) {
    try {
      const existing = await lookupInRegistry({
        apiBaseUrl: args.apiBaseUrl,
        network: args.network,
        walletPubkey: args.walletPubkey,
      })
      if (existing && existing.payment_address !== args.keys.paymentAddress) {
        needsUpdateSig = true
      }
    } catch {
      // Lookup failure → assume first-time registration (matches
      // backend's PATH A which is more permissive).
    }
  }

  let signatureHex: string
  let updateTimestamp: number | undefined
  if (needsUpdateSig && args.updateSignMessage) {
    updateTimestamp = Date.now()
    const challenge = buildRegistryUpdateChallenge({
      walletPubkey: args.walletPubkey,
      paymentAddress: args.keys.paymentAddress,
      timestampMs: updateTimestamp,
    })
    const sig = await args.updateSignMessage(challenge)
    if (!sig || sig.length !== 64) {
      throw new Error(`update signature: expected 64 bytes, got ${sig?.length ?? 0}`)
    }
    signatureHex = bytesToHex(sig)
  } else {
    signatureHex = bytesToHex(args.signature)
  }

  const r = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      network: args.network,
      wallet_pubkey: args.walletPubkey,
      viewing_pk_hex: bytesToHex(args.keys.viewingPk),
      spending_pk_field: args.keys.spendingPkField.toString(10),
      payment_address: args.keys.paymentAddress,
      signature_hex: signatureHex,
      ...(updateTimestamp !== undefined ? { update_timestamp: updateTimestamp } : {}),
    }),
  })
  if (!r.ok) {
    const err = await r.text()
    throw new Error(`registry POST failed: ${r.status} ${err}`)
  }
  const j = (await r.json()) as { ok: boolean; entry: RegistryEntry }
  return j.entry
}

/// GET registry entry by wallet pubkey. Returns `null` when the wallet
/// hasn't registered yet (HTTP 404), throws on other network errors.
export async function lookupInRegistry(args: {
  apiBaseUrl: string
  network: string
  walletPubkey: string
}): Promise<RegistryEntry | null> {
  const url = new URL(
    `api/private-pool/v2/registry/${encodeURIComponent(args.walletPubkey)}`,
    args.apiBaseUrl.endsWith('/') ? args.apiBaseUrl : args.apiBaseUrl + '/',
  )
  url.searchParams.set('network', args.network)
  const r = await fetch(url.toString())
  if (r.status === 404) return null
  if (!r.ok) {
    const err = await r.text()
    throw new Error(`registry GET failed: ${r.status} ${err}`)
  }
  return (await r.json()) as RegistryEntry
}

/// Helper: convert a registry entry into the shape that
/// `prepareJoinSplitTransaction` / `prepareDepositTransaction` expect for
/// `recipient: { spendingPkField, viewingPk }`. Saves the caller a hex
/// decode + bigint parse round-trip per send.
export function registryEntryToRecipient(entry: RegistryEntry): {
  spendingPkField: bigint
  viewingPk: Uint8Array
} {
  const cleanHex = entry.viewing_pk_hex.startsWith('0x')
    ? entry.viewing_pk_hex.slice(2)
    : entry.viewing_pk_hex
  const viewingPk = new Uint8Array(cleanHex.length / 2)
  for (let i = 0; i < viewingPk.length; i++) {
    viewingPk[i] = parseInt(cleanHex.slice(i * 2, i * 2 + 2), 16)
  }
  return {
    spendingPkField: BigInt(entry.spending_pk_field),
    viewingPk,
  }
}
