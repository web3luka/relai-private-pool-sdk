// Private Pool V2 — local key cache (IndexedDB).
//
// Caches `PrivatePoolKeyMaterial` so the user doesn't have to sign the
// challenge message every time they reload `/app/private`. Two modes:
//
//   1. PLAINTEXT (default — opt-out via setupPin)
//      The cache holds the key material as plain JSON in IndexedDB.
//      Anyone with read access to the user's browser disk can recover
//      all V2 keys (spending_sk, viewing_sk, nullifier_sk). The
//      Settings UI labels this honestly: "this device-only cache, click
//      Reset cached keys before leaving a shared computer."
//
//   2. PIN-ENCRYPTED (opt-in via setupPin)
//      The cache is AES-GCM encrypted with a key derived via PBKDF2
//      (200k iterations) from a user-supplied PIN. Each session prompts
//      for PIN once; the derived key sits in module-level memory until
//      either (a) the configurable idle timeout elapses, (b) lockNow()
//      is called, (c) the tab is closed/refreshed.
//
// Threat model coverage:
//   - PLAINTEXT mode: protects against NOTHING beyond browser-storage
//     isolation (per-origin sandbox). Honest about it.
//   - PIN-ENCRYPTED mode: protects against stolen-laptop / compromised
//     device, AS LONG AS the PIN has enough entropy and the idle
//     timeout is short. PBKDF2 200k iters means a brute-force attempt
//     on a stolen laptop costs ~50ms per guess (modern CPU) — a 6-digit
//     numeric PIN falls in ~14 hours, an 8-char alphanumeric PIN takes
//     ~25 years. We recommend ≥8 chars in the UI.
//
// Per ADR-006 amendment ("silent re-derivation when cache missing")
// the wallet signature is always the recovery path: forgot PIN →
// `clearCachedKeys` → next visit re-derives from a fresh wallet sig.
// Cache loss is annoying, never funds-loss.

import { chacha20poly1305 } from '@noble/ciphers/chacha';
import { blake2b } from '@noble/hashes/blake2b';
import type { PrivatePoolKeyMaterial } from './keys';

const DB_NAME = 'relai-private-pool-v2'
// v1 → v2: ACK_STORE for backup-acknowledgement gate.
// v2 → v3: cache entries gain a `mode` discriminator (plaintext / pin-encrypted).
//          Existing v1/v2 plaintext entries auto-upgrade on next read by
//          re-saving as `{ mode: 'plaintext', ... }`.
const DB_VERSION = 2
const STORE = 'keys'
const ACK_STORE = 'backup-ack'

const CACHE_VERSION = 2  // bumped to 2 with mode-aware entries
const PBKDF2_ITERATIONS = 200_000  // ~50ms per guess on modern CPU
const PBKDF2_HASH = 'SHA-256'
const AES_KEY_BITS = 256
const AES_NAME = 'AES-GCM'
const SALT_LEN = 16
const IV_LEN = 12

// localStorage keys for non-secret settings (lock interval, last-mode hint).
const LS_LOCK_INTERVAL_PREFIX = 'relai-pp-v2:lock-interval:'

const TEXT_ENCODER = new TextEncoder()
const TEXT_DECODER = new TextDecoder()

// ── IndexedDB plumbing ──────────────────────────────────────────────────

function isAvailable(): boolean {
  return typeof globalThis !== 'undefined' && typeof globalThis.indexedDB !== 'undefined'
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    if (!isAvailable()) return reject(new Error('IndexedDB not available'))
    const req = indexedDB.open(DB_NAME, DB_VERSION)
    req.onupgradeneeded = () => {
      const db = req.result
      // Both stores created on every upgrade — `createObjectStore` is
      // idempotent in practice via the `contains` guard, and tagging
      // both here means a fresh-install user gets v2 schema on first
      // open without needing the lazy-upgrade dance below.
      if (!db.objectStoreNames.contains(STORE)) {
        db.createObjectStore(STORE)
      }
      if (!db.objectStoreNames.contains(ACK_STORE)) {
        db.createObjectStore(ACK_STORE)
      }
    }
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error || new Error('IndexedDB open failed'))
  })
}

async function withStore<T>(mode: IDBTransactionMode, fn: (store: IDBObjectStore) => Promise<T> | T): Promise<T> {
  const db = await openDb()
  return new Promise<T>((resolve, reject) => {
    const tx = db.transaction(STORE, mode)
    const store = tx.objectStore(STORE)
    Promise.resolve(fn(store)).then((v) => {
      tx.oncomplete = () => resolve(v)
      tx.onerror = () => reject(tx.error || new Error('IndexedDB tx error'))
    }).catch((err) => {
      try { tx.abort() } catch {}
      reject(err)
    })
  })
}

function idbGet<T>(store: IDBObjectStore, key: IDBValidKey): Promise<T | undefined> {
  return new Promise((resolve, reject) => {
    const r = store.get(key)
    r.onsuccess = () => resolve(r.result as T | undefined)
    r.onerror = () => reject(r.error)
  })
}

function idbPut(store: IDBObjectStore, key: IDBValidKey, value: unknown): Promise<void> {
  return new Promise((resolve, reject) => {
    const r = store.put(value, key)
    r.onsuccess = () => resolve()
    r.onerror = () => reject(r.error)
  })
}

function idbDelete(store: IDBObjectStore, key: IDBValidKey): Promise<void> {
  return new Promise((resolve, reject) => {
    const r = store.delete(key)
    r.onsuccess = () => resolve()
    r.onerror = () => reject(r.error)
  })
}

// ── Encryption (deterministic from wallet pubkey) ───────────────────────

function deriveCacheKey(walletPubkey: string): Uint8Array {
  // 32-byte key, blake2b-derived from the wallet pubkey + cache version
  // tag. NOT a security boundary — see threat model in module doc.
  return blake2b(TEXT_ENCODER.encode(`relai-pool-v2-cache:v${CACHE_VERSION}:${walletPubkey}`), { dkLen: 32 })
}

function deriveCacheNonce(walletPubkey: string): Uint8Array {
  // 12-byte deterministic nonce (acceptable: same key never used twice
  // for different plaintexts because each upsert overwrites the
  // ciphertext at rest, so "nonce reuse with same plaintext" never
  // happens at observable boundary).
  return blake2b(TEXT_ENCODER.encode(`relai-pool-v2-cache-nonce:v${CACHE_VERSION}:${walletPubkey}`), { dkLen: 12 })
}

// ── Serialisation ───────────────────────────────────────────────────────

function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex')
}
function hexToBytes(hex: string): Uint8Array {
  return Uint8Array.from(Buffer.from(hex, 'hex'))
}

type SerializedKeyMaterial = {
  v: number
  rootSk: string
  spendingSk: string
  viewingSk: string
  nullifierSk: string
  spendingSkField: string
  nullifierSkField: string
  spendingPkField: string
  viewingPk: string
  paymentAddress: string
}

function serialize(km: PrivatePoolKeyMaterial): SerializedKeyMaterial {
  return {
    v: CACHE_VERSION,
    rootSk: bytesToHex(km.rootSk),
    spendingSk: bytesToHex(km.spendingSk),
    viewingSk: bytesToHex(km.viewingSk),
    nullifierSk: bytesToHex(km.nullifierSk),
    spendingSkField: km.spendingSkField.toString(10),
    nullifierSkField: km.nullifierSkField.toString(10),
    spendingPkField: km.spendingPkField.toString(10),
    viewingPk: bytesToHex(km.viewingPk),
    paymentAddress: km.paymentAddress,
  }
}

function deserialize(s: SerializedKeyMaterial): PrivatePoolKeyMaterial | null {
  if (!s || s.v !== CACHE_VERSION) return null
  try {
    return {
      rootSk: hexToBytes(s.rootSk),
      spendingSk: hexToBytes(s.spendingSk),
      viewingSk: hexToBytes(s.viewingSk),
      nullifierSk: hexToBytes(s.nullifierSk),
      spendingSkField: BigInt(s.spendingSkField),
      nullifierSkField: BigInt(s.nullifierSkField),
      spendingPkField: BigInt(s.spendingPkField),
      viewingPk: hexToBytes(s.viewingPk),
      paymentAddress: s.paymentAddress,
    }
  } catch {
    return null
  }
}

// ── Mode-aware entry shape ──────────────────────────────────────────────

type PlaintextEntry = {
  mode: 'plaintext'
  v: number
  data: SerializedKeyMaterial
  stored_at: number
}

type PinEncryptedEntry = {
  mode: 'pin-encrypted'
  v: number
  ciphertext_b64: string
  salt_b64: string
  iv_b64: string
  iter: number
  stored_at: number
}

// Backward-compat: v1 entries from the previous "deterministic-key
// chacha20poly1305" scheme get treated as legacy and decrypted via
// the same path on first load, then re-saved as plaintext mode.
type LegacyV1Entry = { v: 1; ciphertext: string; stored_at: number }

type CacheEntry = PlaintextEntry | PinEncryptedEntry | LegacyV1Entry

// ── In-memory unlock state (PIN mode only) ──────────────────────────────
//
// When a PIN-protected cache is unlocked, the derived AES key sits in
// module-level memory until either:
//   - lockNow() is called explicitly
//   - the configurable idle interval elapses (each operation refreshes it)
//   - the tab is closed / page refreshes (memory wiped naturally)
// Refresh = re-prompt PIN.

let unlockedKey: CryptoKey | null = null
let unlockedForWallet: string | null = null
let lastActivityAt = 0

/// Lock interval is per-wallet, persisted in localStorage. Defaults to
/// 8h (one working day) — matches what most users will actively work
/// on V2 in a single session. Configurable via `setLockInterval`.
///
/// Allowed presets (ms): 15min / 1h / 8h / 24h / 0 (never).
/// Use `LOCK_INTERVAL_PRESETS` for the runtime list.
export type LockIntervalMs = number

export const LOCK_INTERVAL_PRESETS = [
  15 * 60 * 1000,        // 15 min
  60 * 60 * 1000,        // 1h
  8 * 60 * 60 * 1000,    // 8h (default)
  24 * 60 * 60 * 1000,   // 24h
  0,                      // never
] as const
const DEFAULT_LOCK_INTERVAL_MS = 8 * 60 * 60 * 1000

export function getLockInterval(walletPubkey: string): number {
  if (typeof localStorage === 'undefined') return DEFAULT_LOCK_INTERVAL_MS
  const v = localStorage.getItem(LS_LOCK_INTERVAL_PREFIX + walletPubkey)
  if (!v) return DEFAULT_LOCK_INTERVAL_MS
  const n = Number(v)
  return Number.isFinite(n) && LOCK_INTERVAL_PRESETS.includes(n) ? n : DEFAULT_LOCK_INTERVAL_MS
}

export function setLockInterval(walletPubkey: string, intervalMs: number): void {
  if (typeof localStorage === 'undefined') return
  if (!LOCK_INTERVAL_PRESETS.includes(intervalMs)) {
    throw new Error(`setLockInterval: ${intervalMs} is not one of the allowed presets (15m, 1h, 8h, 24h, never=0)`)
  }
  localStorage.setItem(LS_LOCK_INTERVAL_PREFIX + walletPubkey, String(intervalMs))
}

/// Manually wipe the in-memory unlock key. Next access prompts PIN.
export function lockNow(): void {
  unlockedKey = null
  unlockedForWallet = null
  lastActivityAt = 0
}

/// Returns true when the in-memory unlock key is fresh enough to
/// satisfy the configured idle window. `false` means PIN is needed.
function isUnlockedFor(walletPubkey: string): boolean {
  if (!unlockedKey || unlockedForWallet !== walletPubkey) return false
  const interval = getLockInterval(walletPubkey)
  if (interval === 0) {
    // "Never" — only manual lockNow / page refresh wipes.
    return true
  }
  if (Date.now() - lastActivityAt > interval) {
    lockNow()
    return false
  }
  return true
}

function bumpActivity(): void {
  lastActivityAt = Date.now()
}

// ── Web Crypto helpers (Subtle API) ─────────────────────────────────────

function subtle(): SubtleCrypto {
  if (typeof globalThis === 'undefined' || !globalThis.crypto?.subtle) {
    throw new Error('Web Crypto SubtleCrypto not available — PIN protection requires a modern browser')
  }
  return globalThis.crypto.subtle
}

function randomBytes(len: number): Uint8Array {
  const out = new Uint8Array(len)
  globalThis.crypto.getRandomValues(out)
  return out
}

function bytesToBase64(bytes: Uint8Array): string {
  if (typeof Buffer !== 'undefined') return Buffer.from(bytes).toString('base64')
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s)
}

function base64ToBytes(b64: string): Uint8Array {
  if (typeof Buffer !== 'undefined') return Uint8Array.from(Buffer.from(b64, 'base64'))
  const s = atob(b64)
  const out = new Uint8Array(s.length)
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i)
  return out
}

async function deriveAesKeyFromPin(
  pin: string,
  salt: Uint8Array,
  iterations: number,
): Promise<CryptoKey> {
  const pinBytes = TEXT_ENCODER.encode(pin)
  const baseKey = await subtle().importKey(
    'raw',
    pinBytes,
    { name: 'PBKDF2' },
    false,
    ['deriveKey'],
  )
  return subtle().deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations,
      hash: PBKDF2_HASH,
    },
    baseKey,
    { name: AES_NAME, length: AES_KEY_BITS },
    false,  // not extractable
    ['encrypt', 'decrypt'],
  )
}

async function aesEncrypt(key: CryptoKey, iv: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  const ct = await subtle().encrypt({ name: AES_NAME, iv }, key, plaintext)
  return new Uint8Array(ct)
}

async function aesDecrypt(key: CryptoKey, iv: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
  const pt = await subtle().decrypt({ name: AES_NAME, iv }, key, ciphertext)
  return new Uint8Array(pt)
}

// ── Public surface ──────────────────────────────────────────────────────

/// Save the derived key tree to local cache. Mode is determined by
/// what's already stored:
///   - PIN-protected entry exists AND in-memory key is unlocked → re-encrypt
///   - PIN-protected entry exists BUT locked → THROW (caller must unlock first)
///   - plaintext entry OR no entry → write plaintext
///
/// Plaintext is the default for new caches. Users opt in to PIN
/// protection via `setupPin()`.
export async function saveCachedKeys(walletPubkey: string, keys: PrivatePoolKeyMaterial): Promise<void> {
  if (!isAvailable()) return
  try {
    const existing = await readRawEntry(walletPubkey)
    if (existing && 'mode' in existing && existing.mode === 'pin-encrypted') {
      if (!isUnlockedFor(walletPubkey)) {
        throw new Error('saveCachedKeys: cache is PIN-protected and locked — call unlockWithPin first')
      }
      const salt = base64ToBytes(existing.salt_b64)
      const iv = randomBytes(IV_LEN)
      const plaintext = TEXT_ENCODER.encode(JSON.stringify(serialize(keys)))
      const ciphertext = await aesEncrypt(unlockedKey!, iv, plaintext)
      bumpActivity()
      await writeEntry(walletPubkey, {
        mode: 'pin-encrypted',
        v: CACHE_VERSION,
        ciphertext_b64: bytesToBase64(ciphertext),
        salt_b64: bytesToBase64(salt),
        iv_b64: bytesToBase64(iv),
        iter: PBKDF2_ITERATIONS,
        stored_at: Date.now(),
      })
      return
    }
    // Plaintext path — default for new caches and for entries that
    // were never PIN-protected.
    await writeEntry(walletPubkey, {
      mode: 'plaintext',
      v: CACHE_VERSION,
      data: serialize(keys),
      stored_at: Date.now(),
    })
  } catch (err) {
    // Cache failure must NEVER block deposit/spend (ADR-006). Log and
    // move on; caller falls back to re-derivation from wallet sig.
    // eslint-disable-next-line no-console
    console.warn('[private-pool-v2 cache] saveCachedKeys failed:', err)
  }
}

/// Try to load cached keys.
///
/// Return semantics:
///   - `null` if NO cache entry, OR cache is PIN-protected and locked
///     (caller checks `isPinProtected` to distinguish), OR decryption
///     fails (caller should re-derive from wallet sig).
///   - `PrivatePoolKeyMaterial` if plaintext OR PIN-unlocked.
///
/// To avoid awkward null-checks in callers, see `loadCachedKeysWithStatus`
/// which returns a richer enum.
export async function loadCachedKeys(walletPubkey: string): Promise<PrivatePoolKeyMaterial | null> {
  const status = await loadCachedKeysWithStatus(walletPubkey)
  return status.kind === 'ok' ? status.keys : null
}

/// Rich-status variant — UI uses this to decide whether to show a
/// PIN prompt, an empty-cache "sign to derive" CTA, or just render
/// the balance.
export type LoadCacheStatus =
  | { kind: 'ok'; keys: PrivatePoolKeyMaterial }
  | { kind: 'no-cache' }
  | { kind: 'pin-required' }
  | { kind: 'corrupted' }

export async function loadCachedKeysWithStatus(walletPubkey: string): Promise<LoadCacheStatus> {
  if (!isAvailable()) return { kind: 'no-cache' }
  try {
    const entry = await readRawEntry(walletPubkey)
    if (!entry) return { kind: 'no-cache' }

    // Legacy v1 (pre-mode-aware, deterministic-key chacha20poly1305).
    // Decrypt with the old scheme, then re-save as plaintext so future
    // loads take the fast path.
    if (!('mode' in entry) && entry.v === 1) {
      try {
        const key = deriveCacheKey(walletPubkey)
        const nonce = deriveCacheNonce(walletPubkey)
        const cipher = chacha20poly1305(key, nonce)
        const plaintext = cipher.decrypt(hexToBytes(entry.ciphertext))
        const parsed = JSON.parse(TEXT_DECODER.decode(plaintext)) as SerializedKeyMaterial
        const keys = deserialize(parsed)
        if (!keys) return { kind: 'corrupted' }
        // Lazy upgrade to plaintext mode (honest about it).
        await writeEntry(walletPubkey, {
          mode: 'plaintext',
          v: CACHE_VERSION,
          data: parsed,
          stored_at: Date.now(),
        })
        return { kind: 'ok', keys }
      } catch {
        return { kind: 'corrupted' }
      }
    }

    if ('mode' in entry && entry.mode === 'plaintext') {
      const keys = deserialize(entry.data)
      return keys ? { kind: 'ok', keys } : { kind: 'corrupted' }
    }

    if ('mode' in entry && entry.mode === 'pin-encrypted') {
      if (!isUnlockedFor(walletPubkey)) {
        return { kind: 'pin-required' }
      }
      try {
        const iv = base64ToBytes(entry.iv_b64)
        const ciphertext = base64ToBytes(entry.ciphertext_b64)
        const plaintext = await aesDecrypt(unlockedKey!, iv, ciphertext)
        const parsed = JSON.parse(TEXT_DECODER.decode(plaintext)) as SerializedKeyMaterial
        const keys = deserialize(parsed)
        bumpActivity()
        return keys ? { kind: 'ok', keys } : { kind: 'corrupted' }
      } catch {
        // Decryption failure with a present key usually means corruption.
        // If the key is wrong (wrong PIN), unlockWithPin would have failed
        // already — but be defensive here.
        return { kind: 'corrupted' }
      }
    }

    return { kind: 'corrupted' }
  } catch (err) {
    console.warn('[private-pool-v2 cache] loadCachedKeysWithStatus failed:', err)
    return { kind: 'corrupted' }
  }
}

/// True if the cache for this wallet is PIN-protected (regardless of
/// current unlock state). UI uses this to render the right CTA.
export async function isPinProtected(walletPubkey: string): Promise<boolean> {
  if (!isAvailable()) return false
  try {
    const entry = await readRawEntry(walletPubkey)
    return !!(entry && 'mode' in entry && entry.mode === 'pin-encrypted')
  } catch {
    return false
  }
}

/// True if the in-memory unlock state is fresh (PIN was entered
/// recently and the idle timer hasn't expired).
export function isUnlocked(walletPubkey: string): boolean {
  return isUnlockedFor(walletPubkey)
}

/// Convert an existing plaintext cache (or freshly-derived in-memory
/// keys) into a PIN-protected cache. After success, subsequent loads
/// require `unlockWithPin` and the in-memory key is set so the current
/// session can keep using `saveCachedKeys` without re-prompting.
///
/// Throws if:
///   - No cache exists yet (caller must save plaintext first via the
///     normal flow, then call setupPin)
///   - PIN protection is already enabled (use `changePin` instead)
///   - PIN length < 4 chars
export async function setupPin(args: {
  walletPubkey: string
  pin: string
  intervalMs?: number
}): Promise<void> {
  const { walletPubkey, pin } = args
  if (!isAvailable()) throw new Error('IndexedDB not available')
  if (!pin || pin.length < 4) {
    throw new Error('PIN must be at least 4 characters')
  }
  const existing = await readRawEntry(walletPubkey)
  if (!existing) throw new Error('setupPin: no cache to protect (sign in first)')
  if ('mode' in existing && existing.mode === 'pin-encrypted') {
    throw new Error('setupPin: PIN already enabled — use changePin instead')
  }
  // Pull plaintext keys out of whatever the current entry is.
  let keys: PrivatePoolKeyMaterial | null = null
  if (!('mode' in existing) && existing.v === 1) {
    // Legacy entry — decrypt via the old deterministic scheme.
    const key = deriveCacheKey(walletPubkey)
    const nonce = deriveCacheNonce(walletPubkey)
    const cipher = chacha20poly1305(key, nonce)
    const plaintext = cipher.decrypt(hexToBytes(existing.ciphertext))
    const parsed = JSON.parse(TEXT_DECODER.decode(plaintext)) as SerializedKeyMaterial
    keys = deserialize(parsed)
  } else if ('mode' in existing && existing.mode === 'plaintext') {
    keys = deserialize(existing.data)
  }
  if (!keys) throw new Error('setupPin: failed to read existing cache')

  const salt = randomBytes(SALT_LEN)
  const iv = randomBytes(IV_LEN)
  const aesKey = await deriveAesKeyFromPin(pin, salt, PBKDF2_ITERATIONS)
  const plaintext = TEXT_ENCODER.encode(JSON.stringify(serialize(keys)))
  const ciphertext = await aesEncrypt(aesKey, iv, plaintext)
  await writeEntry(walletPubkey, {
    mode: 'pin-encrypted',
    v: CACHE_VERSION,
    ciphertext_b64: bytesToBase64(ciphertext),
    salt_b64: bytesToBase64(salt),
    iv_b64: bytesToBase64(iv),
    iter: PBKDF2_ITERATIONS,
    stored_at: Date.now(),
  })
  // Persist the chosen interval (or default) and put the unlock state
  // in memory so the user doesn't have to re-enter PIN immediately.
  if (typeof args.intervalMs === 'number') {
    setLockInterval(walletPubkey, args.intervalMs)
  }
  unlockedKey = aesKey
  unlockedForWallet = walletPubkey
  bumpActivity()
}

/// Verify PIN and put the derived AES key in memory for the configured
/// idle window. Returns true on success, false on wrong PIN. Never
/// throws on auth failure; callers branch on the boolean.
///
/// Implementation: derive the AES key from PIN+salt+iter, attempt to
/// decrypt the entry. Decryption success = correct PIN.
export async function unlockWithPin(args: {
  walletPubkey: string
  pin: string
}): Promise<boolean> {
  const { walletPubkey, pin } = args
  if (!isAvailable()) return false
  const entry = await readRawEntry(walletPubkey)
  if (!entry || !('mode' in entry) || entry.mode !== 'pin-encrypted') return false
  try {
    const salt = base64ToBytes(entry.salt_b64)
    const iv = base64ToBytes(entry.iv_b64)
    const ciphertext = base64ToBytes(entry.ciphertext_b64)
    const aesKey = await deriveAesKeyFromPin(pin, salt, entry.iter || PBKDF2_ITERATIONS)
    // Trial decrypt — if PIN is wrong, AES-GCM throws on tag mismatch.
    await aesDecrypt(aesKey, iv, ciphertext)
    unlockedKey = aesKey
    unlockedForWallet = walletPubkey
    bumpActivity()
    return true
  } catch {
    return false
  }
}

/// Remove PIN protection — decrypts the cache back to plaintext mode.
/// Requires the current PIN to authorise. Idempotent on plaintext caches.
export async function removePin(args: {
  walletPubkey: string
  pin: string
}): Promise<void> {
  const ok = await unlockWithPin(args)
  if (!ok) throw new Error('removePin: PIN incorrect')
  // After unlock succeeded, decrypt and re-save as plaintext.
  const status = await loadCachedKeysWithStatus(args.walletPubkey)
  if (status.kind !== 'ok') throw new Error('removePin: failed to decrypt cache after unlock')
  await writeEntry(args.walletPubkey, {
    mode: 'plaintext',
    v: CACHE_VERSION,
    data: serialize(status.keys),
    stored_at: Date.now(),
  })
  lockNow()
}

/// Change PIN — validates old PIN, then re-encrypts with new PIN.
/// New idle interval is OPTIONAL; if omitted the existing interval is preserved.
export async function changePin(args: {
  walletPubkey: string
  oldPin: string
  newPin: string
  intervalMs?: number
}): Promise<void> {
  if (!args.newPin || args.newPin.length < 4) {
    throw new Error('PIN must be at least 4 characters')
  }
  // Verify old PIN by unlocking + reading the keys.
  const ok = await unlockWithPin({ walletPubkey: args.walletPubkey, pin: args.oldPin })
  if (!ok) throw new Error('changePin: old PIN incorrect')
  const status = await loadCachedKeysWithStatus(args.walletPubkey)
  if (status.kind !== 'ok') throw new Error('changePin: failed to decrypt cache')
  // Wipe old in-memory state, then re-setup with the new PIN.
  lockNow()
  const salt = randomBytes(SALT_LEN)
  const iv = randomBytes(IV_LEN)
  const aesKey = await deriveAesKeyFromPin(args.newPin, salt, PBKDF2_ITERATIONS)
  const plaintext = TEXT_ENCODER.encode(JSON.stringify(serialize(status.keys)))
  const ciphertext = await aesEncrypt(aesKey, iv, plaintext)
  await writeEntry(args.walletPubkey, {
    mode: 'pin-encrypted',
    v: CACHE_VERSION,
    ciphertext_b64: bytesToBase64(ciphertext),
    salt_b64: bytesToBase64(salt),
    iv_b64: bytesToBase64(iv),
    iter: PBKDF2_ITERATIONS,
    stored_at: Date.now(),
  })
  if (typeof args.intervalMs === 'number') {
    setLockInterval(args.walletPubkey, args.intervalMs)
  }
  unlockedKey = aesKey
  unlockedForWallet = args.walletPubkey
  bumpActivity()
}

// ── Internal IndexedDB read/write wrappers (mode-aware) ────────────────

async function readRawEntry(walletPubkey: string): Promise<CacheEntry | null> {
  const raw = await withStore('readonly', (store) => idbGet<CacheEntry>(store, walletPubkey))
  return raw ?? null
}

async function writeEntry(walletPubkey: string, entry: PlaintextEntry | PinEncryptedEntry): Promise<void> {
  await withStore('readwrite', (store) => idbPut(store, walletPubkey, entry))
}

// ── Backup / restore (privacy-wallet pattern) ─────────────────────────────────────
//
// Exports the full key tree as a portable JSON file. User keeps it
// safely (cloud drive, USB, encrypted vault — their choice). Restoring
// on a fresh device (or after IndexedDB wipe) bypasses the wallet
// signature challenge — keys flow directly into the in-memory state +
// IndexedDB cache.
//
// Format is plaintext JSON (no extra password) — same as other privacy wallets. The user
// is responsible for protecting the file. We include a clear warning in
// the UI before download. Adding password-based encryption is an obvious
// future enhancement (Faza 6 backlog) — out of scope for the first ship.

const BACKUP_FORMAT_NAME = 'relai-private-pool-v2-backup'
const BACKUP_FORMAT_VERSION = 1

export type BackupFile = {
  format: typeof BACKUP_FORMAT_NAME
  version: number
  walletPubkey: string
  paymentAddress: string
  createdAt: string
  /// Plaintext serialization of `PrivatePoolKeyMaterial`. Whoever holds
  /// this file can spend the user's private balance — treat like a seed.
  keys: SerializedKeyMaterial
  /// Optional metadata to make UX clearer when restoring (e.g. "this
  /// backup is from May 2026, you have 5 notes worth ~3 USDC").
  meta?: {
    note?: string
  }
}

/// Build a portable backup object for the given wallet + keys. Returns
/// the JSON string ready for download. Caller wraps in a Blob and
/// triggers the file save via DOM (no IO from this module).
export function buildBackupFileJson(args: {
  walletPubkey: string
  keys: PrivatePoolKeyMaterial
  note?: string
}): string {
  const file: BackupFile = {
    format: BACKUP_FORMAT_NAME,
    version: BACKUP_FORMAT_VERSION,
    walletPubkey: args.walletPubkey,
    paymentAddress: args.keys.paymentAddress,
    createdAt: new Date().toISOString(),
    keys: serialize(args.keys),
    meta: args.note ? { note: args.note } : undefined,
  }
  return JSON.stringify(file, null, 2)
}

/// Parse a backup JSON file back into `PrivatePoolKeyMaterial`. Returns
/// `{ ok: false, error }` on malformed input, `{ ok: true, keys, walletPubkey }`
/// otherwise. Caller validates `walletPubkey` against the connected
/// wallet (mismatch = warn or block — depends on UX choice).
export function parseBackupFileJson(raw: string): {
  ok: true
  keys: PrivatePoolKeyMaterial
  walletPubkey: string
  paymentAddress: string
  createdAt: string
} | { ok: false; error: string } {
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch (e: unknown) {
    return { ok: false, error: `not a valid JSON file: ${(e as Error)?.message ?? String(e)}` }
  }
  if (typeof parsed !== 'object' || parsed === null) {
    return { ok: false, error: 'backup file must be a JSON object' }
  }
  const file = parsed as Partial<BackupFile>
  if (file.format !== BACKUP_FORMAT_NAME) {
    return { ok: false, error: `unrecognised format: "${file.format}" (expected "${BACKUP_FORMAT_NAME}")` }
  }
  if (typeof file.version !== 'number' || file.version > BACKUP_FORMAT_VERSION) {
    return { ok: false, error: `unsupported backup version ${file.version} (max ${BACKUP_FORMAT_VERSION})` }
  }
  if (!file.keys || typeof file.keys !== 'object') {
    return { ok: false, error: 'backup file is missing the keys block' }
  }
  if (!file.walletPubkey || typeof file.walletPubkey !== 'string') {
    return { ok: false, error: 'backup file is missing walletPubkey' }
  }
  const km = deserialize(file.keys as SerializedKeyMaterial)
  if (!km) {
    return { ok: false, error: 'backup keys block failed deserialisation (corrupt or wrong version)' }
  }
  return {
    ok: true,
    keys: km,
    walletPubkey: file.walletPubkey,
    paymentAddress: file.paymentAddress ?? km.paymentAddress,
    createdAt: file.createdAt ?? '',
  }
}

// ── Backup-acknowledgement gate (per-wallet flag in IndexedDB) ──────────
//
// "Has this user explicitly acknowledged the backup risk?" — flag stored
// in the same IndexedDB so the gate doesn't reappear after a refresh.
// Cleared by `clearCachedKeys` (Reset cached keys) so the gate re-shows
// after a deliberate wipe.

async function withAckStore<T>(mode: IDBTransactionMode, fn: (store: IDBObjectStore) => Promise<T> | T): Promise<T> {
  // ACK_STORE is created in `openDb`'s onupgradeneeded at DB v2, so by
  // the time we get here the store always exists. Same shape as
  // `withStore` for the keys store — symmetric.
  const db = await openDb()
  return new Promise<T>((resolve, reject) => {
    const tx = db.transaction(ACK_STORE, mode)
    const store = tx.objectStore(ACK_STORE)
    Promise.resolve(fn(store)).then((v) => {
      tx.oncomplete = () => resolve(v)
      tx.onerror = () => reject(tx.error || new Error('IDB tx error'))
    }).catch((err) => { try { tx.abort() } catch {}; reject(err) })
  })
}

/// Persist that the user has acknowledged the backup risk for this
/// wallet. Returns `true` on success, `false` on storage failure (in
/// which case we just don't gate — better UX than blocking on a
/// flaky IndexedDB).
export async function setBackupAcknowledged(walletPubkey: string): Promise<boolean> {
  if (!isAvailable()) return false
  try {
    await withAckStore('readwrite', (store) => idbPut(store, walletPubkey, {
      acknowledged_at: new Date().toISOString(),
    }))
    return true
  } catch (err) {
    // eslint-disable-next-line no-console
    console.warn('[private-pool-v2 cache] setBackupAcknowledged failed:', err)
    return false
  }
}

/// Has this wallet acknowledged the backup risk in a previous session?
/// Default: `false`. Returns `false` on storage failure too — that
/// means the gate shows again, not that we silently let users through.
export async function hasBackupAcknowledged(walletPubkey: string): Promise<boolean> {
  if (!isAvailable()) return false
  try {
    const entry = await withAckStore('readonly', (store) =>
      idbGet<{ acknowledged_at: string }>(store, walletPubkey),
    )
    return !!entry?.acknowledged_at
  } catch {
    return false
  }
}

/// Wipe the cached keys for a given wallet (invoked from a "Reset keys"
/// button in Settings, or after a security incident, or "forgot PIN"
/// recovery flow). The wallet signature can always be re-derive the
/// keys; the cache is just a UX nicety.
///
/// Also clears: in-memory unlock state, lock-interval preference,
/// backup acknowledgement (so user re-confirms the backup gate after
/// Reset, never silently-skipping).
export async function clearCachedKeys(walletPubkey: string): Promise<void> {
  if (!isAvailable()) return
  try {
    await withStore('readwrite', (store) => idbDelete(store, walletPubkey))
    await withAckStore('readwrite', (store) => idbDelete(store, walletPubkey))
    // Wipe the in-memory unlock state too — if the user clicks Reset
    // while a PIN-protected cache was unlocked, the next access should
    // see "no cache" not "unlocked-key-without-cache".
    if (unlockedForWallet === walletPubkey) lockNow()
    // Lock-interval preference is per-wallet; reset to default by
    // removing the localStorage key.
    if (typeof localStorage !== 'undefined') {
      localStorage.removeItem(LS_LOCK_INTERVAL_PREFIX + walletPubkey)
    }
  } catch (err) {
    // eslint-disable-next-line no-console
    console.warn('[private-pool-v2 cache] clearCachedKeys failed:', err)
  }
}
