// Private Pool V2 — wallet-derived key tree (ADR-002).
//
//   root_sk      = blake2b256(walletSig)[:32]
//   spending_sk  = blake2b256(root_sk || ASCII("relai-pool-v2/spend"))
//   viewing_sk   = blake2b256(root_sk || ASCII("relai-pool-v2/view"))
//   nullifier_sk = blake2b256(root_sk || ASCII("relai-pool-v2/null"))
//
//   spending_pk  = Poseidon1(spending_sk_field) mod p   // field element used in commitments
//   viewing_pk   = X25519.public_from(viewing_sk)        // 32-byte X25519 pubkey
//
//   PaymentAddress = base58( spending_pk_bytes_BE || viewing_pk_bytes )
//
// `*_sk` is the raw 32-byte blake2b output. `*_sk_field` is the same
// bytes reduced mod the BN254 scalar field modulus, then re-emitted as
// a bigint suitable for Poseidon / circuit witness inputs. The two
// representations are kept side by side because:
//   - the encryption layer (ADR-003) wants raw bytes for X25519
//   - the circuit witness (Faza 1) wants field elements

import { blake2b } from '@noble/hashes/blake2b';
import { x25519 } from '@noble/curves/ed25519';
import { buildPoseidon } from 'circomlibjs';
import bs58 from 'bs58';

const FIELD_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const TEXT_ENCODER = new TextEncoder();
const LABELS = {
  spending: TEXT_ENCODER.encode('relai-pool-v2/spend'),
  viewing: TEXT_ENCODER.encode('relai-pool-v2/view'),
  nullifier: TEXT_ENCODER.encode('relai-pool-v2/null'),
} as const;

const PAYMENT_ADDRESS_BYTES = 64; // spending_pk(32) + viewing_pk(32)

// ── Hash helpers ─────────────────────────────────────────────────────────

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, p) => sum + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function ensureBytes(label: string, bytes: Uint8Array, expected: number): void {
  if (bytes.length !== expected) {
    throw new Error(`${label}: expected ${expected} bytes, got ${bytes.length}`);
  }
}

/// 32-byte BE → bigint (reduced mod BN254 scalar field).
export function bytesToFieldBE(bytes: Uint8Array): bigint {
  if (bytes.length === 0) return 0n;
  let v = 0n;
  for (const b of bytes) v = (v << 8n) + BigInt(b);
  return ((v % FIELD_MODULUS) + FIELD_MODULUS) % FIELD_MODULUS;
}

/// bigint → 32-byte BE buffer. Throws if the bigint exceeds 256 bits
/// (shouldn't happen for field elements, but worth being explicit).
export function fieldToBytes32BE(value: bigint): Uint8Array {
  if (value < 0n) {
    value = ((value % FIELD_MODULUS) + FIELD_MODULUS) % FIELD_MODULUS;
  }
  const hex = value.toString(16).padStart(64, '0');
  if (hex.length > 64) {
    throw new Error(`fieldToBytes32BE: value exceeds 32 bytes (${hex.length / 2})`);
  }
  return Uint8Array.from(Buffer.from(hex, 'hex'));
}

// ── Poseidon singleton ───────────────────────────────────────────────────

let poseidonInstance: ReturnType<typeof buildPoseidon> extends Promise<infer T> ? T | null : never = null;
async function getPoseidon() {
  if (!poseidonInstance) {
    poseidonInstance = await buildPoseidon();
  }
  return poseidonInstance!;
}

/// Poseidon-Bn254X5 of one field input → bigint mod p.
export async function poseidon1(input: bigint): Promise<bigint> {
  // circomlibjs has no published .d.ts so the `buildPoseidon` return is
  // typed as `unknown` upstream. The runtime shape is well-known and
  // stable; cast to `any` for the call sites.
  const p = (await getPoseidon()) as any;
  const h = p([input]);
  return ((BigInt(p.F.toString(h)) % FIELD_MODULUS) + FIELD_MODULUS) % FIELD_MODULUS;
}

// ── Sub-key derivation ───────────────────────────────────────────────────

/// `root_sk = blake2b256(walletSig)[:32]`. The wallet signature is
/// produced off-screen by signing the canonical challenge message
/// (`PRIVATE_POOL_V2_KEY_CHALLENGE`) — the caller is expected to handle
/// the wallet popup itself.
export function deriveRootSk(walletSignature: Uint8Array): Uint8Array {
  if (!walletSignature || walletSignature.length === 0) {
    throw new Error('deriveRootSk: walletSignature must be non-empty');
  }
  return blake2b(walletSignature, { dkLen: 32 });
}

/// `<sub_sk> = blake2b256(root_sk || label)`.
export function deriveSubkey(rootSk: Uint8Array, label: Uint8Array): Uint8Array {
  ensureBytes('rootSk', rootSk, 32);
  return blake2b(concatBytes(rootSk, label), { dkLen: 32 });
}

export type PrivatePoolKeyMaterial = {
  /// Raw 32-byte blake2b sub-keys.
  rootSk: Uint8Array;
  spendingSk: Uint8Array;
  viewingSk: Uint8Array;
  nullifierSk: Uint8Array;
  /// Field-element views of the spending/nullifier secrets — what the
  /// circuit witness consumes. spending_sk_field / nullifier_sk_field
  /// are `bytesToFieldBE(spendingSk)` etc.
  spendingSkField: bigint;
  nullifierSkField: bigint;
  /// Public counterparts.
  spendingPkField: bigint;        // Poseidon1(spendingSkField)
  viewingPk: Uint8Array;          // X25519.public(viewingSk)
  /// Encoded payment address, base58( spending_pk_bytes || viewing_pk_bytes ).
  paymentAddress: string;
};

/// One-shot key derivation. Returns the full sub-key tree + payment
/// address. Idempotent; safe to re-run on every page load.
export async function derivePrivatePoolKeys(
  walletSignature: Uint8Array,
): Promise<PrivatePoolKeyMaterial> {
  const rootSk = deriveRootSk(walletSignature);
  const spendingSk = deriveSubkey(rootSk, LABELS.spending);
  const viewingSk = deriveSubkey(rootSk, LABELS.viewing);
  const nullifierSk = deriveSubkey(rootSk, LABELS.nullifier);

  const spendingSkField = bytesToFieldBE(spendingSk);
  const nullifierSkField = bytesToFieldBE(nullifierSk);
  const spendingPkField = await poseidon1(spendingSkField);
  const viewingPk = x25519.getPublicKey(viewingSk);

  const paymentAddress = encodePaymentAddress(spendingPkField, viewingPk);

  return {
    rootSk,
    spendingSk,
    viewingSk,
    nullifierSk,
    spendingSkField,
    nullifierSkField,
    spendingPkField,
    viewingPk,
    paymentAddress,
  };
}

// ── F2: code-derived key material (private payment codes) ──────────────
//
// A one-time `code_seed` (32 bytes) deterministically generates the
// same key tree as a wallet signature would. The seed plays exactly
// the role of `walletSignature` in `derivePrivatePoolKeys` — same
// blake2b labels, same Poseidon derivation, same X25519 viewing key.
//
// Why we reuse the existing tree shape:
//   - The credit-pool leaf binds `owner_pk = spending_pk_field`.
//     Whatever generates `spending_sk_field` and lets us compute its
//     Poseidon-1 image works as a "recipient identity." The wallet
//     case derives via signature; the bearer-code case derives via
//     seed. Same circuit, same prover, same on-chain verifier.
//   - The encrypted note blob is keyed by `viewing_pk` (X25519). The
//     redeemer needs to derive the matching `viewing_sk` from the
//     same seed at redeem time.
//
// Why this is safe:
//   - The seed is generated client-side and never leaves the issuer's
//     device (except via the URL/QR they hand to the redeemer).
//   - Anyone with the seed can re-derive all keys and cash out the
//     parked leaf. That's exactly the bearer-token semantics we want.
//   - The seed is large enough (32 bytes = 256 bits) that brute-force
//     guessing the seed of a specific leaf is not feasible.
//
// Important difference from `derivePrivatePoolKeys`:
//   - No `paymentAddress` is computed — the seed itself encodes both
//     halves of the addressing, and we don't want to leak a payment
//     address that ties the code to a long-lived identity.

/// Two seed formats, picked by the issuer per code:
///
///   • `long` (default; 32B / 256-bit)
///     - Encoded as base58 in URL fragment (~44 chars).
///     - Astronomically brute-force resistant. Industry-standard for
///       "fire and forget" bearer tokens.
///     - Hard to dictate by voice/SMS — must be shared as URL/QR.
///
///   • `short` (16-char Wi-Fi-style base32, 80-bit)
///     - Encoded as `XXXX-XXXX-XXXX-XXXX` for easy reading.
///     - ~80 bits of entropy. At 10⁹ hashes/s a single specific code
///       takes ≈ 38,000 years to brute-force; the on-chain leaf set
///       gates each guess by Poseidon-derived owner_pk lookup, so
///       practical attack cost is much higher. Comfortable for typical
///       consumer amounts; we'd recommend `long` for institutional /
///       very high value.
///     - Can be dictated, written on paper, typed into a separate
///       device — same UX feel as a Wi-Fi password.
///
/// Both share the SAME key-derivation algorithm — we just hand
/// `deriveRootSk` a different number of entropy bytes. The on-chain
/// proof is identical for both formats; format choice is purely an
/// issuer-side UX dial.
const LONG_SEED_BYTES = 32;
const SHORT_SEED_BYTES = 10; // 10 × 8 = 80 bits, encodes as 16 base32 chars

export type CodeSeedFormat = 'short' | 'long';

export type CodeKeyMaterial = {
  /// Raw seed; the only thing the issuer must guard + later share.
  /// 10 bytes for `short`, 32 bytes for `long`. The on-chain derivation
  /// works identically either way (blake2b is variable-input).
  codeSeed: Uint8Array;
  /// Which format the seed was generated as. Lets callers re-encode
  /// the same seed back to the right surface (base32 vs base58)
  /// without recomputing entropy.
  format: CodeSeedFormat;
  /// Key tree, identical shape to wallet-derived material.
  rootSk: Uint8Array;
  spendingSk: Uint8Array;
  viewingSk: Uint8Array;
  nullifierSk: Uint8Array;
  spendingSkField: bigint;
  nullifierSkField: bigint;
  spendingPkField: bigint;
  viewingPk: Uint8Array;
};

/// Generate a fresh code seed using a CSPRNG. The issuer holds this
/// locally (in IndexedDB if they want cancel capability) and shares
/// it out-of-band — usually as part of a URL fragment so it never
/// touches the server.
///
/// `format` defaults to `'long'` for safety. Callers wanting the
/// dictatable Wi-Fi-style format pass `'short'` explicitly.
export function generateCodeSeed(format: CodeSeedFormat = 'long'): Uint8Array {
  const bytes = format === 'short' ? SHORT_SEED_BYTES : LONG_SEED_BYTES;
  const out = new Uint8Array(bytes);
  // `crypto` is the same global the rest of the SDK uses for
  // blinding randomness; available in both browser and Node ≥ 19.
  crypto.getRandomValues(out);
  return out;
}

/// Detect the format of an existing seed by its length. Useful when a
/// caller has the bytes but not the format flag (e.g. after re-deriving
/// from a decoded code).
export function detectCodeSeedFormat(codeSeed: Uint8Array): CodeSeedFormat {
  if (codeSeed.length === SHORT_SEED_BYTES) return 'short';
  if (codeSeed.length === LONG_SEED_BYTES) return 'long';
  throw new Error(
    `detectCodeSeedFormat: unsupported seed length ${codeSeed.length} (expected ${SHORT_SEED_BYTES} or ${LONG_SEED_BYTES})`,
  );
}

/// Deterministic key derivation from a code seed. Same algorithm as
/// the wallet-derived path; the only difference is the entropy source
/// (seed vs wallet signature). Idempotent — calling it twice with the
/// same seed yields exactly the same key material.
///
/// Accepts both short (10-byte) and long (32-byte) seeds; the
/// `blake2b(seed)` rooting step doesn't care about input length, and
/// downstream derivation is identical.
export async function deriveCodeKeys(
  codeSeed: Uint8Array,
): Promise<CodeKeyMaterial> {
  if (!codeSeed) {
    throw new Error('deriveCodeKeys: codeSeed required');
  }
  if (codeSeed.length !== SHORT_SEED_BYTES && codeSeed.length !== LONG_SEED_BYTES) {
    throw new Error(
      `deriveCodeKeys: codeSeed must be ${SHORT_SEED_BYTES} or ${LONG_SEED_BYTES} bytes (got ${codeSeed.length})`,
    );
  }
  const format: CodeSeedFormat = codeSeed.length === SHORT_SEED_BYTES ? 'short' : 'long';
  const rootSk = deriveRootSk(codeSeed);
  const spendingSk = deriveSubkey(rootSk, LABELS.spending);
  const viewingSk = deriveSubkey(rootSk, LABELS.viewing);
  const nullifierSk = deriveSubkey(rootSk, LABELS.nullifier);

  const spendingSkField = bytesToFieldBE(spendingSk);
  const nullifierSkField = bytesToFieldBE(nullifierSk);
  const spendingPkField = await poseidon1(spendingSkField);
  const viewingPk = x25519.getPublicKey(viewingSk);

  return {
    codeSeed,
    format,
    rootSk,
    spendingSk,
    viewingSk,
    nullifierSk,
    spendingSkField,
    nullifierSkField,
    spendingPkField,
    viewingPk,
  };
}

// ── F2: code-seed codec for URLs (Bech32-style) ────────────────────────
//
// We encode the 32B seed as base58 — same alphabet the SDK already uses
// for the payment address, no new dependencies, ~44 ASCII chars. The
// short fixed length lets us validate decoded seeds with a single
// length check. A Bech32 checksum is overkill at this size (a typo
// would already fail the field-element derivation at park-redeem time,
// just less helpfully) — kept simple to reduce dependency surface.

/// Encode a 32B "long" seed for URL / QR transport. Result is base58
/// of the raw seed bytes — no version byte, no checksum. The caller
/// is expected to put this in the URL fragment (`#seed=…`) so it never
/// hits server logs.
export function encodeCodeSeed(seed: Uint8Array): string {
  if (!seed || seed.length !== LONG_SEED_BYTES) {
    throw new Error(
      `encodeCodeSeed: seed must be exactly ${LONG_SEED_BYTES} bytes (got ${seed?.length ?? 0})`,
    );
  }
  const encoder = (bs58 as { encode?: (b: Uint8Array) => string }).encode
    ?? (bs58 as { default?: { encode: (b: Uint8Array) => string } }).default?.encode;
  if (!encoder) {
    throw new Error('encodeCodeSeed: bs58 encoder missing — incompatible bs58 version');
  }
  return encoder(seed);
}

/// Inverse of `encodeCodeSeed`. Throws on malformed input (wrong
/// length, non-base58 chars). The caller may want to wrap this in a
/// try/catch to surface a user-friendly "invalid code" error.
export function decodeCodeSeed(encoded: string): Uint8Array {
  if (typeof encoded !== 'string' || encoded.length === 0) {
    throw new Error('decodeCodeSeed: input must be a non-empty string');
  }
  const decoder = (bs58 as { decode?: (s: string) => Uint8Array }).decode
    ?? (bs58 as { default?: { decode: (s: string) => Uint8Array } }).default?.decode;
  if (!decoder) {
    throw new Error('decodeCodeSeed: bs58 decoder missing — incompatible bs58 version');
  }
  const out = decoder(encoded);
  if (out.length !== LONG_SEED_BYTES) {
    throw new Error(
      `decodeCodeSeed: decoded ${out.length} bytes, expected ${LONG_SEED_BYTES}`,
    );
  }
  return out;
}

// ── Short-code (Wi-Fi-style base32) codec ──────────────────────────────
//
// 10 bytes → 16 base32 characters → rendered as `XXXX-XXXX-XXXX-XXXX`.
// RFC 4648 base32 alphabet (`A-Z2-7`) is deliberately confusion-free —
// no 0/O, 1/I/l ambiguity. Issuer can dictate the code over the phone
// without losing 25 minutes to "is that an O or zero" rounds. Dashes
// are decorative; the decoder strips them.
//
// Why base32 over base58 here:
//   • 5 bits per character → fixed 16-char output for 80 bits, with
//     no awkward "≈ 14 chars" rounding.
//   • Voice-friendly alphabet.
//   • Dashes optional in the input — we tolerate either form.

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function encodeBase32(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 0x1f];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += BASE32_ALPHABET[(value << (5 - bits)) & 0x1f];
  }
  return out;
}

function decodeBase32(s: string): Uint8Array {
  // Normalise: uppercase, drop dashes/whitespace, validate alphabet.
  const cleaned = s.toUpperCase().replace(/[\s-]/g, '');
  if (cleaned.length === 0) throw new Error('decodeBase32: empty input');
  for (const ch of cleaned) {
    if (BASE32_ALPHABET.indexOf(ch) === -1) {
      throw new Error(`decodeBase32: illegal character '${ch}' (allowed: A-Z, 2-7)`);
    }
  }
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of cleaned) {
    value = (value << 5) | BASE32_ALPHABET.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Uint8Array.from(out);
}

/// Format a raw 10-byte seed into the user-facing
/// `XXXX-XXXX-XXXX-XXXX` representation. Round-trip with
/// `decodeShortCode` is exact.
export function encodeShortCode(seed: Uint8Array): string {
  if (!seed || seed.length !== SHORT_SEED_BYTES) {
    throw new Error(
      `encodeShortCode: seed must be exactly ${SHORT_SEED_BYTES} bytes (got ${seed?.length ?? 0})`,
    );
  }
  const flat = encodeBase32(seed); // 16 chars
  // Insert a hyphen every 4 chars for readability. `XXXX-XXXX-XXXX-XXXX`.
  return flat.match(/.{1,4}/g)!.join('-');
}

/// Inverse of `encodeShortCode`. Accepts the canonical
/// `XXXX-XXXX-XXXX-XXXX` form, plain `XXXXXXXXXXXXXXXX`, lower-case,
/// or any combination with extra whitespace — anything a user might
/// dictate or paste with mild messiness. Throws on illegal characters
/// or wrong length.
export function decodeShortCode(encoded: string): Uint8Array {
  if (typeof encoded !== 'string') {
    throw new Error('decodeShortCode: input must be a string');
  }
  const out = decodeBase32(encoded);
  if (out.length !== SHORT_SEED_BYTES) {
    throw new Error(
      `decodeShortCode: decoded ${out.length} bytes, expected ${SHORT_SEED_BYTES} (16 base32 chars)`,
    );
  }
  return out;
}

/// Auto-detect the format of an encoded code string and return the raw
/// seed bytes. Convenience for redeem flows that accept either format
/// from a single text input.
///
/// Detection rules:
///   • Strip whitespace + dashes. If the result is exactly 16 chars in
///     the base32 alphabet → short code, decoded as such.
///   • Otherwise try base58 → 32-byte long seed.
///   • Anything else → throw with a hint.
export function decodeCodeAuto(encoded: string): {
  seed: Uint8Array;
  format: CodeSeedFormat;
} {
  if (typeof encoded !== 'string' || encoded.trim().length === 0) {
    throw new Error('decodeCodeAuto: empty input');
  }
  const cleaned = encoded.trim();
  const base32Cleaned = cleaned.toUpperCase().replace(/[\s-]/g, '');
  // Short code: exactly 16 base32 chars.
  if (
    base32Cleaned.length === 16
    && [...base32Cleaned].every((c) => BASE32_ALPHABET.indexOf(c) !== -1)
  ) {
    return { seed: decodeShortCode(cleaned), format: 'short' };
  }
  // Otherwise assume base58 long. The base58 decoder will throw if
  // the alphabet doesn't match.
  try {
    return { seed: decodeCodeSeed(cleaned), format: 'long' };
  } catch (err) {
    throw new Error(
      `decodeCodeAuto: not a valid short (16 char) or long (~44 char) code: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

// ── Payment address codec ────────────────────────────────────────────────

/// `base58(spending_pk_bytes_BE || viewing_pk_bytes)` — the human-shareable
/// "send notes to me" handle. 64 bytes encoded → ~88 base58 chars.
export function encodePaymentAddress(spendingPkField: bigint, viewingPk: Uint8Array): string {
  ensureBytes('viewingPk', viewingPk, 32);
  const spendingPkBytes = fieldToBytes32BE(spendingPkField);
  const concat = concatBytes(spendingPkBytes, viewingPk);
  // bs58@4: bs58.encode(buffer)
  // bs58@5+: bs58.default.encode(buffer)
  const encoder = (bs58 as { encode?: (b: Uint8Array) => string }).encode
    ?? (bs58 as { default?: { encode: (b: Uint8Array) => string } }).default?.encode;
  if (!encoder) throw new Error('encodePaymentAddress: bs58.encode not found');
  return encoder(concat);
}

export function parsePaymentAddress(address: string): {
  spendingPkField: bigint;
  viewingPk: Uint8Array;
} {
  const decoder = (bs58 as { decode?: (s: string) => Uint8Array }).decode
    ?? (bs58 as { default?: { decode: (s: string) => Uint8Array } }).default?.decode;
  if (!decoder) throw new Error('parsePaymentAddress: bs58.decode not found');
  const decoded = decoder(address);
  if (decoded.length !== PAYMENT_ADDRESS_BYTES) {
    throw new Error(
      `parsePaymentAddress: decoded length ${decoded.length} != ${PAYMENT_ADDRESS_BYTES}`,
    );
  }
  return {
    spendingPkField: bytesToFieldBE(decoded.slice(0, 32)),
    viewingPk: decoded.slice(32, 64),
  };
}

// ── Wallet challenge ─────────────────────────────────────────────────────

/// Canonical challenge message the wallet signs to derive the root_sk.
/// Versioned + namespaced so a sig made for V2 can never be reused for
/// any other RelAI feature (or any other app's "sign this" flow).
export const PRIVATE_POOL_V2_KEY_CHALLENGE =
  'RelAI Private Pool V2 — derive private balance keys.\n\nThis signature unlocks your hidden-amount balance under the /app/private surface. It does NOT authorize any spend on its own.';

/// Build the wallet challenge bytes for `signMessage` (UTF-8 of the
/// human-readable challenge above; matches what the on-screen prompt
/// will display).
export function buildKeyChallengeMessage(): Uint8Array {
  return TEXT_ENCODER.encode(PRIVATE_POOL_V2_KEY_CHALLENGE);
}
