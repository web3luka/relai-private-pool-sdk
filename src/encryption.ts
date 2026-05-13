// Private Pool V2 — encrypted note format (ADR-003).
//
//   ChaCha20-Poly1305 AEAD
//   X25519 ephemeral key agreement → HKDF-SHA256(shared, salt, info=commitment)
//   nonce = blake2b256(eph_pk || commitment)[:12]
//   AAD   = commitment (32 bytes)
//
// Plaintext layout (memo-less, 80 bytes):
//   0..8    value     (u64 LE, micro-USDC)
//   8..40   blinding  (32 bytes BE)
//   40..72  owner_pk  (32 bytes BE)
//   72      memo flag (0x00)
//   73..80  zero pad
//
// Plaintext layout (with memo, 112 bytes): same as above but
//   72      memo flag (0x01)
//   80..112 memo (32 bytes)
//
// On-chain `EncryptedNoteBlobAccount`:
//   - ephemeral_pk: 32 bytes (separate field)
//   - ciphertext:   96 or 128 bytes (Vec<u8>) — plaintext + 16-byte Poly1305 tag
//
// Conformance vectors: see `frontend/src/__tests__/private-pool-encryption.test.ts`.

import { chacha20poly1305 } from '@noble/ciphers/chacha';
import { x25519 } from '@noble/curves/ed25519';
import { hkdf } from '@noble/hashes/hkdf';
import { blake2b } from '@noble/hashes/blake2b';
import { sha256 } from '@noble/hashes/sha2';

const HKDF_SALT = new TextEncoder().encode('RelAI PrivatePool v2 note key');
const NONCE_LEN = 12;
const TAG_LEN = 16;

// Plaintext layouts (legacy ADR-003 only — stealth was withdrawn,
// see ADR-008 postmortem):
//   80B  no memo:   value(8) + blinding(32) + owner_pk(32) + flag=0(1) + 7B pad
//   112B with memo: above + 32B memo at offset 80, flag=1
const PLAINTEXT_NO_MEMO = 80;
const PLAINTEXT_WITH_MEMO = 112;
const CIPHERTEXT_NO_MEMO = PLAINTEXT_NO_MEMO + TAG_LEN; // 96
const CIPHERTEXT_WITH_MEMO = PLAINTEXT_WITH_MEMO + TAG_LEN; // 128

const EPHEMERAL_PK_LEN = 32;
const COMMITMENT_LEN = 32;

export const PRIVATE_POOL_NOTE_BYTES = {
  PLAINTEXT_NO_MEMO,
  PLAINTEXT_WITH_MEMO,
  CIPHERTEXT_NO_MEMO,
  CIPHERTEXT_WITH_MEMO,
  EPHEMERAL_PK_LEN,
  COMMITMENT_LEN,
  NONCE_LEN,
  TAG_LEN,
} as const;

export type NoteLayout = 'legacy';

export type DecryptedNote = {
  value: bigint;
  blinding: Uint8Array; // 32 bytes BE
  ownerPk: Uint8Array; // 32 bytes BE — recipient's master spending_pk
  memo: Uint8Array | null; // 32 bytes when present, null otherwise
  /// Always `null` in V1 (stealth withdrawn — see ADR-008 postmortem).
  /// Field kept on the type so callers don't have to branch on a
  /// missing property; the encryption layer enforces null.
  stealthNonce: null;
  /// Always `'legacy'` in V1.
  layout: NoteLayout;
};

// ── Plaintext (de)serialisation ──────────────────────────────────────────

function ensureLen(label: string, bytes: Uint8Array, expected: number): void {
  if (bytes.length !== expected) {
    throw new Error(`${label}: expected ${expected} bytes, got ${bytes.length}`);
  }
}

/// Pack a `DecryptedNote` to its on-chain plaintext bytes.
///
/// Layout selection (auto):
///   - `stealthNonce: null, memo: null` → 80B legacy (ADR-003 v1)
///   - `memo: null` → 80B (no memo)
///   - `memo: Uint8Array` → 112B (with memo)
export function serializeNotePlaintext(note: DecryptedNote): Uint8Array {
  ensureLen('blinding', note.blinding, 32);
  ensureLen('ownerPk', note.ownerPk, 32);
  if (note.memo) ensureLen('memo', note.memo, 32);

  const isWithMemo = !!note.memo;
  const len = isWithMemo ? PLAINTEXT_WITH_MEMO : PLAINTEXT_NO_MEMO;
  const out = new Uint8Array(len);

  const view = new DataView(out.buffer, out.byteOffset, 8);
  view.setBigUint64(0, note.value, true);
  out.set(note.blinding, 8);
  out.set(note.ownerPk, 40);
  out[72] = isWithMemo ? 0x01 : 0x00;
  if (isWithMemo) out.set(note.memo!, 80);
  return out;
}

/// Inverse of `serializeNotePlaintext`. Throws on malformed inputs.
export function parseNotePlaintext(plaintext: Uint8Array): DecryptedNote {
  const view = new DataView(plaintext.buffer, plaintext.byteOffset, plaintext.byteLength);
  const flag = plaintext.length >= 73 ? plaintext[72] : 0xff;

  if (plaintext.length === PLAINTEXT_NO_MEMO && flag === 0x00) {
    return {
      value: view.getBigUint64(0, true),
      blinding: plaintext.slice(8, 40),
      ownerPk: plaintext.slice(40, 72),
      memo: null,
      stealthNonce: null,
      layout: 'legacy',
    };
  }
  if (plaintext.length === PLAINTEXT_WITH_MEMO && flag === 0x01) {
    return {
      value: view.getBigUint64(0, true),
      blinding: plaintext.slice(8, 40),
      ownerPk: plaintext.slice(40, 72),
      memo: plaintext.slice(80, 112),
      stealthNonce: null,
      layout: 'legacy',
    };
  }
  throw new Error(
    `note plaintext: unrecognized layout (length ${plaintext.length}, memo flag ${flag.toString(16)})`,
  );
}

// ── Key agreement ────────────────────────────────────────────────────────

/// HKDF-SHA256 with ADR-003 salt + commitment-as-info → 32-byte key.
function deriveSymmetricKey(sharedSecret: Uint8Array, commitment: Uint8Array): Uint8Array {
  return hkdf(sha256, sharedSecret, HKDF_SALT, commitment, 32);
}

/// `nonce = blake2b256(eph_pk || commitment)[:12]`.
function deriveNonce(ephemeralPk: Uint8Array, commitment: Uint8Array): Uint8Array {
  ensureLen('ephemeralPk', ephemeralPk, EPHEMERAL_PK_LEN);
  ensureLen('commitment', commitment, COMMITMENT_LEN);
  const concat = new Uint8Array(ephemeralPk.length + commitment.length);
  concat.set(ephemeralPk, 0);
  concat.set(commitment, ephemeralPk.length);
  // dkLen 32 default; we slice the first 12 bytes for the AEAD nonce.
  return blake2b(concat, { dkLen: 32 }).slice(0, NONCE_LEN);
}

// ── Encrypt / decrypt ────────────────────────────────────────────────────

export type EncryptedNoteBlob = {
  /// X25519 ephemeral pubkey published with the blob. Pure scalar mult,
  /// reveals nothing about the recipient.
  ephemeralPk: Uint8Array; // 32 bytes
  /// Plaintext + Poly1305 tag (96 or 128 bytes total).
  ciphertext: Uint8Array;
  /// Mirrors the on-chain commitment for AAD binding.
  commitment: Uint8Array; // 32 bytes
};

export type EncryptArgs = {
  /// Plaintext note to encrypt — recipient's ownerPk + (optional)
  /// `stealthNonce` are committed to inside.
  note: DecryptedNote;
  /// Recipient's X25519 viewing-key pubkey (per ADR-002).
  recipientViewingPk: Uint8Array; // 32 bytes
  /// Note commitment (Poseidon4 of value/owner_pk/blinding/memo). Used as
  /// AEAD AAD + HKDF info — binds the ciphertext to a single commitment.
  commitment: Uint8Array; // 32 bytes
  /// Optional ephemeral keypair override (for deterministic test vectors).
  /// Production code generates fresh randomness per note.
  ephemeralKeypairOverride?: { sk: Uint8Array; pk: Uint8Array };
};

/// Encrypt a note for a recipient. Returns the publishable blob fields.
///
/// Domain-separation guarantees:
///   - HKDF info=commitment makes the AEAD key unique per note (a leak
///     of one key doesn't cascade)
///   - AAD=commitment makes the ciphertext non-portable (can't be moved
///     to a different commitment without breaking decryption)
///   - Deterministic nonce (eph_pk + commitment) avoids the catastrophic
///     "weak browser entropy" path; uniqueness is by construction since
///     ephemeral_pk is fresh per call.
export function encryptNote(args: EncryptArgs): EncryptedNoteBlob {
  ensureLen('recipientViewingPk', args.recipientViewingPk, 32);
  ensureLen('commitment', args.commitment, COMMITMENT_LEN);

  let ephSk: Uint8Array;
  let ephPk: Uint8Array;
  if (args.ephemeralKeypairOverride) {
    ephSk = args.ephemeralKeypairOverride.sk;
    ephPk = args.ephemeralKeypairOverride.pk;
    ensureLen('ephemeralKeypairOverride.sk', ephSk, 32);
    ensureLen('ephemeralKeypairOverride.pk', ephPk, 32);
  } else {
    ephSk = x25519.utils.randomPrivateKey();
    ephPk = x25519.getPublicKey(ephSk);
  }

  const sharedSecret = x25519.getSharedSecret(ephSk, args.recipientViewingPk);
  const key = deriveSymmetricKey(sharedSecret, args.commitment);
  const nonce = deriveNonce(ephPk, args.commitment);

  const plaintext = serializeNotePlaintext(args.note);
  const cipher = chacha20poly1305(key, nonce, args.commitment);
  const ciphertext = cipher.encrypt(plaintext);

  if (
    ciphertext.length !== CIPHERTEXT_NO_MEMO
    && ciphertext.length !== CIPHERTEXT_WITH_MEMO
  ) {
    throw new Error(`encryptNote: unexpected ciphertext length ${ciphertext.length}`);
  }
  return {
    ephemeralPk: ephPk,
    ciphertext,
    commitment: args.commitment,
  };
}

/// Try to decrypt a blob with the given viewing secret. Returns the note
/// when the auth tag verifies, or `null` when it doesn't (i.e. "this
/// blob isn't mine"). Never throws on tag-mismatch — that's the
/// expected hot path during note discovery.
export function tryDecryptNote(args: {
  blob: EncryptedNoteBlob;
  viewingSk: Uint8Array; // 32 bytes
}): DecryptedNote | null {
  ensureLen('viewingSk', args.viewingSk, 32);
  ensureLen('blob.ephemeralPk', args.blob.ephemeralPk, 32);
  ensureLen('blob.commitment', args.blob.commitment, COMMITMENT_LEN);
  const len = args.blob.ciphertext.length;
  if (len !== CIPHERTEXT_NO_MEMO && len !== CIPHERTEXT_WITH_MEMO) {
    return null;
  }

  const sharedSecret = x25519.getSharedSecret(args.viewingSk, args.blob.ephemeralPk);
  const key = deriveSymmetricKey(sharedSecret, args.blob.commitment);
  const nonce = deriveNonce(args.blob.ephemeralPk, args.blob.commitment);
  const cipher = chacha20poly1305(key, nonce, args.blob.commitment);
  let plaintext: Uint8Array;
  try {
    plaintext = cipher.decrypt(args.blob.ciphertext);
  } catch {
    // Tag verification failed — not our blob, or corrupted.
    return null;
  }
  try {
    return parseNotePlaintext(plaintext);
  } catch {
    // Decrypted but plaintext layout is bad — bail rather than return
    // garbage. Should never happen on a well-formed blob.
    return null;
  }
}

/// Strict variant: throws on auth-tag mismatch. Use this when the
/// caller asserts the blob is theirs (e.g. after a successful trial-decrypt
/// on a different blob, this one MUST match too).
export function decryptNote(args: { blob: EncryptedNoteBlob; viewingSk: Uint8Array }): DecryptedNote {
  const out = tryDecryptNote(args);
  if (!out) throw new Error('decryptNote: ciphertext failed Poly1305 verification');
  return out;
}

// ── X25519 helpers (re-exported so callers don't import @noble directly) ─

/// Generate a fresh X25519 keypair. Used for per-note ephemerals AND
/// for the user's long-lived viewing key when initialising private balance.
export function generateX25519Keypair(): { sk: Uint8Array; pk: Uint8Array } {
  const sk = x25519.utils.randomPrivateKey();
  const pk = x25519.getPublicKey(sk);
  return { sk, pk };
}

/// Derive an X25519 viewing pubkey from a 32-byte secret. The secret
/// itself is produced by ADR-002's HKDF-from-wallet-sig path (see
/// `private-pool-keys.ts`).
export function x25519PublicFromSecret(viewingSk: Uint8Array): Uint8Array {
  ensureLen('viewingSk', viewingSk, 32);
  return x25519.getPublicKey(viewingSk);
}

