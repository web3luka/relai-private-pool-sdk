// Private Pool V2 — note discovery + ownership tracking.
//
// Recipient flow ("walk into a coffee shop, open my wallet"):
//   1. Pull every encrypted note blob from `/api/private-pool/v2/notes`.
//   2. Trial-decrypt each one with the user's `viewing_sk`.
//   3. The blobs that decrypt cleanly are the user's notes — collect them.
//   4. For each owned note, query `/api/private-pool/v2/nullifier/:n`
//      to determine spent status.
//   5. Sum unspent values for the displayed balance.
//
// Privacy properties this preserves:
//   - The server doesn't know which notes are yours (it serves every blob).
//   - The nullifier check tells the server "is this nullifier spent?"
//     without revealing whose. Each query is unlinkable IF the queries
//     are spread over time (request batching → linkability).
//   - We trial-decrypt every blob client-side; the only metadata leak is
//     network timing on the bulk fetch, which is benign because blobs
//     are public anyway.

import { tryDecryptNote, type DecryptedNote, type EncryptedNoteBlob } from './encryption';
import { poseidon1, fieldToBytes32BE } from './keys';
import { buildPoseidon } from 'circomlibjs';

const FIELD_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// ── API shapes (mirror server/src/routes/private-pool-v2.js) ────────────

export type EncryptedNoteApiBlob = {
  pda: string;
  commitment_hex: string;
  ephemeral_pk_hex: string;
  ciphertext_b64: string;
  ciphertext_len: number;
};

export type CommitmentLeafApiEntry = {
  pda: string;
  commitment_hex: string;
  commitment_decimal: string;
  leaf_index: number;
  block_slot: number;
};

export type NullifierStatusApi = {
  network: string;
  nullifier: string;
  consumed: boolean;
  used_at_slot?: number;
  pda?: string;
};

// ── Owned-note shape ─────────────────────────────────────────────────────

export type OwnedNote = DecryptedNote & {
  /// 32-byte commitment as bytes (BE field element). Mirrors the on-chain
  /// `commitment` field on `CommitmentLeafAccount`.
  commitment: Uint8Array;
  /// `0x…64-char-hex` representation of `commitment`.
  commitmentHex: string;
  /// `commitment` as a bigint reduced mod the BN254 scalar field. The
  /// circuit witness uses this form directly.
  commitmentField: bigint;
  /// Position in the merkle tree (or `null` when the indexer hasn't
  /// caught the leaf record yet — happens for ~1s after a fresh deposit).
  leafIndex: number | null;
  /// Block slot the leaf was inserted in (best-effort timestamp).
  blockSlot: number | null;
  /// Has the matching nullifier been published on chain?
  spent: boolean;
  /// When `spent === true`, the slot the nullifier landed in.
  spentAtSlot?: number;
};

// ── HTTP helpers ─────────────────────────────────────────────────────────

function buildUrl(apiBaseUrl: string, path: string, query: Record<string, string | number | undefined> = {}): string {
  const url = new URL(path, apiBaseUrl.endsWith('/') ? apiBaseUrl : apiBaseUrl + '/');
  for (const [k, v] of Object.entries(query)) {
    if (v !== undefined) url.searchParams.set(k, String(v));
  }
  return url.toString();
}

async function getJson<T>(url: string, init?: RequestInit): Promise<T> {
  const r = await fetch(url, init);
  if (!r.ok) throw new Error(`GET ${url} → ${r.status} ${await r.text()}`);
  return (await r.json()) as T;
}

/// Pull every encrypted blob the indexer has published. Filtering is
/// done client-side (we trial-decrypt each one with our viewing key).
export async function fetchEncryptedNoteBlobs(args: {
  apiBaseUrl: string;
  network: string;
  sinceSlot?: number;
}): Promise<EncryptedNoteApiBlob[]> {
  const url = buildUrl(args.apiBaseUrl, 'api/private-pool/v2/notes', {
    network: args.network,
    sinceSlot: args.sinceSlot,
  });
  const body = await getJson<{ blobs: EncryptedNoteApiBlob[] }>(url);
  return body.blobs;
}

/// Pull every commitment-leaf record (used to attach `leafIndex` to
/// each owned note). Cheap enough to call alongside the blob fetch.
export async function fetchCommitmentLeaves(args: {
  apiBaseUrl: string;
  network: string;
  since?: number;
}): Promise<CommitmentLeafApiEntry[]> {
  const url = buildUrl(args.apiBaseUrl, 'api/private-pool/v2/leaves', {
    network: args.network,
    since: args.since,
  });
  const body = await getJson<{ leaves: CommitmentLeafApiEntry[] }>(url);
  return body.leaves;
}

/// Per-note nullifier check. The server returns `consumed: true|false`.
/// Frontend should NOT batch all of these into a single request — see
/// the privacy notes at the top of this module.
///
/// Note for hot-path balance reads: prefer `fetchAllNullifiers` (one
/// round-trip + local `Set.has()`) over calling this in a Promise.all.
/// Both reach the same on-chain markers, but the batch endpoint
/// dedupes the cost across every owned note + every concurrent
/// surface loading at once.
export async function fetchNullifierStatus(args: {
  apiBaseUrl: string;
  network: string;
  nullifier: bigint | Uint8Array | string;
}): Promise<NullifierStatusApi> {
  let asString: string;
  if (typeof args.nullifier === 'bigint') {
    asString = '0x' + args.nullifier.toString(16).padStart(64, '0');
  } else if (args.nullifier instanceof Uint8Array) {
    asString = '0x' + Buffer.from(args.nullifier).toString('hex');
  } else {
    asString = String(args.nullifier);
  }
  const url = buildUrl(
    args.apiBaseUrl,
    `api/private-pool/v2/nullifier/${encodeURIComponent(asString)}`,
    { network: args.network },
  );
  return getJson<NullifierStatusApi>(url);
}

/// Pull every consumed nullifier hex in one request. Used by
/// `attachSpentStatus` to do membership checks locally — strictly
/// cheaper than N parallel hits to `/nullifier/:n` (single RPC call
/// server-side, single cache slot, no per-PDA round-trip).
///
/// Trade-off vs. the per-nullifier variant: privacy-wise, on this
/// endpoint the server still doesn't learn *which* of these
/// nullifiers belong to the caller (frontend membership-tests them
/// privately). It's strictly better than parallel /nullifier/:n
/// fetches, where the server learned the exact set of nullifiers the
/// caller wanted to check.
export async function fetchAllNullifiers(args: {
  apiBaseUrl: string;
  network: string;
}): Promise<string[]> {
  const url = buildUrl(args.apiBaseUrl, 'api/private-pool/v2/nullifiers/all', {
    network: args.network,
  });
  const body = await getJson<{ nullifiers: string[] }>(url);
  return body.nullifiers;
}

// ── Discovery primitives ─────────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  return Uint8Array.from(Buffer.from(clean, 'hex'));
}

/// Trial-decrypt a list of encrypted blobs with `viewingSk`. Returns the
/// blobs the auth tag accepts — i.e. the user's own notes. Pure (no RPC).
export function trialDecryptBlobs(args: {
  blobs: EncryptedNoteApiBlob[];
  viewingSk: Uint8Array;
  /// Optional bound — stop after this many decryptions (test/dev hook;
  /// production callers leave it undefined).
  limit?: number;
}): Array<{ blob: EncryptedNoteApiBlob; note: DecryptedNote }> {
  const out: Array<{ blob: EncryptedNoteApiBlob; note: DecryptedNote }> = [];
  for (const blob of args.blobs) {
    const ephPk = hexToBytes(blob.ephemeral_pk_hex);
    const commitment = hexToBytes(blob.commitment_hex);
    const ciphertext = Uint8Array.from(Buffer.from(blob.ciphertext_b64, 'base64'));
    const ownedBlob: EncryptedNoteBlob = { ephemeralPk: ephPk, ciphertext, commitment };
    const note = tryDecryptNote({ blob: ownedBlob, viewingSk: args.viewingSk });
    if (note) {
      out.push({ blob, note });
      if (args.limit && out.length >= args.limit) break;
    }
  }
  return out;
}

/// One-shot fetch + trial-decrypt + leaf attachment. Returns owned notes
/// without spent flags — call `attachSpentStatus` after to check chain.
///
/// `apiBaseUrl` should NOT include the trailing `/api/private-pool/v2`
/// segment — pass the host root (e.g. `https://api.relai.fi`) and this
/// helper appends the path.
export async function discoverOwnedNotes(args: {
  apiBaseUrl: string;
  network: string;
  viewingSk: Uint8Array;
}): Promise<OwnedNote[]> {
  const [blobs, leaves] = await Promise.all([
    fetchEncryptedNoteBlobs(args),
    fetchCommitmentLeaves(args),
  ]);
  const leafByCommitment = new Map<string, CommitmentLeafApiEntry>();
  for (const l of leaves) leafByCommitment.set(l.commitment_hex.toLowerCase(), l);

  const decrypted = trialDecryptBlobs({ blobs, viewingSk: args.viewingSk });
  return decrypted.map(({ blob, note }) => {
    const commitment = hexToBytes(blob.commitment_hex);
    const leaf = leafByCommitment.get(blob.commitment_hex.toLowerCase()) ?? null;
    return {
      ...note,
      commitment,
      commitmentHex: blob.commitment_hex,
      commitmentField: BigInt(leaf?.commitment_decimal ?? '0x' + blob.commitment_hex.slice(2)),
      leafIndex: leaf?.leaf_index ?? null,
      blockSlot: leaf?.block_slot ?? null,
      spent: false,
    };
  });
}

// ── Nullifier derivation + spent status ──────────────────────────────────

let cachedPoseidon: Awaited<ReturnType<typeof buildPoseidon>> | null = null;
async function getPoseidonInstance() {
  if (!cachedPoseidon) cachedPoseidon = await buildPoseidon();
  return cachedPoseidon!;
}

/// `nullifier = Poseidon2(commitment, nullifier_sk)`. Matches the
/// circuit's `NullifierHash` template. Use this off-circuit when
/// querying `fetchNullifierStatus` to check whether a note is spent.
export async function deriveNullifier(commitmentField: bigint, nullifierSkField: bigint): Promise<bigint> {
  const p = (await getPoseidonInstance()) as any;
  const h = p([commitmentField, nullifierSkField]);
  return ((BigInt(p.F.toString(h)) % FIELD_MODULUS) + FIELD_MODULUS) % FIELD_MODULUS;
}

/// Decorate `notes` with their `spent` flag by checking each nullifier
/// against the API.
///
/// Two evolutionary steps got us here:
///   1. Original sequential per-note check — privacy-by-spreading. Was
///      10-30 s of "Loading…" with a few dozen notes.
///   2. Parallel `Promise.all` of per-note `/nullifier/:n` fetches —
///      faster, but still N RPC calls server-side (and a 20-note
///      wallet × every surface reloading at once = browser
///      connection-limit pile-ups + duplicated `getProgramAccounts`
///      pressure).
///
/// Current shape: ONE request to `/nullifiers/all` returning every
/// consumed nullifier hex, then we Poseidon-derive each note's
/// nullifier locally and check membership against a `Set`. N → 1
/// round-trips; the membership check is O(N) on a Set lookup, dwarfed
/// by the network call.
///
/// Privacy: the server-side batch fetch is content-agnostic (it
/// hands back the full list regardless of caller), so it doesn't learn
/// which subset belongs to this user. Strictly better than the parallel
/// /nullifier/:n flow, where the server saw the exact set the caller
/// wanted to test.
///
/// Loss-of-detail: the per-note `spentAtSlot` field used to be
/// populated from `/nullifier/:n`. The batch endpoint omits it to keep
/// the payload tight; if a caller needs `spentAtSlot` for a specific
/// note (e.g. transaction-history reconciliation), they can call
/// `fetchNullifierStatus` for that single nullifier on-demand. The hot
/// balance-fetch path doesn't need it.
///
/// If you genuinely need the spread-over-time per-note variant (e.g.
/// a paranoid privacy-mode toggle), call `attachSpentStatusSequential`
/// below.
export async function attachSpentStatus(args: {
  apiBaseUrl: string;
  network: string;
  notes: OwnedNote[];
  nullifierSkField: bigint;
}): Promise<OwnedNote[]> {
  // Fetch all consumed nullifiers + derive ours in parallel (the
  // Poseidon hashes are independent of the network round-trip, so
  // there's no reason to wait for one before the other).
  const [consumedHex, ownedNullifierHex] = await Promise.all([
    fetchAllNullifiers({ apiBaseUrl: args.apiBaseUrl, network: args.network }).catch((): string[] => []),
    Promise.all(
      args.notes.map(async (n) => {
        const nullifier = await deriveNullifier(n.commitmentField, args.nullifierSkField);
        return '0x' + nullifier.toString(16).padStart(64, '0');
      }),
    ),
  ])
  // Normalise to lowercase so the membership check isn't bitten by
  // 0xAbCd vs 0xabcd casing drift between client and server.
  const consumedSet = new Set(consumedHex.map((h) => h.toLowerCase()))
  return args.notes.map((note, i) => ({
    ...note,
    spent: consumedSet.has(ownedNullifierHex[i].toLowerCase()),
  }))
}

/// Sequential variant — kept for callers who want the original
/// privacy-conscious behaviour (one nullifier check per note, spread
/// over time). Slow with N > 10 notes; do not use on UI hot paths.
export async function attachSpentStatusSequential(args: {
  apiBaseUrl: string;
  network: string;
  notes: OwnedNote[];
  nullifierSkField: bigint;
}): Promise<OwnedNote[]> {
  const out: OwnedNote[] = [];
  for (const note of args.notes) {
    const nullifier = await deriveNullifier(note.commitmentField, args.nullifierSkField);
    try {
      const status = await fetchNullifierStatus({
        apiBaseUrl: args.apiBaseUrl,
        network: args.network,
        nullifier,
      });
      out.push({ ...note, spent: status.consumed, spentAtSlot: status.used_at_slot });
    } catch {
      out.push({ ...note });
    }
  }
  return out;
}

/// Sum `value` across every unspent note. Returns micro-USDC bigint.
/// Caller divides by 10^6 for human display.
export function totalUnspentBalance(notes: OwnedNote[]): bigint {
  return notes.reduce((sum, n) => (n.spent ? sum : sum + n.value), 0n);
}

/// Same shape as `totalUnspentBalance` but breaks down per memo-tag
/// (handy for receipts / reconciliation).
export function balanceBreakdown(notes: OwnedNote[]): {
  totalMicroUsdc: bigint;
  unspentCount: number;
  spentCount: number;
} {
  let totalMicroUsdc = 0n;
  let unspentCount = 0;
  let spentCount = 0;
  for (const n of notes) {
    if (n.spent) spentCount++;
    else {
      totalMicroUsdc += n.value;
      unspentCount++;
    }
  }
  return { totalMicroUsdc, unspentCount, spentCount };
}

// re-exports for callers that don't want to pull `private-pool-keys`
// directly (most discovery callers stay in this module).
export { fieldToBytes32BE, poseidon1 } from './keys';
