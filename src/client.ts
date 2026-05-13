// Private Pool V2 — high-level orchestration helper.
//
// Glues together the foundational libs into the user-facing flows:
//   - `prepareDepositTransaction(...)` — build witness, prove, build ix,
//     return a versioned tx ready for the wallet adapter to sign+send
//   - `prepareWithdrawTransaction(...)` — same, but consumes a note
//   - `prepareJoinSplitTransaction(...)` — same, 2 inputs / 2 outputs
//   - `loadConfig(network)` — fetch + cache pool addresses from
//     `/api/private-pool/v2/config`
//
// The wallet adapter takes care of signing + sending (`wallet.sendTransaction`).
// Backend orkiestracji przyjdzie w v1.1 (sponsored fee payer); MVP is
// fully client-driven.

import {
  AddressLookupTableProgram,
  ComputeBudgetProgram,
  Connection,
  PublicKey,
  SystemProgram,
  TransactionInstruction,
  TransactionMessage,
  VersionedTransaction,
} from '@solana/web3.js';

import { deriveCommitment, deriveNullifier as deriveNullifierAsync, merkleParent } from './witness';
import { proveDeposit, proveWithdraw, proveJoinSplit, proveCashoutProof } from './prover';
import { parsePaymentAddress, deriveCodeKeys, type CodeKeyMaterial } from './keys';
// ADR-008 (stealth addresses) was withdrawn 2026-05-08 — see the ADR
// markdown postmortem. All notes are now legacy ADR-003 (master_pk
// owner_pk). Future stealth needs a curve-based scheme + circuit
// upgrade.
import {
  fieldToBytes32BE as keysFieldToBytes32BE,
  type PrivatePoolKeyMaterial,
} from './keys';
import {
  encryptNote,
  tryDecryptNote,
  type DecryptedNote,
  PRIVATE_POOL_NOTE_BYTES,
} from './encryption';
import type { OwnedNote } from './discovery';

// ── Config fetcher ───────────────────────────────────────────────────────

export type PrivatePoolV2Config = {
  network: string;
  cluster: 'devnet' | 'mainnet';
  programIds: {
    pool: string;
    depositVerifier: string;
    withdrawVerifier: string;
    joinsplitVerifier: string;
  };
  poolPda: string;
  vaultAta: string;
  usdcMint: string;
  aspAuthority: string;
  tokenProgramId: string;
  associatedTokenProgramId: string;
  /// Backend's sponsored-fee-payer pubkey (`null` when the backend
  /// doesn't have a keypair configured — fall back to user-pays-fees).
  /// When set, frontend builds v0 messages with `payerKey: feePayer`
  /// so the wallet popup never asks the user for SOL.
  feePayer: string | null;
  constants: {
    poolDepth: number;
    aspDepth: number;
    rootHistorySize: number;
    aspRootHistorySize: number;
    encryptedNoteBytes: number;
    encryptedNoteWithMemoBytes: number;
    usdcDecimals: number;
  };
};

const configCache = new Map<string, PrivatePoolV2Config>();

export async function loadConfig(args: {
  apiBaseUrl: string;
  network: string;
}): Promise<PrivatePoolV2Config> {
  const cacheKey = `${args.apiBaseUrl}|${args.network}`;
  const cached = configCache.get(cacheKey);
  if (cached) return cached;
  const url = new URL('api/private-pool/v2/config', args.apiBaseUrl.endsWith('/') ? args.apiBaseUrl : args.apiBaseUrl + '/');
  url.searchParams.set('network', args.network);
  const r = await fetch(url.toString());
  if (!r.ok) throw new Error(`loadConfig: ${r.status} ${await r.text()}`);
  const cfg = (await r.json()) as PrivatePoolV2Config;
  configCache.set(cacheKey, cfg);
  return cfg;
}

// ── PDA helpers (mirror server `pdas.js` shape so the client can derive
//    the same addresses without round-tripping the backend) ─────────────

export function fieldToBytes32BE(value: bigint): Buffer {
  return Buffer.from(keysFieldToBytes32BE(value));
}

function deriveLeafPda(programId: PublicKey, poolPda: PublicKey, commitmentBytes: Buffer): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from('ppv2-leaf'), poolPda.toBuffer(), commitmentBytes],
    programId,
  );
}
function deriveBlobPda(programId: PublicKey, poolPda: PublicKey, commitmentBytes: Buffer): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from('ppv2-enc'), poolPda.toBuffer(), commitmentBytes],
    programId,
  );
}
function deriveNullifierPda(programId: PublicKey, poolPda: PublicKey, nullifierBytes: Buffer): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from('ppv2-nullifier'), poolPda.toBuffer(), nullifierBytes],
    programId,
  );
}

function deriveAta(mint: PublicKey, owner: PublicKey, tokenProgram: PublicKey, atokenProgram: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync(
    [owner.toBuffer(), tokenProgram.toBuffer(), mint.toBuffer()],
    atokenProgram,
  )[0];
}

// ── Anchor + borsh primitives (frontend mirror) ──────────────────────────

async function anchorDiscriminator(name: string): Promise<Buffer> {
  // Use Web Crypto SHA-256 — same output as Node `crypto.createHash`.
  const enc = new TextEncoder().encode(`global:${name}`);
  const digest = await crypto.subtle.digest('SHA-256', enc);
  return Buffer.from(new Uint8Array(digest).slice(0, 8));
}

function writeU64LE(value: bigint | number): Buffer {
  // The browser polyfill for `Buffer` (`buffer` npm package) doesn't
  // always implement BigInt-flavoured methods like writeBigUInt64LE
  // — older versions ship without them. Drop down to DataView, which
  // is part of the ES standard and supports `setBigUint64` everywhere
  // we run (Node + every modern browser).
  const buf = Buffer.alloc(8);
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  view.setBigUint64(0, BigInt(value), true /* littleEndian */);
  return buf;
}

function writeAnchorVecU8(bytes: Uint8Array): Buffer {
  const out = Buffer.alloc(4 + bytes.length);
  out.writeUInt32LE(bytes.length, 0);
  Buffer.from(bytes).copy(out, 4);
  return out;
}

// ── poseidon_addr_hash mirror — match the on-chain handler ──────────────

import { buildPoseidon } from 'circomlibjs';

const FIELD_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

let cachedPoseidon: any = null;
async function getPoseidon(): Promise<any> {
  if (!cachedPoseidon) cachedPoseidon = await buildPoseidon();
  return cachedPoseidon;
}

/// Match the Rust `poseidon_addr_hash`: reduce the SPL pubkey
/// (interpreted as a 256-bit BE big-int) modulo the BN254 scalar
/// field, then Poseidon-1.
///
/// Both sides do PROPER `bytes mod p` reduction (audit H-3). The
/// previous `& 0x1f` mask threw away 3 bits of pre-image entropy;
/// this version preserves full ~254-bit field uniformity.
///
/// On-chain side: `reduce_into_bn254_fr` in
/// `programs/solana-private-pool-v2/src/lib.rs` — hand-rolled
/// 8-bound subtraction loop against a hard-coded BN254 modulus
/// constant (avoids pulling `ark_bn254` for one mod op). Both
/// implementations are covered by 6 unit tests including a Python
/// cross-reference for the worst-case input.
async function poseidonAddrHash(pubkey: PublicKey): Promise<bigint> {
  const bytes = Buffer.from(pubkey.toBytes());
  let acc = 0n;
  for (const b of bytes) acc = (acc << 8n) + BigInt(b);
  acc = ((acc % FIELD_MODULUS) + FIELD_MODULUS) % FIELD_MODULUS;
  const p = await getPoseidon();
  const h = p([acc]);
  return ((BigInt(p.F.toString(h)) % FIELD_MODULUS) + FIELD_MODULUS) % FIELD_MODULUS;
}

// ── Deposit flow ─────────────────────────────────────────────────────────

export type PrepareDepositArgs = {
  cfg: PrivatePoolV2Config;
  /// Wallet pubkey of the depositor (user signing the tx). The proof
  /// binds `depositor_addr_hash` to this exact pubkey; the on-chain
  /// handler re-hashes the signer at runtime and rejects on mismatch.
  depositor: PublicKey;
  /// Recipient identity. For self-deposit (typical onboarding) pass the
  /// caller's own derived `spendingPkField`. For depositing to someone
  /// else, parse their payment address and use that `spendingPkField`.
  recipientSpendingPkField: bigint;
  /// 32-byte X25519 viewing pubkey of the recipient. Used to encrypt the
  /// note for them; the on-chain blob lets them trial-decrypt later.
  recipientViewingPk: Uint8Array;
  /// micro-USDC amount entering the pool (full, fee will be subtracted
  /// inside the circuit to compute the note's value).
  publicValue: bigint;
  /// Relayer fee in micro-USDC. Most MVP flows set this to 0.
  fee: bigint;
  /// Optional 32-byte memo. `null` for memo-less.
  memo: Uint8Array | null;
  /// Leave on-chain ciphertext or send `null` to skip blob storage and
  /// rely on off-chain delivery (e.g. self-deposit where the depositor
  /// already has the plaintext locally).
  storeBlobOnChain?: boolean;
  // (ADR-008 `useStealthAddress` flag removed — see ADR markdown
  // postmortem. All notes are now master_pk legacy.)
};

export type PreparedDepositTx = {
  /// Versioned tx ready for `wallet.sendTransaction(tx, conn)`.
  transaction: VersionedTransaction;
  /// Computed commitment (hex + field) — useful for showing the user a
  /// "this is your note ID" preview before signing.
  commitmentHex: string;
  commitmentField: bigint;
  /// PDA addresses the handler is going to allocate. Frontend can poll
  /// these post-confirmation to detect when the indexer has indexed the
  /// fresh leaf.
  leafPda: PublicKey;
  blobPda: PublicKey;
  /// Local copies of the note material — caller stashes these in
  /// IndexedDB / localStorage so the recipient can recover the note
  /// from local state even if the on-chain blob is skipped.
  ownedNoteSecret: {
    blinding: Uint8Array;
    ownerPk: Uint8Array;
    memo: Uint8Array | null;
    valueMicroUsdc: bigint;
  };
  /// Time spent on Groth16 prove (for UX progress feedback).
  proveMs: number;
};

/// Build a deposit tx end-to-end. Caller's responsibility to sign+send
/// via the wallet adapter.
export async function prepareDepositTransaction(
  args: PrepareDepositArgs,
  options: { connection: Connection; recentBlockhash?: string } = {} as any,
): Promise<PreparedDepositTx> {
  const conn = options.connection;
  if (!conn) throw new Error('prepareDepositTransaction: connection required');

  // 1. Witness — note value = publicValue - fee.
  const noteValue = args.publicValue - args.fee;
  if (noteValue <= 0n) throw new Error('prepareDepositTransaction: noteValue must be positive');

  // Fresh per-note blinding. Real wallets pull from a CSPRNG.
  const blinding = crypto.getRandomValues(new Uint8Array(32));
  // Reduce blinding to a field element (just clear top 2 bits).
  blinding[0] = blinding[0] & 0x3f;
  const blindingField = bytesToField(blinding);

  // Legacy ADR-003 only: owner_pk = recipient's master spending_pk.
  const ownerPkField = args.recipientSpendingPkField;

  const memoField = args.memo ? bytesToField(args.memo) : 0n;
  const commitmentField = await deriveCommitment({
    value: noteValue,
    ownerPk: ownerPkField,
    blinding: blindingField,
    memo: memoField,
  });

  const depositorAddrHashField = await poseidonAddrHash(args.depositor);

  // Witness shape mirrors `Deposit.circom` signal declaration order.
  const witness = {
    ownerPk: ownerPkField.toString(10),
    blinding: blindingField.toString(10),
    memo: memoField.toString(10),
    publicValue: args.publicValue.toString(10),
    depositorAddrHash: depositorAddrHashField.toString(10),
    fee: args.fee.toString(10),
  } as unknown as import('./types').DepositWitness;

  // 2. Prove.
  const { proofBytes, proveMs } = await proveDeposit(witness);

  // 3. Optional: encrypt the note for the recipient.
  const commitmentBytes = fieldToBytes32BE(commitmentField);
  let encryptedNote = new Uint8Array(0);
  let ephemeralPk = new Uint8Array(32);
  if (args.storeBlobOnChain !== false) {
    // ownerPk inside the plaintext mirrors the on-chain commitment's
    // stealth pubkey when stealth is on (so the recipient's
    // self-recovery sanity check matches), or the master pubkey for
    // legacy notes. Either way, recipient does the same Poseidon4
    // commitment recompute and verifies match.
    const note: DecryptedNote = {
      value: noteValue,
      blinding,
      ownerPk: fieldToBytes32BE(ownerPkField),
      memo: args.memo,
      stealthNonce: null,
      layout: 'legacy',
    };
    const blob = encryptNote({
      note,
      recipientViewingPk: args.recipientViewingPk,
      commitment: commitmentBytes,
    });
    encryptedNote = blob.ciphertext;
    ephemeralPk = blob.ephemeralPk;
  }

  // 4. Build deposit_note ix.
  const programId = new PublicKey(args.cfg.programIds.pool);
  const usdcMint = new PublicKey(args.cfg.usdcMint);
  const poolPda = new PublicKey(args.cfg.poolPda);
  const tokenProgram = new PublicKey(args.cfg.tokenProgramId);
  const atokenProgram = new PublicKey(args.cfg.associatedTokenProgramId);
  const vaultAta = new PublicKey(args.cfg.vaultAta);
  const depositorAta = deriveAta(usdcMint, args.depositor, tokenProgram, atokenProgram);

  const [leafPda] = deriveLeafPda(programId, poolPda, commitmentBytes);
  const [blobPda] = deriveBlobPda(programId, poolPda, commitmentBytes);

  const disc = await anchorDiscriminator('deposit_note');
  const ixData = Buffer.concat([
    disc,
    commitmentBytes,
    fieldToBytes32BE(depositorAddrHashField),
    writeU64LE(args.publicValue),
    writeU64LE(args.fee),
    writeAnchorVecU8(encryptedNote),
    Buffer.from(ephemeralPk),
    writeAnchorVecU8(proofBytes),
  ]);

  const verifierProgram = new PublicKey(args.cfg.programIds.depositVerifier);

  const depositIx = new TransactionInstruction({
    programId,
    keys: [
      { pubkey: args.depositor, isSigner: true, isWritable: true },
      { pubkey: usdcMint, isSigner: false, isWritable: false },
      { pubkey: poolPda, isSigner: false, isWritable: true },
      { pubkey: leafPda, isSigner: false, isWritable: true },
      { pubkey: blobPda, isSigner: false, isWritable: true },
      { pubkey: vaultAta, isSigner: false, isWritable: true },
      { pubkey: depositorAta, isSigner: false, isWritable: true },
      { pubkey: verifierProgram, isSigner: false, isWritable: false },
      { pubkey: tokenProgram, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: ixData,
  });

  // Pre-flight: vault ATA + depositor ATA must exist. Add `CreateIdempotent`
  // ixs for any missing ones — cheaper than a full pre-tx round-trip.
  const preIxs: TransactionInstruction[] = [];
  const vaultExists = !!(await conn.getAccountInfo(vaultAta));
  const depositorAtaExists = !!(await conn.getAccountInfo(depositorAta));
  if (!vaultExists) {
    preIxs.push(buildCreateIdempotentAtaIx(args.depositor, vaultAta, poolPda, usdcMint, tokenProgram, atokenProgram));
  }
  if (!depositorAtaExists) {
    preIxs.push(buildCreateIdempotentAtaIx(args.depositor, depositorAta, args.depositor, usdcMint, tokenProgram, atokenProgram));
  }

  // Compute budget — deposit verifier is cheap (~50k CU), but stay safe.
  const cuIx = ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 });

  // Recent blockhash.
  const blockhash = options.recentBlockhash
    ?? (await conn.getLatestBlockhash('confirmed')).blockhash;

  // Sponsored fee payer when backend exposed `feePayer`; otherwise user
  // pays SOL fees themselves. The wallet popup wording differs noticeably
  // — sponsored case shows ~0 SOL deduction, fallback shows ~5k lamports.
  const payerKey = args.cfg.feePayer ? new PublicKey(args.cfg.feePayer) : args.depositor;
  const message = new TransactionMessage({
    payerKey,
    recentBlockhash: blockhash,
    instructions: [cuIx, ...preIxs, depositIx],
  }).compileToV0Message();
  const tx = new VersionedTransaction(message);

  return {
    transaction: tx,
    commitmentHex: '0x' + commitmentBytes.toString('hex'),
    commitmentField,
    leafPda,
    blobPda,
    ownedNoteSecret: {
      blinding,
      ownerPk: fieldToBytes32BE(args.recipientSpendingPkField),
      memo: args.memo,
      valueMicroUsdc: noteValue,
    },
    proveMs,
  };
}

// ── shared helpers ───────────────────────────────────────────────────────

function bytesToField(bytes: Uint8Array): bigint {
  if (bytes.length === 0) return 0n;
  let v = 0n;
  for (const b of bytes) v = (v << 8n) + BigInt(b);
  return ((v % FIELD_MODULUS) + FIELD_MODULUS) % FIELD_MODULUS;
}

function buildCreateIdempotentAtaIx(
  payer: PublicKey,
  ata: PublicKey,
  owner: PublicKey,
  mint: PublicKey,
  tokenProgram: PublicKey,
  atokenProgram: PublicKey,
): TransactionInstruction {
  return new TransactionInstruction({
    programId: atokenProgram,
    keys: [
      { pubkey: payer, isSigner: true, isWritable: true },
      { pubkey: ata, isSigner: false, isWritable: true },
      { pubkey: owner, isSigner: false, isWritable: false },
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      { pubkey: tokenProgram, isSigner: false, isWritable: false },
    ],
    data: Buffer.from([1]), // CreateIdempotent discriminator
  });
}

// ── Merkle reconstruction (frontend mirror) ─────────────────────────────

/// Build the path for `leafIndex` in a depth-`depth` sparse tree whose
/// occupied leaves are `leaves` (insertion order).
async function buildMerkleTreeFromLeaves(
  leaves: bigint[],
  leafIndex: number,
  depth: number,
): Promise<{ pathElements: bigint[]; pathIndices: number[]; root: bigint }> {
  if (leafIndex < 0 || leafIndex >= leaves.length) {
    throw new Error(`merkle path: leafIndex ${leafIndex} out of range [0, ${leaves.length})`);
  }
  const zeroHashes: bigint[] = [0n];
  for (let i = 0; i < depth; i++) {
    zeroHashes.push(await merkleParent(zeroHashes[i], zeroHashes[i]));
  }
  const pathElements: bigint[] = [];
  const pathIndices: number[] = [];
  let layer = [...leaves];
  let cur = leafIndex;
  for (let level = 0; level < depth; level++) {
    const isRight = cur % 2;
    const sibling =
      isRight === 0
        ? layer[cur + 1] !== undefined
          ? layer[cur + 1]
          : zeroHashes[level]
        : layer[cur - 1] !== undefined
        ? layer[cur - 1]
        : zeroHashes[level];
    pathElements.push(sibling);
    pathIndices.push(isRight);
    const next: bigint[] = [];
    for (let i = 0; i < layer.length; i += 2) {
      const l = layer[i];
      const r = i + 1 < layer.length ? layer[i + 1] : zeroHashes[level];
      next.push(await merkleParent(l, r));
    }
    layer = next;
    cur = Math.floor(cur / 2);
  }
  // Compute root.
  let rootLayer = [...leaves];
  for (let level = 0; level < depth; level++) {
    const next: bigint[] = [];
    for (let i = 0; i < rootLayer.length; i += 2) {
      const l = rootLayer[i];
      const r = i + 1 < rootLayer.length ? rootLayer[i + 1] : zeroHashes[level];
      next.push(await merkleParent(l, r));
    }
    if (rootLayer.length === 0) {
      rootLayer = [zeroHashes[depth]];
      break;
    }
    rootLayer = next.length > 0 ? next : [zeroHashes[level + 1]];
  }
  return { pathElements, pathIndices, root: rootLayer[0] };
}

// ── Withdraw flow ────────────────────────────────────────────────────────

export type PrepareWithdrawArgs = {
  cfg: PrivatePoolV2Config;
  /// User's master spending_sk (the one derived from the wallet sig).
  /// For ADR-008 stealth notes the circuit needs the per-note
  /// `noteStealthSpendingSkField` instead — pass that via the field
  /// below; this `spendingSkField` is the fallback used for legacy
  spendingSkField: bigint;
  nullifierSkField: bigint;
  /// The note to consume (one OwnedNote-shaped value; we accept just the
  /// fields the witness needs so callers can pass a slim subset).
  note: {
    value: bigint;
    blinding: bigint;
    memo: bigint;
    commitmentField: bigint;
    leafIndex: number;
  };
  /// All commitments currently in the pool, in insertion order. Caller
  /// fetches via `GET /api/private-pool/v2/leaves`.
  allLeaves: bigint[];
  /// Pool root the proof will be built against. Must match what the
  /// reconstructed merkle root yields for `allLeaves`. Caller pulls this
  /// from `pool.latest_root` (or any of the last 64 root_history entries).
  poolRoot: bigint;
  /// Active ASP root that contains `note.commitmentField`. Caller is
  /// responsible for ensuring the ASP authority has published this root.
  aspRoot: bigint;
  /// ASP merkle path for the note's commitment (also caller's responsibility).
  aspPath: { pathElements: bigint[]; pathIndices: number[] };
  /// Recipient SPL pubkey — Poseidon-1 hashed for the proof.
  recipient: PublicKey;
  /// micro-USDC paid out to recipient (full note value − fee).
  publicValue: bigint;
  fee: bigint;
};

export type PreparedWithdrawTx = {
  transaction: VersionedTransaction;
  nullifierField: bigint;
  nullifierPda: PublicKey;
  proveMs: number;
};

export async function prepareWithdrawTransaction(
  args: PrepareWithdrawArgs,
  options: { connection: Connection; payer: PublicKey; recentBlockhash?: string },
): Promise<PreparedWithdrawTx> {
  // 1. Reconstruct the pool merkle path for the note's leaf.
  const poolPath = await buildMerkleTreeFromLeaves(
    args.allLeaves,
    args.note.leafIndex,
    args.cfg.constants.poolDepth,
  );
  if (poolPath.root !== args.poolRoot) {
    throw new Error(
      `prepareWithdrawTransaction: reconstructed pool root ${poolPath.root.toString(16)} does not match supplied ${args.poolRoot.toString(16)} — likely stale leaves array`,
    );
  }

  // 2. Derive the public address binding (Poseidon-1 of recipient pubkey).
  const publicAddressField = await poseidonAddrHash(args.recipient);

  // Legacy ADR-003: owner_pk = poseidon1(master_spending_sk). The
  // commitment on chain was minted with this exact owner_pk, so the
  // circuit's `poseidon1(spendingSk) == ownerPk` check tautologically
  // holds when both sides come from the same master sk.
  const p = await getPoseidon();
  const ownerPkField = ((BigInt(p.F.toString(p([args.spendingSkField]))) % FIELD_MODULUS) + FIELD_MODULUS) % FIELD_MODULUS;

  // Witness shape — mirrors `Withdraw.circom` signal order. Same rationale
  // as deposit: we build the field-string map directly, bypassing the
  // builder that expects Uint8Array shapes.
  const witness = {
    value: args.note.value.toString(10),
    ownerPk: ownerPkField.toString(10),
    blinding: args.note.blinding.toString(10),
    memo: args.note.memo.toString(10),
    spendingSk: args.spendingSkField.toString(10),
    nullifierSk: args.nullifierSkField.toString(10),
    poolPathElements: poolPath.pathElements.map((e) => e.toString(10)),
    poolPathIndices: poolPath.pathIndices,
    aspPathElements: args.aspPath.pathElements.map((e) => e.toString(10)),
    aspPathIndices: args.aspPath.pathIndices,
    publicValue: args.publicValue.toString(10),
    publicAddress: publicAddressField.toString(10),
    fee: args.fee.toString(10),
  } as unknown as import('./types').WithdrawWitness;

  // 4. Prove + pack.
  const { proofBytes, proveMs } = await proveWithdraw(witness);

  // 5. Compute the nullifier (matches what the circuit emits).
  const nullifierField = await deriveNullifierAsync({
    commitment: args.note.commitmentField,
    nullifierSk: args.nullifierSkField,
  });
  const nullifierBytes = fieldToBytes32BE(nullifierField);

  // 6. Build the ix.
  const programId = new PublicKey(args.cfg.programIds.pool);
  const usdcMint = new PublicKey(args.cfg.usdcMint);
  const poolPda = new PublicKey(args.cfg.poolPda);
  const tokenProgram = new PublicKey(args.cfg.tokenProgramId);
  const atokenProgram = new PublicKey(args.cfg.associatedTokenProgramId);
  const vaultAta = new PublicKey(args.cfg.vaultAta);
  const recipientAta = deriveAta(usdcMint, args.recipient, tokenProgram, atokenProgram);
  const verifier = new PublicKey(args.cfg.programIds.withdrawVerifier);

  const [nullifierPda] = deriveNullifierPda(programId, poolPda, nullifierBytes);

  const disc = await anchorDiscriminator('withdraw');
  const ixData = Buffer.concat([
    disc,
    nullifierBytes,
    fieldToBytes32BE(args.poolRoot),
    fieldToBytes32BE(args.aspRoot),
    fieldToBytes32BE(publicAddressField),
    writeU64LE(args.publicValue),
    writeU64LE(args.fee),
    writeAnchorVecU8(proofBytes),
  ]);

  const withdrawIx = new TransactionInstruction({
    programId,
    keys: [
      { pubkey: options.payer, isSigner: true, isWritable: true },
      { pubkey: usdcMint, isSigner: false, isWritable: false },
      { pubkey: poolPda, isSigner: false, isWritable: true },
      { pubkey: nullifierPda, isSigner: false, isWritable: true },
      { pubkey: args.recipient, isSigner: false, isWritable: false },
      { pubkey: vaultAta, isSigner: false, isWritable: true },
      { pubkey: recipientAta, isSigner: false, isWritable: true },
      { pubkey: verifier, isSigner: false, isWritable: false },
      { pubkey: tokenProgram, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: ixData,
  });

  // Pre-flight: recipient ATA may not exist yet on a fresh wallet.
  const preIxs: TransactionInstruction[] = [];
  const recipientAtaExists = !!(await options.connection.getAccountInfo(recipientAta));
  if (!recipientAtaExists) {
    preIxs.push(buildCreateIdempotentAtaIx(options.payer, recipientAta, args.recipient, usdcMint, tokenProgram, atokenProgram));
  }
  const cuIx = ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 });

  const blockhash = options.recentBlockhash
    ?? (await options.connection.getLatestBlockhash('confirmed')).blockhash;
  const payerKey = args.cfg.feePayer ? new PublicKey(args.cfg.feePayer) : options.payer;
  const message = new TransactionMessage({
    payerKey,
    recentBlockhash: blockhash,
    instructions: [cuIx, ...preIxs, withdrawIx],
  }).compileToV0Message();
  const tx = new VersionedTransaction(message);
  return { transaction: tx, nullifierField, nullifierPda, proveMs };
}

// ── Relayer-signed withdraw (ADR-010) ────────────────────────────────────
//
// Companion to `prepareWithdrawTransaction`: instead of returning a
// VersionedTransaction the caller has to sign + broadcast (which puts
// the user's wallet pubkey into the on-chain `signers` array),
// `prepareWithdrawRelayPayload` returns a typed bundle the SDK ships
// to `POST /api/private-pool/v2/relay/withdraw`. The backend wraps it
// in a tx with `caller = relayer_keypair` and broadcasts.
//
// Net effect on chain: the user's wallet never appears as a signer of
// the withdraw tx. The proof is the only authorisation primitive
// (recipient is bound via `public_address = Poseidon(recipient)`;
// amount + fee + roots are public inputs the verifier cross-checks).
// See ADR-010 §Threat model for what the relayer can / cannot do.

export type WithdrawRelayPayload = {
  network: string
  nullifier_hex: string
  root_hex: string
  asp_root_hex: string
  public_address_hex: string
  public_value: string
  fee: string
  recipient: string
  recipient_ata: string
  proof_b64: string
}

export type PreparedWithdrawRelay = {
  payload: WithdrawRelayPayload
  nullifierField: bigint
  proveMs: number
}

export async function prepareWithdrawRelayPayload(
  args: PrepareWithdrawArgs & { network: string },
): Promise<PreparedWithdrawRelay> {
  // The proof + public-input derivation is identical to
  // `prepareWithdrawTransaction`; only the output shape differs.
  // We inline the steps rather than refactoring the existing function
  // to share a helper because every step inside that function is
  // tightly couple to the on-chain ix layout (witness shape, account
  // ordering) — duplicating a few lines keeps each path independently
  // auditable.

  // 1. Pool merkle path.
  const poolPath = await buildMerkleTreeFromLeaves(
    args.allLeaves,
    args.note.leafIndex,
    args.cfg.constants.poolDepth,
  )
  if (poolPath.root !== args.poolRoot) {
    throw new Error(
      `prepareWithdrawRelayPayload: reconstructed pool root ${poolPath.root.toString(16)} != supplied ${args.poolRoot.toString(16)} — likely stale leaves array`,
    )
  }

  // 2. Recipient binding.
  const publicAddressField = await poseidonAddrHash(args.recipient)

  // 3. Witness (same shape as the tx flow; see `prepareWithdrawTransaction`).
  // CRITICAL: this must match `Withdraw.circom` signal inputs EXACTLY.
  // The circuit derives poolRoot/aspRoot internally from the path elements
  // and verifies leafIndex via `poolPathIndices` — adding those as separate
  // signals fails witness gen with "Signal X not found" under strict snarkjs.
  const p = await getPoseidon()
  const ownerPkField = ((BigInt(p.F.toString(p([args.spendingSkField]))) % FIELD_MODULUS) + FIELD_MODULUS) % FIELD_MODULUS
  const witness = {
    value: args.note.value.toString(10),
    ownerPk: ownerPkField.toString(10),
    blinding: args.note.blinding.toString(10),
    memo: args.note.memo.toString(10),
    spendingSk: args.spendingSkField.toString(10),
    nullifierSk: args.nullifierSkField.toString(10),
    poolPathElements: poolPath.pathElements.map((e) => e.toString(10)),
    poolPathIndices: poolPath.pathIndices,
    aspPathElements: args.aspPath.pathElements.map((e) => e.toString(10)),
    aspPathIndices: args.aspPath.pathIndices,
    publicValue: args.publicValue.toString(10),
    publicAddress: publicAddressField.toString(10),
    fee: args.fee.toString(10),
  } as unknown as import('./types').WithdrawWitness

  const { proofBytes, proveMs } = await proveWithdraw(witness)

  // 4. Nullifier (matches the circuit's emission).
  const nullifierField = await deriveNullifierAsync({
    commitment: args.note.commitmentField,
    nullifierSk: args.nullifierSkField,
  })
  const nullifierBytes = fieldToBytes32BE(nullifierField)

  // 5. Pre-derive the recipient ATA so the server doesn't re-do the
  //    derivation work + we can cross-check the proof's binding before
  //    burning relayer SOL.
  const usdcMint = new PublicKey(args.cfg.usdcMint)
  const tokenProgram = new PublicKey(args.cfg.tokenProgramId)
  const atokenProgram = new PublicKey(args.cfg.associatedTokenProgramId)
  const recipientAta = deriveAta(usdcMint, args.recipient, tokenProgram, atokenProgram)

  // 6. Build the JSON payload. All bigint values serialised as
  //    decimal strings — the server parses them with `BigInt(…)`,
  //    bypassing JS Number precision loss above 2^53.
  const toHex32 = (n: bigint) => '0x' + n.toString(16).padStart(64, '0')

  const payload: WithdrawRelayPayload = {
    network: args.network,
    nullifier_hex: toHex32(nullifierField),
    root_hex: toHex32(args.poolRoot),
    asp_root_hex: toHex32(args.aspRoot),
    public_address_hex: toHex32(publicAddressField),
    public_value: args.publicValue.toString(10),
    fee: args.fee.toString(10),
    recipient: args.recipient.toBase58(),
    recipient_ata: recipientAta.toBase58(),
    proof_b64: Buffer.from(proofBytes).toString('base64'),
  }

  return { payload, nullifierField, proveMs }
}

/**
 * Submit a prepared relay payload. Returns the on-chain tx signature
 * + an explorer URL when confirmation succeeds.
 *
 * Network-error handling: if the POST itself fails (server down,
 * timeout, etc.), the error is rethrown for the caller to retry —
 * the on-chain state is unchanged because no tx was built. If the
 * POST returns a structured error (e.g. `already_consumed`,
 * `fee_below_min`), it's surfaced as a typed exception with the
 * server's error code on `cause.error`.
 */
export async function submitWithdrawViaRelay(args: {
  apiBaseUrl: string
  payload: WithdrawRelayPayload
}): Promise<{ signature: string; confirmed: boolean; explorerUrl: string }> {
  const url = new URL(
    'api/private-pool/v2/relay/withdraw',
    args.apiBaseUrl.endsWith('/') ? args.apiBaseUrl : args.apiBaseUrl + '/',
  )
  const res = await fetch(url.toString(), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(args.payload),
  })
  const body = (await res.json().catch(() => ({}))) as Record<string, unknown>
  if (!res.ok) {
    const err = new Error(
      `relay/withdraw rejected (HTTP ${res.status}): ${body.error ?? 'unknown'} — ${body.detail ?? ''}`,
    )
    ;(err as Error & { cause?: unknown }).cause = body
    throw err
  }
  return {
    signature: String(body.signature ?? ''),
    confirmed: Boolean(body.confirmed),
    explorerUrl: String(body.explorerUrl ?? ''),
  }
}

// ── JoinSplit flow ───────────────────────────────────────────────────────
//
// Solana's 1232-byte tx limit forces a couple of compromises here:
//   - Use a v0 tx with an Address Lookup Table (caller manages the LUT,
//     normally created once per pool and reused).
//   - Encrypted-note blobs go off-chain (per ADR-004 amendment); caller
//     POSTs them to `/api/private-pool/v2/notes/relay-blob` AFTER the tx
//     confirms.
//
// Caller is responsible for:
//   - publishing an ASP root containing both input commitments (separate
//     `add_asp_root` tx, gated by ASP authority signer)
//   - allocating + extending the LUT and waiting for it to land
//   - encrypting the recipient + change ciphertexts and uploading them
//     to the relay (we return the cipher material so the caller can do
//     this in parallel with confirmation polling)

export type JoinSplitNoteRecipient = {
  /// Recipient's public spending key field (Poseidon1 of their spending_sk).
  spendingPkField: bigint;
  /// Recipient's X25519 viewing pubkey (32 bytes) — used for blob encryption.
  viewingPk: Uint8Array;
};

export type PrepareJoinSplitArgs = {
  cfg: PrivatePoolV2Config;
  /// Sender's keys (must be the owner of both input notes).
  senderSpendingSkField: bigint;
  senderSpendingPkField: bigint; // Poseidon1(senderSpendingSkField) — mirror for owner_pk equality
  senderNullifierSkField: bigint;
  senderViewingPk: Uint8Array; // for self-encrypting the change note
  /// Two input notes the sender owns + their merkle paths in the pool tree.
  /// All notes are legacy ADR-003 (master_pk owner_pk) in V1.
  inputNotes: [
    { value: bigint; blinding: bigint; memo: bigint; commitmentField: bigint; leafIndex: number },
    { value: bigint; blinding: bigint; memo: bigint; commitmentField: bigint; leafIndex: number },
  ];
  allLeaves: bigint[];
  poolRoot: bigint;
  aspRoot: bigint;
  aspPaths: [
    { pathElements: bigint[]; pathIndices: number[] },
    { pathElements: bigint[]; pathIndices: number[] },
  ];
  /// Recipient identity. Output 1 goes here; output 2 is sender's change.
  recipient: JoinSplitNoteRecipient;
  /// Amount transferred to recipient (micro-USDC). Must satisfy
  /// `recipientAmount + changeAmount + fee == in1.value + in2.value`.
  recipientAmount: bigint;
  fee: bigint;
  /// Optional 32-byte memo attached to the recipient's output note —
  /// the recipient sees it after decrypting their blob. Use cases:
  /// invoice IDs (binds the JoinSplit to a specific invoice), payment
  /// reason codes, free-text labels (UTF-8 truncated). Pass `null` for
  /// memo-less notes (default).
  recipientMemo?: Uint8Array | null;
  /// Lookup table to fold constant accounts into. Caller created earlier.
  lookupTable: import('@solana/web3.js').AddressLookupTableAccount;
};

export type PreparedJoinSplitTx = {
  transaction: VersionedTransaction;
  nullifiers: [bigint, bigint];
  outputCommitments: [bigint, bigint];
  /// Materials the caller MUST relay to the backend after confirmation,
  /// otherwise the recipient never sees the new note.
  blobs: [
    { commitmentHex: string; ephemeralPkHex: string; ciphertextB64: string; ciphertextLen: number },
    { commitmentHex: string; ephemeralPkHex: string; ciphertextB64: string; ciphertextLen: number },
  ];
  proveMs: number;
};

export async function prepareJoinSplitTransaction(
  args: PrepareJoinSplitArgs,
  options: { connection: Connection; payer: PublicKey; recentBlockhash?: string },
): Promise<PreparedJoinSplitTx> {
  // 1. Balance check before anything expensive.
  const totalIn = args.inputNotes[0].value + args.inputNotes[1].value;
  const changeAmount = totalIn - args.recipientAmount - args.fee;
  if (changeAmount < 0n) {
    throw new Error(
      `prepareJoinSplitTransaction: insufficient input value (have ${totalIn}, need ${args.recipientAmount + args.fee})`,
    );
  }

  // All notes are legacy ADR-003 in V1 (stealth removed — see ADR-008
  // postmortem). Both inputs spend under the master spending_sk, both
  // outputs land under the recipient's / sender's master spending_pk.
  const inputSpendingSkField = args.senderSpendingSkField;
  const inputOwnerPkField = args.senderSpendingPkField;

  // 2. Reconstruct merkle paths for both inputs.
  const path1 = await buildMerkleTreeFromLeaves(args.allLeaves, args.inputNotes[0].leafIndex, args.cfg.constants.poolDepth);
  const path2 = await buildMerkleTreeFromLeaves(args.allLeaves, args.inputNotes[1].leafIndex, args.cfg.constants.poolDepth);
  if (path1.root !== args.poolRoot || path2.root !== args.poolRoot) {
    throw new Error('prepareJoinSplitTransaction: pool root mismatch on reconstruction');
  }

  // 3. Generate fresh blindings for the two output notes.
  const out1Blinding = randomFieldBytes();
  const out2Blinding = randomFieldBytes();
  const out1BlindingField = bytesToField(out1Blinding);
  const out2BlindingField = bytesToField(out2Blinding);

  // Recipient memo (optional 32-byte tag). The change note has no memo.
  const recipientMemo = args.recipientMemo ?? null;
  if (recipientMemo && recipientMemo.length !== 32) {
    throw new Error(`prepareJoinSplitTransaction: recipientMemo must be 32 bytes, got ${recipientMemo.length}`);
  }
  const recipientMemoField = recipientMemo ? bytesToField(recipientMemo) : 0n;

  // Legacy ADR-003 outputs — recipient + change notes carry the master
  // `spending_pk` of their respective owners. Per-recipient
  // unlinkability is weaker (two transfers to the same pubkey share
  // the same `owner_pk`) but amounts + sender stay hidden via the
  // anonymity set — V1 trade-off until a curve-based stealth scheme
  // ships (see ADR-008 postmortem).
  const recipientOwnerPk = args.recipient.spendingPkField;
  const changeOwnerPk = args.senderSpendingPkField;

  // Witness shape mirrors `JoinSplit2x2.circom` signal declaration order.
  // Built directly from bigint inputs (cheaper than going through the
  // Uint8Array-shaped builder API).
  //
  // `inputOwnerPkN` and `spendingSk` are the stealth-aware values
  // (= master pair when both inputs are non-stealth, = stealth pair
  // when both inputs share the same stealth nonce). Outputs always use
  // the per-payment stealth `owner_pk` — the recipient/sender unwrap
  // their nonce from the blob during discovery.
  const witness = {
    inputValue1: args.inputNotes[0].value.toString(10),
    inputOwnerPk1: inputOwnerPkField.toString(10),
    inputBlinding1: args.inputNotes[0].blinding.toString(10),
    inputMemo1: args.inputNotes[0].memo.toString(10),
    inputPoolPath1: path1.pathElements.map((e) => e.toString(10)),
    inputPoolIndices1: path1.pathIndices,
    inputAspPath1: args.aspPaths[0].pathElements.map((e) => e.toString(10)),
    inputAspIndices1: args.aspPaths[0].pathIndices,

    inputValue2: args.inputNotes[1].value.toString(10),
    inputOwnerPk2: inputOwnerPkField.toString(10),
    inputBlinding2: args.inputNotes[1].blinding.toString(10),
    inputMemo2: args.inputNotes[1].memo.toString(10),
    inputPoolPath2: path2.pathElements.map((e) => e.toString(10)),
    inputPoolIndices2: path2.pathIndices,
    inputAspPath2: args.aspPaths[1].pathElements.map((e) => e.toString(10)),
    inputAspIndices2: args.aspPaths[1].pathIndices,

    spendingSk: inputSpendingSkField.toString(10),
    nullifierSk: args.senderNullifierSkField.toString(10),

    outputValue1: args.recipientAmount.toString(10),
    outputOwnerPk1: recipientOwnerPk.toString(10),
    outputBlinding1: out1BlindingField.toString(10),
    outputMemo1: recipientMemoField.toString(10),

    outputValue2: changeAmount.toString(10),
    outputOwnerPk2: changeOwnerPk.toString(10),
    outputBlinding2: out2BlindingField.toString(10),
    outputMemo2: '0',

    publicValueIn: '0',
    publicValueOut: '0',
    publicAddress: '0',
    fee: args.fee.toString(10),
  } as unknown as import('./types').JoinSplitWitness;

  // 5. Prove.
  const { proofBytes, proveMs } = await proveJoinSplit(witness);

  // 6. Compute output commitments + nullifiers (witness builder didn't
  //    surface them as bigints, so re-derive from the public signals — or
  //    cleaner: recompute via Poseidon4).
  //
  //    Output commitments use the stealth `owner_pk` so they match the
  //    on-chain leaf the verifier emits from the public-input `outputOwnerPkN`.
  const out1Commitment = await poseidonHashFour(
    args.recipientAmount,
    recipientOwnerPk,
    out1BlindingField,
    recipientMemoField,
  );
  const out2Commitment = await poseidonHashFour(
    changeAmount,
    changeOwnerPk,
    out2BlindingField,
    0n,
  );
  const n1 = await deriveNullifierAsync({
    commitment: args.inputNotes[0].commitmentField,
    nullifierSk: args.senderNullifierSkField,
  });
  const n2 = await deriveNullifierAsync({
    commitment: args.inputNotes[1].commitmentField,
    nullifierSk: args.senderNullifierSkField,
  });

  // 7. Encrypt blobs (recipient note + sender's change note).
  //
  //    Plaintext carries:
  //      - `ownerPk`: the stealth `owner_pk` so the recipient's
  //        Poseidon4 commitment recompute (during decrypt sanity-check)
  //        matches the on-chain leaf
  //      - `stealthNonce`: lets the recipient derive
  //        `stealth_spending_sk = poseidon2(master_sk, nonce)`
  //        so they can spend later
  //      - `layout: 'stealth'`: triggers the 112B/144B serializer path
  const oc1Bytes = fieldToBytes32BE(out1Commitment);
  const oc2Bytes = fieldToBytes32BE(out2Commitment);
  const recipientBlob = encryptNote({
    note: {
      value: args.recipientAmount,
      blinding: out1Blinding,
      ownerPk: fieldToBytes32BE(recipientOwnerPk),
      memo: recipientMemo,
      stealthNonce: null,
      layout: 'legacy',
    },
    recipientViewingPk: args.recipient.viewingPk,
    commitment: oc1Bytes,
  });
  const changeBlob = encryptNote({
    note: {
      value: changeAmount,
      blinding: out2Blinding,
      ownerPk: fieldToBytes32BE(changeOwnerPk),
      memo: null,
      stealthNonce: null,
      layout: 'legacy',
    },
    recipientViewingPk: args.senderViewingPk,
    commitment: oc2Bytes,
  });

  // 8. Build the ix. Empty `encrypted_note` per output (ADR-004 amendment:
  //    JoinSplit blobs go off-chain via the relay).
  const programId = new PublicKey(args.cfg.programIds.pool);
  const usdcMint = new PublicKey(args.cfg.usdcMint);
  const poolPda = new PublicKey(args.cfg.poolPda);
  const tokenProgram = new PublicKey(args.cfg.tokenProgramId);
  const atokenProgram = new PublicKey(args.cfg.associatedTokenProgramId);
  const vaultAta = new PublicKey(args.cfg.vaultAta);
  const verifier = new PublicKey(args.cfg.programIds.joinsplitVerifier);

  const n1Bytes = fieldToBytes32BE(n1);
  const n2Bytes = fieldToBytes32BE(n2);
  const [nMarker1] = deriveNullifierPda(programId, poolPda, n1Bytes);
  const [nMarker2] = deriveNullifierPda(programId, poolPda, n2Bytes);
  const [leaf1] = deriveLeafPda(programId, poolPda, oc1Bytes);
  const [leaf2] = deriveLeafPda(programId, poolPda, oc2Bytes);
  const [blob1] = deriveBlobPda(programId, poolPda, oc1Bytes);
  const [blob2] = deriveBlobPda(programId, poolPda, oc2Bytes);

  const disc = await anchorDiscriminator('joinsplit');
  const ixData = Buffer.concat([
    disc,
    n1Bytes, n2Bytes,
    oc1Bytes, oc2Bytes,
    fieldToBytes32BE(args.poolRoot),
    fieldToBytes32BE(args.aspRoot),
    fieldToBytes32BE(0n), // public_address (pure internal)
    writeU64LE(0n),  // public_value_in
    writeU64LE(0n),  // public_value_out
    writeU64LE(args.fee),
    writeAnchorVecU8(new Uint8Array(0)), // encrypted_note_1 — empty (off-chain)
    writeAnchorVecU8(new Uint8Array(0)), // encrypted_note_2 — empty (off-chain)
    Buffer.alloc(32),                    // ephemeral_pk_1 — zero (unused)
    Buffer.alloc(32),                    // ephemeral_pk_2 — zero (unused)
    writeAnchorVecU8(proofBytes),
  ]);

  const joinsplitIx = new TransactionInstruction({
    programId,
    keys: [
      { pubkey: options.payer, isSigner: true, isWritable: true },
      { pubkey: usdcMint, isSigner: false, isWritable: false },
      { pubkey: poolPda, isSigner: false, isWritable: true },
      { pubkey: nMarker1, isSigner: false, isWritable: true },
      { pubkey: nMarker2, isSigner: false, isWritable: true },
      { pubkey: leaf1, isSigner: false, isWritable: true },
      { pubkey: leaf2, isSigner: false, isWritable: true },
      { pubkey: blob1, isSigner: false, isWritable: true },
      { pubkey: blob2, isSigner: false, isWritable: true },
      { pubkey: vaultAta, isSigner: false, isWritable: true },
      // pure internal: pass payer as spl_counterparty + payer ATA
      { pubkey: options.payer, isSigner: false, isWritable: false },
      { pubkey: deriveAta(usdcMint, options.payer, tokenProgram, atokenProgram), isSigner: false, isWritable: true },
      { pubkey: verifier, isSigner: false, isWritable: false },
      { pubkey: tokenProgram, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: ixData,
  });

  const cuIx = ComputeBudgetProgram.setComputeUnitLimit({ units: 800_000 });
  const blockhash = options.recentBlockhash
    ?? (await options.connection.getLatestBlockhash('confirmed')).blockhash;
  const payerKey = args.cfg.feePayer ? new PublicKey(args.cfg.feePayer) : options.payer;
  const message = new TransactionMessage({
    payerKey,
    recentBlockhash: blockhash,
    instructions: [cuIx, joinsplitIx],
  }).compileToV0Message([args.lookupTable]);
  const tx = new VersionedTransaction(message);

  return {
    transaction: tx,
    nullifiers: [n1, n2],
    outputCommitments: [out1Commitment, out2Commitment],
    blobs: [
      {
        commitmentHex: '0x' + Buffer.from(oc1Bytes).toString('hex'),
        ephemeralPkHex: '0x' + Buffer.from(recipientBlob.ephemeralPk).toString('hex'),
        ciphertextB64: Buffer.from(recipientBlob.ciphertext).toString('base64'),
        ciphertextLen: recipientBlob.ciphertext.length,
      },
      {
        commitmentHex: '0x' + Buffer.from(oc2Bytes).toString('hex'),
        ephemeralPkHex: '0x' + Buffer.from(changeBlob.ephemeralPk).toString('hex'),
        ciphertextB64: Buffer.from(changeBlob.ciphertext).toString('base64'),
        ciphertextLen: changeBlob.ciphertext.length,
      },
    ],
    proveMs,
  };
}

// ── Relayer-signed joinsplit (ADR-010) ───────────────────────────────────
//
// Sibling of `prepareWithdrawRelayPayload`. Same trade-offs and same
// "caller is unbound" trick the Anchor program already supports. Top-up
// (`public_value_in > 0`) is rejected server-side because the SPL
// transfer in that branch requires the counterparty's signing
// authority; this function still accepts pure-internal and mid-flow
// withdraw shapes.

export type JoinSplitRelayPayload = {
  network: string
  root_hex: string
  asp_root_hex: string
  public_address_hex: string
  input_nullifiers_hex: [string, string]
  output_commitments_hex: [string, string]
  ephemeral_pks_b64: [string, string]
  encrypted_notes_b64: [string, string]
  spl_counterparty: string
  spl_counterparty_ata: string
  public_value_in: string
  public_value_out: string
  fee: string
  proof_b64: string
}

export type PreparedJoinSplitRelay = {
  payload: JoinSplitRelayPayload
  nullifiers: [bigint, bigint]
  outputCommitments: [bigint, bigint]
  /// Same shape as `PreparedJoinSplitTx.blobs` — the SDK still POSTs
  /// these to /notes/relay-blob AFTER the relay tx confirms, so the
  /// recipient can trial-decrypt. The relay tx ITSELF carries empty
  /// `encrypted_note_*` Vec<u8> (ADR-004 amendment).
  blobs: [
    { commitmentHex: string; ephemeralPkHex: string; ciphertextB64: string; ciphertextLen: number },
    { commitmentHex: string; ephemeralPkHex: string; ciphertextB64: string; ciphertextLen: number },
  ]
  proveMs: number
}

/// Args for the relay flow. Same as `PrepareJoinSplitArgs` minus the
/// `lookupTable` (the server builds a legacy Transaction without LUT
/// since with only one signer the joinsplit ix fits comfortably under
/// the 1232-byte tx size limit).
export type PrepareJoinSplitRelayArgs = Omit<PrepareJoinSplitArgs, 'lookupTable'> & {
  network: string
  /// Sender's wallet pubkey — used to derive the depositor's own ATA
  /// which the on-chain ix struct requires as `spl_counterparty` even
  /// for pure-internal flows (handler short-circuits the SPL movement
  /// when both public values are zero).
  payer: PublicKey
}

export async function prepareJoinSplitRelayPayload(
  args: PrepareJoinSplitRelayArgs,
): Promise<PreparedJoinSplitRelay> {
  // Balance + path reconstruction, mirroring `prepareJoinSplitTransaction`
  // (no shared helper for the same reason as withdraw — keep each
  // path independently auditable).
  const totalIn = args.inputNotes[0].value + args.inputNotes[1].value
  const changeAmount = totalIn - args.recipientAmount - args.fee
  if (changeAmount < 0n) {
    throw new Error(
      `prepareJoinSplitRelayPayload: insufficient input value (have ${totalIn}, need ${args.recipientAmount + args.fee})`,
    )
  }

  const path1 = await buildMerkleTreeFromLeaves(args.allLeaves, args.inputNotes[0].leafIndex, args.cfg.constants.poolDepth)
  const path2 = await buildMerkleTreeFromLeaves(args.allLeaves, args.inputNotes[1].leafIndex, args.cfg.constants.poolDepth)
  if (path1.root !== args.poolRoot || path2.root !== args.poolRoot) {
    throw new Error('prepareJoinSplitRelayPayload: pool root mismatch on reconstruction')
  }

  // Fresh blindings for the two outputs.
  const out1Blinding = randomFieldBytes()
  const out2Blinding = randomFieldBytes()
  const out1BlindingField = bytesToField(out1Blinding)
  const out2BlindingField = bytesToField(out2Blinding)

  // Recipient memo (optional 32-byte tag); change note has no memo.
  const recipientMemo = args.recipientMemo ?? null
  if (recipientMemo && recipientMemo.length !== 32) {
    throw new Error(`prepareJoinSplitRelayPayload: recipientMemo must be 32 bytes, got ${recipientMemo.length}`)
  }
  const recipientMemoField = recipientMemo ? bytesToField(recipientMemo) : 0n

  // Owner_pk per output. Same legacy ADR-003 rule as the tx flow.
  const recipientOwnerPk = args.recipient.spendingPkField
  const changeOwnerPk = args.senderSpendingPkField

  // Witness — identical shape to the tx path; the proof bytes carry
  // the same public-input commitments.
  const witness = {
    inputValue1: args.inputNotes[0].value.toString(10),
    inputOwnerPk1: args.senderSpendingPkField.toString(10),
    inputBlinding1: args.inputNotes[0].blinding.toString(10),
    inputMemo1: args.inputNotes[0].memo.toString(10),
    inputPoolPath1: path1.pathElements.map((e) => e.toString(10)),
    inputPoolIndices1: path1.pathIndices,
    inputAspPath1: args.aspPaths[0].pathElements.map((e) => e.toString(10)),
    inputAspIndices1: args.aspPaths[0].pathIndices,

    inputValue2: args.inputNotes[1].value.toString(10),
    inputOwnerPk2: args.senderSpendingPkField.toString(10),
    inputBlinding2: args.inputNotes[1].blinding.toString(10),
    inputMemo2: args.inputNotes[1].memo.toString(10),
    inputPoolPath2: path2.pathElements.map((e) => e.toString(10)),
    inputPoolIndices2: path2.pathIndices,
    inputAspPath2: args.aspPaths[1].pathElements.map((e) => e.toString(10)),
    inputAspIndices2: args.aspPaths[1].pathIndices,

    spendingSk: args.senderSpendingSkField.toString(10),
    nullifierSk: args.senderNullifierSkField.toString(10),

    outputValue1: args.recipientAmount.toString(10),
    outputOwnerPk1: recipientOwnerPk.toString(10),
    outputBlinding1: out1BlindingField.toString(10),
    outputMemo1: recipientMemoField.toString(10),

    outputValue2: changeAmount.toString(10),
    outputOwnerPk2: changeOwnerPk.toString(10),
    outputBlinding2: out2BlindingField.toString(10),
    outputMemo2: '0',

    publicValueIn: '0',
    publicValueOut: '0',
    publicAddress: '0',
    fee: args.fee.toString(10),
  } as unknown as import('./types').JoinSplitWitness

  const { proofBytes, proveMs } = await proveJoinSplit(witness)

  // Output commitments + nullifiers (derived post-prove so we don't
  // need a separate witness pass).
  const out1Commitment = await poseidonHashFour(args.recipientAmount, recipientOwnerPk, out1BlindingField, recipientMemoField)
  const out2Commitment = await poseidonHashFour(changeAmount, changeOwnerPk, out2BlindingField, 0n)
  const n1 = await deriveNullifierAsync({
    commitment: args.inputNotes[0].commitmentField,
    nullifierSk: args.senderNullifierSkField,
  })
  const n2 = await deriveNullifierAsync({
    commitment: args.inputNotes[1].commitmentField,
    nullifierSk: args.senderNullifierSkField,
  })

  // Encrypt both blobs (recipient + change). Plaintext same shape as
  // the tx path so the recipient's decrypt code is identical.
  const oc1Bytes = fieldToBytes32BE(out1Commitment)
  const oc2Bytes = fieldToBytes32BE(out2Commitment)
  const recipientBlob = encryptNote({
    note: {
      value: args.recipientAmount,
      blinding: out1Blinding,
      ownerPk: fieldToBytes32BE(recipientOwnerPk),
      memo: recipientMemo,
      stealthNonce: null,
      layout: 'legacy',
    },
    recipientViewingPk: args.recipient.viewingPk,
    commitment: oc1Bytes,
  })
  const changeBlob = encryptNote({
    note: {
      value: changeAmount,
      blinding: out2Blinding,
      ownerPk: fieldToBytes32BE(changeOwnerPk),
      memo: null,
      stealthNonce: null,
      layout: 'legacy',
    },
    recipientViewingPk: args.senderViewingPk,
    commitment: oc2Bytes,
  })

  // Pure-internal sub-case: pass payer as spl_counterparty + their
  // ATA. The handler short-circuits SPL movement when both public
  // values are zero, so these accounts are unused on chain but the
  // ix struct requires them.
  const usdcMint = new PublicKey(args.cfg.usdcMint)
  const tokenProgram = new PublicKey(args.cfg.tokenProgramId)
  const atokenProgram = new PublicKey(args.cfg.associatedTokenProgramId)
  const payerAta = deriveAta(usdcMint, args.payer, tokenProgram, atokenProgram)

  const toHex32 = (n: bigint) => '0x' + n.toString(16).padStart(64, '0')

  const payload: JoinSplitRelayPayload = {
    network: args.network,
    root_hex: toHex32(args.poolRoot),
    asp_root_hex: toHex32(args.aspRoot),
    public_address_hex: toHex32(0n),
    input_nullifiers_hex: [toHex32(n1), toHex32(n2)],
    output_commitments_hex: [toHex32(out1Commitment), toHex32(out2Commitment)],
    // The on-chain ix struct includes ephemeral_pk_* even though the
    // Anchor handler ignores them when encrypted_note_* is empty.
    // We pass zeros (matches `prepareJoinSplitTransaction`).
    ephemeral_pks_b64: [
      Buffer.from(new Uint8Array(32)).toString('base64'),
      Buffer.from(new Uint8Array(32)).toString('base64'),
    ],
    encrypted_notes_b64: ['', ''], // off-chain via /notes/relay-blob
    spl_counterparty: args.payer.toBase58(),
    spl_counterparty_ata: payerAta.toBase58(),
    public_value_in: '0',
    public_value_out: '0',
    fee: args.fee.toString(10),
    proof_b64: Buffer.from(proofBytes).toString('base64'),
  }

  return {
    payload,
    nullifiers: [n1, n2],
    outputCommitments: [out1Commitment, out2Commitment],
    blobs: [
      {
        commitmentHex: '0x' + Buffer.from(oc1Bytes).toString('hex'),
        ephemeralPkHex: '0x' + Buffer.from(recipientBlob.ephemeralPk).toString('hex'),
        ciphertextB64: Buffer.from(recipientBlob.ciphertext).toString('base64'),
        ciphertextLen: recipientBlob.ciphertext.length,
      },
      {
        commitmentHex: '0x' + Buffer.from(oc2Bytes).toString('hex'),
        ephemeralPkHex: '0x' + Buffer.from(changeBlob.ephemeralPk).toString('hex'),
        ciphertextB64: Buffer.from(changeBlob.ciphertext).toString('base64'),
        ciphertextLen: changeBlob.ciphertext.length,
      },
    ],
    proveMs,
  }
}

/**
 * Submit a prepared joinsplit relay payload. Same shape as
 * `submitWithdrawViaRelay`. Returns the on-chain tx signature on
 * success; throws with `cause.error` on structured server errors
 * (e.g. `not_relayable`, `already_consumed`).
 */
export async function submitJoinSplitViaRelay(args: {
  apiBaseUrl: string
  payload: JoinSplitRelayPayload
}): Promise<{ signature: string; confirmed: boolean; explorerUrl: string }> {
  const url = new URL(
    'api/private-pool/v2/relay/joinsplit',
    args.apiBaseUrl.endsWith('/') ? args.apiBaseUrl : args.apiBaseUrl + '/',
  )
  const res = await fetch(url.toString(), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(args.payload),
  })
  const body = (await res.json().catch(() => ({}))) as Record<string, unknown>
  if (!res.ok) {
    const err = new Error(
      `relay/joinsplit rejected (HTTP ${res.status}): ${body.error ?? 'unknown'} — ${body.detail ?? ''}`,
    )
    ;(err as Error & { cause?: unknown }).cause = body
    throw err
  }
  return {
    signature: String(body.signature ?? ''),
    confirmed: Boolean(body.confirmed),
    explorerUrl: String(body.explorerUrl ?? ''),
  }
}

// ── Internal helpers ────────────────────────────────────────────────────

function randomFieldBytes(): Uint8Array {
  const out = crypto.getRandomValues(new Uint8Array(32));
  out[0] = out[0] & 0x3f; // keep within BN254 field
  return out;
}

async function poseidonHashFour(a: bigint, b: bigint, c: bigint, d: bigint): Promise<bigint> {
  const p = await getPoseidon();
  const h = p([a, b, c, d]);
  return ((BigInt(p.F.toString(h)) % FIELD_MODULUS) + FIELD_MODULUS) % FIELD_MODULUS;
}

// Re-export the parser so callers don't need to pull `private-pool-keys`
// directly when they're only translating a payment-address string.
export { parsePaymentAddress };

/// Submit a user-signed (sponsored-fee-payer) tx to the backend for
/// fee-payer signing + RPC relay. Returns the cluster signature once
/// the tx confirms (or unconfirmed signature with a `confirmed: false`
/// flag if the cluster lagged on confirmation).
///
/// `signedTx` is the result of `wallet.signTransaction(prepared.transaction)` —
/// user provides their own signature, backend adds fee-payer sig + sends.
export async function relaySponsoredTransaction(args: {
  apiBaseUrl: string;
  network: string;
  signedTx: VersionedTransaction;
}): Promise<{ signature: string; confirmed: boolean }> {
  const url = new URL('api/private-pool/v2/relay-tx', args.apiBaseUrl.endsWith('/') ? args.apiBaseUrl : args.apiBaseUrl + '/');
  url.searchParams.set('network', args.network);
  const r = await fetch(url.toString(), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      tx_b64: Buffer.from(args.signedTx.serialize()).toString('base64'),
    }),
  });
  if (!r.ok) {
    const err = await r.text();
    throw new Error(`relay-tx failed: ${r.status} ${err}`);
  }
  const j = await r.json() as { signature: string; confirmed?: boolean };
  return { signature: j.signature, confirmed: j.confirmed !== false };
}

// ── ADR-012 V3 — unlinkable cashout via credit pool tree ────────────────
//
// V3 differs from ADR-011 v2 in shape:
//   - Park outputs a fresh commitment to the credit pool merkle tree
//     (NOT a per-recipient PDA). The on-chain claim_credit_v3 tx has
//     NO recipient account in its account list — recipient is bound
//     only through the publicAddress hash + the ownerPk inside the
//     encrypted commitment.
//   - Cashout is a ZK proof of membership in the credit pool tree
//     against a fresh credit_nullifier (Poseidon2(commitment,
//     nullifier_sk), like main-pool spends). Recipient pubkey appears
//     only as `recipient_ata` owner check at cashout time, decoupled
//     from any specific Park.
//   - Encrypted blob is keyed by credit_commitment (not by PDA),
//     mirroring main-pool deposit blobs. Discovery is trial-decrypt
//     against the recipient's viewing_sk, just like Send notes.

export type ClaimCreditV3RelayPayload = {
  network: string
  // ── Source-side (Withdraw proof on the pool note being spent) ────
  source_nullifier_hex: string
  source_root_hex: string
  asp_root_hex: string
  public_address_hex: string
  public_value: string
  fee: string
  source_proof_b64: string
  // ── Credit-pool side (new commitment + encrypted blob) ───────────
  credit_commitment_hex: string
  /// Base64 of the encrypted blob — server stores it on chain at the
  /// credit-pool blob PDA `[b"ppv2-enc", pool, credit_commitment]`.
  encrypted_note_b64: string
}

export type PreparedClaimCreditV3Relay = {
  payload: ClaimCreditV3RelayPayload
  /// Source note's nullifier (for indexer correlation + dedup).
  sourceNullifierField: bigint
  /// Credit-pool commitment (for the recipient's cashout flow).
  creditCommitmentField: bigint
  /// Plaintext credit-pool note details (the recipient gets these
  /// by decrypting `encrypted_note_b64` with their viewing_sk — we
  /// expose them here for testing + side-channel persistence).
  creditNote: {
    value: bigint
    blinding: Uint8Array
    ownerPk: Uint8Array
  }
  proveMs: number
}

export async function prepareClaimCreditV3RelayPayload(args: {
  cfg: PrivatePoolV2Config
  /// Source pool note being spent.
  note: {
    value: bigint
    blinding: bigint
    memo: bigint
    commitmentField: bigint
    leafIndex: number
  }
  spendingSkField: bigint
  nullifierSkField: bigint
  /// Recipient's spending_pk field (becomes ownerPk in the new credit
  /// commitment). From payment_address or self-derivation.
  recipientSpendingPkField: bigint
  /// Recipient's viewing_pk (32B) for encrypting the note.
  recipientViewingPk: Uint8Array
  /// Recipient's wallet pubkey — binds the source proof's publicAddress.
  /// Same wallet must show up at cashout time to satisfy ATA owner check.
  recipient: PublicKey
  allLeaves: bigint[]
  poolRoot: bigint
  aspRoot: bigint
  aspPath: { pathElements: bigint[]; pathIndices: number[] }
  publicValue: bigint
  fee: bigint
  network: string
}): Promise<PreparedClaimCreditV3Relay> {
  // 1. Build source merkle path (same as v2 claim_credit).
  const poolPath = await buildMerkleTreeFromLeaves(
    args.allLeaves,
    args.note.leafIndex,
    args.cfg.constants.poolDepth,
  )
  if (poolPath.root !== args.poolRoot) {
    throw new Error(
      `prepareClaimCreditV3RelayPayload: reconstructed pool root ${poolPath.root.toString(16)} != supplied ${args.poolRoot.toString(16)} — stale leaves`,
    )
  }

  // 2. Recipient binding for source proof's publicAddress.
  const publicAddressField = await poseidonAddrHash(args.recipient)

  // 3. Source-side Withdraw proof witness (identical shape to atomic
  // withdraw + v2 claim_credit — no extra fields).
  const p = await getPoseidon()
  const ownerPkField = ((BigInt(p.F.toString(p([args.spendingSkField]))) % FIELD_MODULUS) + FIELD_MODULUS) % FIELD_MODULUS
  const sourceWitness = {
    value: args.note.value.toString(10),
    ownerPk: ownerPkField.toString(10),
    blinding: args.note.blinding.toString(10),
    memo: args.note.memo.toString(10),
    spendingSk: args.spendingSkField.toString(10),
    nullifierSk: args.nullifierSkField.toString(10),
    poolPathElements: poolPath.pathElements.map((e) => e.toString(10)),
    poolPathIndices: poolPath.pathIndices,
    aspPathElements: args.aspPath.pathElements.map((e) => e.toString(10)),
    aspPathIndices: args.aspPath.pathIndices,
    publicValue: args.publicValue.toString(10),
    publicAddress: publicAddressField.toString(10),
    fee: args.fee.toString(10),
  } as unknown as import('./types').WithdrawWitness
  const { proofBytes: sourceProofBytes, proveMs } = await proveWithdraw(sourceWitness)

  // 4. Source-side nullifier — same Poseidon2(commitment, nullifierSk).
  const sourceNullifierField = await deriveNullifierAsync({
    commitment: args.note.commitmentField,
    nullifierSk: args.nullifierSkField,
  })

  // 5. Build the FRESH credit-pool note.
  //   value = recipient amount (after relayer fee carved off)
  //   ownerPk = recipient's spending_pk_field — recipient proves
  //             knowledge at cashout via SpendingPkFromSk(spendingSk)
  //   blinding = fresh random, modular-reduced into BN254 field
  //   memo = 0 (V3 doesn't use the memo slot)
  const creditValue = args.publicValue - args.fee
  if (creditValue <= 0n) {
    throw new Error('prepareClaimCreditV3RelayPayload: creditValue <= 0 (publicValue must exceed fee)')
  }
  const randomFieldBytes32 = (): Uint8Array => {
    const raw = crypto.getRandomValues(new Uint8Array(32))
    let acc = 0n
    for (const b of raw) acc = (acc << 8n) + BigInt(b)
    const reduced = ((acc % FIELD_MODULUS) + FIELD_MODULUS) % FIELD_MODULUS
    return new Uint8Array(fieldToBytes32BE(reduced))
  }
  const blindingBytes = randomFieldBytes32()
  let blindingField = 0n
  for (const b of blindingBytes) blindingField = (blindingField << 8n) + BigInt(b)
  blindingField = ((blindingField % FIELD_MODULUS) + FIELD_MODULUS) % FIELD_MODULUS
  const recipientOwnerPkBytes = fieldToBytes32BE(args.recipientSpendingPkField)

  const creditCommitmentField = await deriveCommitment({
    value: creditValue,
    ownerPk: args.recipientSpendingPkField,
    blinding: blindingField,
    memo: 0n,
  })
  const commitmentBytes = fieldToBytes32BE(creditCommitmentField)

  // 6. Encrypt the fresh credit-pool note for the recipient.
  // Layout matches the main-pool legacy ADR-003 path: 96B ciphertext
  // (no memo, no stealth). On-chain handler accepts this via the
  // existing is_valid_ciphertext_len check.
  const noteForEnc: DecryptedNote = {
    value: creditValue,
    blinding: blindingBytes,
    ownerPk: new Uint8Array(recipientOwnerPkBytes),
    memo: null,
    stealthNonce: null,
    layout: 'legacy',
  }
  const encryptedBlob = encryptNote({
    note: noteForEnc,
    recipientViewingPk: args.recipientViewingPk,
    commitment: new Uint8Array(commitmentBytes),
  })
  // Server expects `ephemeral_pk || ciphertext` packed contiguously
  // for the on-chain `encrypted_note` arg (matches main-pool blob layout).
  const encryptedNoteFull = new Uint8Array(32 + encryptedBlob.ciphertext.length)
  encryptedNoteFull.set(encryptedBlob.ephemeralPk, 0)
  encryptedNoteFull.set(encryptedBlob.ciphertext, 32)

  const toHex32 = (n: bigint) => '0x' + n.toString(16).padStart(64, '0')
  const payload: ClaimCreditV3RelayPayload = {
    network: args.network,
    source_nullifier_hex: toHex32(sourceNullifierField),
    source_root_hex: toHex32(args.poolRoot),
    asp_root_hex: toHex32(args.aspRoot),
    public_address_hex: toHex32(publicAddressField),
    public_value: args.publicValue.toString(10),
    fee: args.fee.toString(10),
    source_proof_b64: Buffer.from(sourceProofBytes).toString('base64'),
    credit_commitment_hex: toHex32(creditCommitmentField),
    encrypted_note_b64: Buffer.from(encryptedNoteFull).toString('base64'),
  }

  return {
    payload,
    sourceNullifierField,
    creditCommitmentField,
    creditNote: {
      value: creditValue,
      blinding: blindingBytes,
      ownerPk: new Uint8Array(recipientOwnerPkBytes),
    },
    proveMs,
  }
}

export async function submitClaimCreditV3ViaRelay(args: {
  apiBaseUrl: string
  payload: ClaimCreditV3RelayPayload
}): Promise<{ signature: string; credit_commitment_hex: string; credit_root_hex: string }> {
  const url = new URL(
    'api/private-pool/v2/relay/claim-credit-v3',
    args.apiBaseUrl.endsWith('/') ? args.apiBaseUrl : args.apiBaseUrl + '/',
  )
  url.searchParams.set('network', args.payload.network)
  const res = await fetch(url.toString(), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(args.payload),
  })
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw new Error(
      `relay/claim-credit-v3 rejected (HTTP ${res.status}): ${(body as any).error ?? 'unknown'} — ${(body as any).detail ?? ''}`,
    )
  }
  return res.json() as Promise<{ signature: string; credit_commitment_hex: string; credit_root_hex: string }>
}

export type CashOutV3RelayPayload = {
  network: string
  credit_nullifier_hex: string
  credit_pool_root_hex: string
  public_address_hex: string
  public_value: string
  fee: string
  recipient: string
  recipient_ata: string
  proof_b64: string
}

export type PreparedCashOutV3Relay = {
  payload: CashOutV3RelayPayload
  creditNullifierField: bigint
  proveMs: number
}

export async function prepareCashOutV3RelayPayload(args: {
  cfg: PrivatePoolV2Config
  /// Credit-pool note being cashed out — recipient decrypted it from
  /// the encrypted blob on the credit-pool tree leaf.
  note: {
    value: bigint
    blinding: bigint
    ownerPkField: bigint
    commitmentField: bigint
    leafIndex: number
  }
  /// Recipient's keys (proves knowledge of spendingSk that matches
  /// note.ownerPk, and derives the credit-pool nullifier).
  spendingSkField: bigint
  nullifierSkField: bigint
  /// Recipient SPL accounts.
  recipient: PublicKey
  recipientAta: PublicKey
  /// Snapshot of all credit-pool leaves for merkle-path reconstruction.
  /// Server's `/credit-pool/leaves` endpoint returns this.
  allCreditLeaves: bigint[]
  creditPoolRoot: bigint
  publicValue: bigint
  fee: bigint
  network: string
}): Promise<PreparedCashOutV3Relay> {
  // 1. Build credit-pool merkle path.
  const creditPath = await buildMerkleTreeFromLeaves(
    args.allCreditLeaves,
    args.note.leafIndex,
    24, // CREDIT_POOL_TREE_DEPTH from ADR-012
  )
  if (creditPath.root !== args.creditPoolRoot) {
    throw new Error(
      `prepareCashOutV3RelayPayload: reconstructed credit root ${creditPath.root.toString(16)} != supplied ${args.creditPoolRoot.toString(16)} — stale credit leaves`,
    )
  }

  // 2. Recipient binding.
  const publicAddressField = await poseidonAddrHash(args.recipient)

  // 3. CashoutProof witness — mirrors Withdraw witness shape minus ASP.
  const witness = {
    value: args.note.value.toString(10),
    ownerPk: args.note.ownerPkField.toString(10),
    blinding: args.note.blinding.toString(10),
    memo: '0',
    spendingSk: args.spendingSkField.toString(10),
    nullifierSk: args.nullifierSkField.toString(10),
    creditPoolPathElements: creditPath.pathElements.map((e) => e.toString(10)),
    creditPoolPathIndices: creditPath.pathIndices,
    publicValue: args.publicValue.toString(10),
    publicAddress: publicAddressField.toString(10),
    fee: args.fee.toString(10),
  } as unknown as import('./types').CashoutProofWitness
  const { proofBytes, proveMs } = await proveCashoutProof(witness)

  // 4. Credit-pool nullifier.
  const creditNullifierField = await deriveNullifierAsync({
    commitment: args.note.commitmentField,
    nullifierSk: args.nullifierSkField,
  })

  const toHex32 = (n: bigint) => '0x' + n.toString(16).padStart(64, '0')
  const payload: CashOutV3RelayPayload = {
    network: args.network,
    credit_nullifier_hex: toHex32(creditNullifierField),
    credit_pool_root_hex: toHex32(args.creditPoolRoot),
    public_address_hex: toHex32(publicAddressField),
    public_value: args.publicValue.toString(10),
    fee: args.fee.toString(10),
    recipient: args.recipient.toBase58(),
    recipient_ata: args.recipientAta.toBase58(),
    proof_b64: Buffer.from(proofBytes).toString('base64'),
  }

  return { payload, creditNullifierField, proveMs }
}

// ── F2 — Bearer-mode park + cashout (private payment codes) ────────────
//
// Bearer mode parks a credit-pool leaf without binding it to a specific
// recipient wallet. The leaf's `owner_pk` is derived from a one-time
// `code_seed`; whoever ends up with the seed can derive the matching
// `spending_sk_field` and cash out to any wallet they choose. The
// `public_address` field in the proof witness is set to 0, signalling
// the on-chain handler to skip the recipient-binding check (per the
// ADR-012 addendum + Anchor change deployed alongside this code).
//
// Why this is safe: the leaf's commitment still binds value + owner_pk
// + blinding. The proof still verifies the prover knew the
// spending_sk that hashes to owner_pk. The credit_nullifier still
// prevents double-spend. The only thing different from a normal park
// is that any wallet — not a specific bound one — can be the
// `recipient` on the cashout side.
//
// This is the primitive behind F2 (private payment codes) and F3
// (public tip jars) in CREDIT_POOL_FEATURE_ROADMAP.md.

/// Park a pool note into a code-bound credit-pool leaf. Returns the
/// prepared relay payload PLUS the `codeKeys` (so the caller can
/// encode `codeKeys.codeSeed` into a redemption URL or QR).
///
/// The caller should NOT show `codeKeys.codeSeed` anywhere except
/// directly to the issuer — once the seed is shared, anyone with it
/// can cash out the leaf. Treat it like the seed phrase of a hot
/// wallet: high blast radius, single-purpose, ephemeral.
export async function prepareClaimCreditV3RelayPayloadAsBearer(args: {
  cfg: PrivatePoolV2Config
  /// Source pool note being spent by the issuer.
  note: {
    value: bigint
    blinding: bigint
    memo: bigint
    commitmentField: bigint
    leafIndex: number
  }
  /// Issuer's keys — proves ownership of the source note.
  spendingSkField: bigint
  nullifierSkField: bigint
  /// Either pass an externally-generated `codeKeys` (when the caller
  /// wants to control the seed lifecycle / persist it for cancel) OR
  /// pass `codeSeed` and let us derive. One must be set.
  codeKeys?: CodeKeyMaterial
  codeSeed?: Uint8Array
  allLeaves: bigint[]
  poolRoot: bigint
  aspRoot: bigint
  aspPath: { pathElements: bigint[]; pathIndices: number[] }
  publicValue: bigint
  fee: bigint
  network: string
}): Promise<PreparedClaimCreditV3Relay & { codeKeys: CodeKeyMaterial }> {
  // 0. Resolve code keys — caller-supplied wins; fall back to deriving
  // from a passed-in seed. Throws if neither is set.
  let codeKeys: CodeKeyMaterial
  if (args.codeKeys) {
    codeKeys = args.codeKeys
  } else if (args.codeSeed) {
    codeKeys = await deriveCodeKeys(args.codeSeed)
  } else {
    throw new Error(
      'prepareClaimCreditV3RelayPayloadAsBearer: must pass codeKeys OR codeSeed',
    )
  }

  // 1. Build source merkle path — identical to the non-bearer path.
  const poolPath = await buildMerkleTreeFromLeaves(
    args.allLeaves,
    args.note.leafIndex,
    args.cfg.constants.poolDepth,
  )
  if (poolPath.root !== args.poolRoot) {
    throw new Error(
      `prepareClaimCreditV3RelayPayloadAsBearer: reconstructed pool root ${poolPath.root.toString(16)} != supplied ${args.poolRoot.toString(16)} — stale leaves`,
    )
  }

  // 2. Source-side Withdraw proof witness. Crucially, `publicAddress`
  // is set to 0 instead of `poseidon_addr_hash(recipient)` — that's
  // what flags this leaf as bearer-mode for the on-chain cashout.
  const sourceWitness = {
    value: args.note.value.toString(10),
    ownerPk: ((await getPoseidon())
      ? '0' // placeholder; reassigned below
      : '0'),
    blinding: args.note.blinding.toString(10),
    memo: args.note.memo.toString(10),
    spendingSk: args.spendingSkField.toString(10),
    nullifierSk: args.nullifierSkField.toString(10),
    poolPathElements: poolPath.pathElements.map((e) => e.toString(10)),
    poolPathIndices: poolPath.pathIndices,
    aspPathElements: args.aspPath.pathElements.map((e) => e.toString(10)),
    aspPathIndices: args.aspPath.pathIndices,
    publicValue: args.publicValue.toString(10),
    publicAddress: '0',
    fee: args.fee.toString(10),
  } as unknown as import('./types').WithdrawWitness
  // Recompute ownerPk properly (the placeholder above keeps TS happy
  // during literal init; the real value is the issuer's spendingPk).
  const p = await getPoseidon()
  const ownerPkField = ((BigInt(p.F.toString(p([args.spendingSkField]))) % FIELD_MODULUS) + FIELD_MODULUS) % FIELD_MODULUS
  ;(sourceWitness as unknown as { ownerPk: string }).ownerPk = ownerPkField.toString(10)
  const { proofBytes: sourceProofBytes, proveMs } = await proveWithdraw(sourceWitness)

  // 3. Source-side nullifier.
  const sourceNullifierField = await deriveNullifierAsync({
    commitment: args.note.commitmentField,
    nullifierSk: args.nullifierSkField,
  })

  // 4. Build the fresh credit-pool leaf — same as cross-wallet park,
  // except the recipient's `spending_pk_field` is the CODE-derived
  // public, not a wallet-derived one. Whoever has `codeSeed` can later
  // derive the matching `spending_sk_field` to satisfy ownership.
  const creditValue = args.publicValue - args.fee
  if (creditValue <= 0n) {
    throw new Error('prepareClaimCreditV3RelayPayloadAsBearer: creditValue <= 0 (publicValue must exceed fee)')
  }
  const randomFieldBytes32 = (): Uint8Array => {
    const raw = crypto.getRandomValues(new Uint8Array(32))
    let acc = 0n
    for (const b of raw) acc = (acc << 8n) + BigInt(b)
    const reduced = ((acc % FIELD_MODULUS) + FIELD_MODULUS) % FIELD_MODULUS
    return new Uint8Array(fieldToBytes32BE(reduced))
  }
  const blindingBytes = randomFieldBytes32()
  let blindingField = 0n
  for (const b of blindingBytes) blindingField = (blindingField << 8n) + BigInt(b)
  blindingField = ((blindingField % FIELD_MODULUS) + FIELD_MODULUS) % FIELD_MODULUS
  const recipientOwnerPkBytes = fieldToBytes32BE(codeKeys.spendingPkField)

  const creditCommitmentField = await deriveCommitment({
    value: creditValue,
    ownerPk: codeKeys.spendingPkField,
    blinding: blindingField,
    memo: 0n,
  })
  const commitmentBytes = fieldToBytes32BE(creditCommitmentField)

  // 5. Encrypt the credit-pool note for the code's viewing key. The
  // redeemer derives the same viewing_sk from the seed and decrypts.
  const noteForEnc: DecryptedNote = {
    value: creditValue,
    blinding: blindingBytes,
    ownerPk: new Uint8Array(recipientOwnerPkBytes),
    memo: null,
    stealthNonce: null,
    layout: 'legacy',
  }
  const encryptedBlob = encryptNote({
    note: noteForEnc,
    recipientViewingPk: codeKeys.viewingPk,
    commitment: new Uint8Array(commitmentBytes),
  })
  const encryptedNoteFull = new Uint8Array(32 + encryptedBlob.ciphertext.length)
  encryptedNoteFull.set(encryptedBlob.ephemeralPk, 0)
  encryptedNoteFull.set(encryptedBlob.ciphertext, 32)

  const toHex32 = (n: bigint) => '0x' + n.toString(16).padStart(64, '0')
  const payload: ClaimCreditV3RelayPayload = {
    network: args.network,
    source_nullifier_hex: toHex32(sourceNullifierField),
    source_root_hex: toHex32(args.poolRoot),
    asp_root_hex: toHex32(args.aspRoot),
    // Bearer mode signal — on-chain cash_out_v3 skips the recipient
    // binding check when this is all-zero (see Anchor addendum).
    public_address_hex: toHex32(0n),
    public_value: args.publicValue.toString(10),
    fee: args.fee.toString(10),
    source_proof_b64: Buffer.from(sourceProofBytes).toString('base64'),
    credit_commitment_hex: toHex32(creditCommitmentField),
    encrypted_note_b64: Buffer.from(encryptedNoteFull).toString('base64'),
  }

  return {
    payload,
    sourceNullifierField,
    creditCommitmentField,
    creditNote: {
      value: creditValue,
      blinding: blindingBytes,
      ownerPk: new Uint8Array(recipientOwnerPkBytes),
    },
    proveMs,
    codeKeys,
  }
}

/// Cash out a code-bound credit-pool leaf to an arbitrary wallet.
/// `args.note` must come from `findCreditPoolLeafByCommitment` (or
/// equivalent — the caller has to know value/blinding/ownerPkField
/// of the leaf, typically obtained by decrypting the on-chain blob
/// with `codeKeys.viewingSk`).
///
/// The proof uses `publicAddress = 0`, matching how the leaf was
/// parked. On-chain cash_out_v3 sees the zero binding and skips the
/// `Poseidon(recipient) == publicAddress` check, allowing any wallet
/// to be the destination.
export async function prepareCashOutV3RelayPayloadAsBearer(args: {
  cfg: PrivatePoolV2Config
  /// Credit-pool leaf being cashed out. Decrypted client-side from
  /// the on-chain blob using the seed-derived viewing_sk.
  note: {
    value: bigint
    blinding: bigint
    ownerPkField: bigint
    commitmentField: bigint
    leafIndex: number
  }
  /// Code keys — derive these once from the seed and reuse for
  /// discovery + cashout. We need `spendingSkField` (for the proof)
  /// and `nullifierSkField` (for the credit_nullifier).
  codeKeys: CodeKeyMaterial
  /// Destination wallet — can be ANY wallet, not bound to anything
  /// committed at park time. SPL transfer lands at this wallet's ATA.
  recipient: PublicKey
  recipientAta: PublicKey
  /// Snapshot of all credit-pool leaves for the merkle-path proof.
  allCreditLeaves: bigint[]
  creditPoolRoot: bigint
  publicValue: bigint
  fee: bigint
  network: string
}): Promise<PreparedCashOutV3Relay> {
  // 1. Reconstruct the credit-pool merkle path.
  const creditPath = await buildMerkleTreeFromLeaves(
    args.allCreditLeaves,
    args.note.leafIndex,
    24, // CREDIT_POOL_TREE_DEPTH from ADR-012
  )
  if (creditPath.root !== args.creditPoolRoot) {
    throw new Error(
      `prepareCashOutV3RelayPayloadAsBearer: reconstructed credit root ${creditPath.root.toString(16)} != supplied ${args.creditPoolRoot.toString(16)} — stale credit leaves`,
    )
  }

  // 2. Cashout proof witness — same shape as the non-bearer path,
  // EXCEPT publicAddress = 0 (mirrors the bearer-mode park witness).
  const witness = {
    value: args.note.value.toString(10),
    ownerPk: args.note.ownerPkField.toString(10),
    blinding: args.note.blinding.toString(10),
    memo: '0',
    spendingSk: args.codeKeys.spendingSkField.toString(10),
    nullifierSk: args.codeKeys.nullifierSkField.toString(10),
    creditPoolPathElements: creditPath.pathElements.map((e) => e.toString(10)),
    creditPoolPathIndices: creditPath.pathIndices,
    publicValue: args.publicValue.toString(10),
    publicAddress: '0',
    fee: args.fee.toString(10),
  } as unknown as import('./types').CashoutProofWitness
  const { proofBytes, proveMs } = await proveCashoutProof(witness)

  // 3. Credit-pool nullifier (Poseidon2(commitment, nullifier_sk),
  // where nullifier_sk is the CODE's, not a wallet's).
  const creditNullifierField = await deriveNullifierAsync({
    commitment: args.note.commitmentField,
    nullifierSk: args.codeKeys.nullifierSkField,
  })

  const toHex32 = (n: bigint) => '0x' + n.toString(16).padStart(64, '0')
  const payload: CashOutV3RelayPayload = {
    network: args.network,
    credit_nullifier_hex: toHex32(creditNullifierField),
    credit_pool_root_hex: toHex32(args.creditPoolRoot),
    // Bearer mode — zero public address. On-chain handler skips
    // the recipient binding check; `args.recipient` is whatever
    // wallet the redeemer wants paid out to.
    public_address_hex: toHex32(0n),
    public_value: args.publicValue.toString(10),
    fee: args.fee.toString(10),
    recipient: args.recipient.toBase58(),
    recipient_ata: args.recipientAta.toBase58(),
    proof_b64: Buffer.from(proofBytes).toString('base64'),
  }

  return { payload, creditNullifierField, proveMs }
}

/// Find a single credit-pool leaf by its commitment hex. Used at
/// redeem time: the issuer's URL carries `commitment=…` alongside
/// `seed=…`, and we look the leaf up directly rather than trial-
/// decrypting every leaf in the tree.
///
/// Returns the leaf's plaintext fields (value, blinding, ownerPk,
/// leafIndex) after decrypting the on-chain blob with the code-
/// derived viewing_sk. Returns null if the leaf doesn't exist or
/// the blob can't be decrypted with the supplied viewing key (= the
/// seed doesn't actually correspond to this leaf).
export async function fetchCreditPoolLeafForBearerRedeem(args: {
  apiBaseUrl: string
  network: string
  commitmentHex: string
  codeKeys: CodeKeyMaterial
}): Promise<{
  value: bigint
  blinding: bigint
  ownerPkField: bigint
  commitmentField: bigint
  leafIndex: number
  alreadySpent: boolean
} | null> {
  const target = args.commitmentHex.toLowerCase().startsWith('0x')
    ? args.commitmentHex.toLowerCase()
    : '0x' + args.commitmentHex.toLowerCase()

  // 1. Pull the credit-pool leaves snapshot + check spent state for
  // each candidate nullifier we can derive from this seed.
  const url = new URL(
    'api/private-pool/v2/credit-pool/leaves',
    args.apiBaseUrl.endsWith('/') ? args.apiBaseUrl : args.apiBaseUrl + '/',
  )
  url.searchParams.set('network', args.network)
  const r = await fetch(url.toString(), { cache: 'no-store' })
  if (!r.ok) return null
  const body = (await r.json()) as {
    leaves: Array<{
      commitment_hex: string
      leaf_index: number
      // The /credit-pool/leaves response joins blob fields inline
      // (not nested under a sub-object). See
      // server/src/routes/private-pool-v2.js:3084-3100.
      ephemeral_pk_hex: string | null
      ciphertext_b64: string | null
      ciphertext_len: number | null
    }>
  }
  const match = body.leaves.find(
    (l) => l.commitment_hex.toLowerCase() === target,
  )
  if (!match) return null
  if (!match.ephemeral_pk_hex || !match.ciphertext_b64) return null

  // 2. Decrypt the blob with the code's viewing_sk.
  const ephPk = Uint8Array.from(Buffer.from(match.ephemeral_pk_hex.replace(/^0x/, ''), 'hex'))
  let ciphertext = Uint8Array.from(Buffer.from(match.ciphertext_b64, 'base64'))
  // V3 blobs may be stored as `ephPk || ciphertext` (128B / 160B); strip
  // the prefix if it matches the blob's ephemeral pk.
  if ((ciphertext.length === 128 || ciphertext.length === 160) && ephPk.length === 32) {
    let matchesPrefix = true
    for (let i = 0; i < 32; i++) {
      if (ciphertext[i] !== ephPk[i]) { matchesPrefix = false; break }
    }
    if (matchesPrefix) ciphertext = ciphertext.slice(32)
  }
  const decrypted = tryDecryptNote({
    blob: {
      ephemeralPk: ephPk,
      ciphertext,
      commitment: Uint8Array.from(Buffer.from(target.replace(/^0x/, ''), 'hex')),
    },
    viewingSk: args.codeKeys.viewingSk,
  })
  if (!decrypted) return null

  // 3. Convert blinding bytes → bigint field. Same reduction the
  // park flow used when generating the blinding.
  let blindingField = 0n
  for (const b of decrypted.blinding) blindingField = (blindingField << 8n) + BigInt(b)
  blindingField = ((blindingField % FIELD_MODULUS) + FIELD_MODULUS) % FIELD_MODULUS
  let ownerPkField = 0n
  for (const b of decrypted.ownerPk) ownerPkField = (ownerPkField << 8n) + BigInt(b)
  ownerPkField = ((ownerPkField % FIELD_MODULUS) + FIELD_MODULUS) % FIELD_MODULUS

  // 4. Spent-state check. Compute the credit_nullifier using the
  // code's nullifier_sk and ask the indexer if it's already used.
  const commitmentField = BigInt(target)
  const credNull = await deriveNullifierAsync({
    commitment: commitmentField,
    nullifierSk: args.codeKeys.nullifierSkField,
  })
  let alreadySpent = false
  try {
    const nullUrl = new URL(
      'api/private-pool/v2/nullifiers/all',
      args.apiBaseUrl.endsWith('/') ? args.apiBaseUrl : args.apiBaseUrl + '/',
    )
    nullUrl.searchParams.set('network', args.network)
    const nr = await fetch(nullUrl.toString(), { cache: 'no-store' })
    if (nr.ok) {
      const nb = (await nr.json()) as { nullifiers?: string[] }
      const credNullHex = '0x' + credNull.toString(16).padStart(64, '0')
      alreadySpent = (nb.nullifiers ?? []).some(
        (n) => n.toLowerCase() === credNullHex.toLowerCase(),
      )
    }
  } catch {
    // Best-effort. If we can't reach the indexer, leave alreadySpent
    // = false; the on-chain cash_out_v3 will fail loudly if it's
    // actually already spent (duplicate nullifier account).
  }

  return {
    value: decrypted.value,
    blinding: blindingField,
    ownerPkField,
    commitmentField,
    leafIndex: match.leaf_index,
    alreadySpent,
  }
}

/// Code-only discovery: given just the code-derived keys (no
/// commitment hint), scan every leaf in the credit-pool tree and
/// trial-decrypt its blob with `codeKeys.viewingSk`. The first leaf
/// that decrypts successfully — and whose `owner_pk` matches our
/// derived `spendingPkField` — is "ours" by construction (the leaf's
/// commitment binds to `Poseidon4(value, owner_pk, blinding, memo)`,
/// and we put exactly this `owner_pk` in at park time).
///
/// Used by the redeem page when the URL fragment carries only `code=`
/// without `commitment=`, or when the user pastes a raw code into the
/// text-input form. Same end result as `fetchCreditPoolLeafForBearerRedeem`,
/// just slower on big trees (scan cost = N × ChaCha20-Poly1305 attempt,
/// ≈ 1–2 ms per leaf in practice).
///
/// Returns `null` when no leaf decrypts — meaning either the code
/// doesn't belong to this network's credit pool, or the park hasn't
/// confirmed yet.
export async function discoverCreditPoolLeafByCodeKeys(args: {
  apiBaseUrl: string
  network: string
  codeKeys: CodeKeyMaterial
}): Promise<{
  value: bigint
  blinding: bigint
  ownerPkField: bigint
  commitmentField: bigint
  commitmentHex: string
  leafIndex: number
  alreadySpent: boolean
} | null> {
  // 1. Pull the credit-pool leaves + blobs in one round-trip.
  const url = new URL(
    'api/private-pool/v2/credit-pool/leaves',
    args.apiBaseUrl.endsWith('/') ? args.apiBaseUrl : args.apiBaseUrl + '/',
  )
  url.searchParams.set('network', args.network)
  const r = await fetch(url.toString(), { cache: 'no-store' })
  if (!r.ok) return null
  const body = (await r.json()) as {
    leaves: Array<{
      commitment_hex: string
      leaf_index: number
      ephemeral_pk_hex: string | null
      ciphertext_b64: string | null
      ciphertext_len: number | null
    }>
  }

  // 2. Pre-compute the spent-nullifier set so we can flag a redeemed
  // leaf in a single response, without a per-row spent check after
  // we find the match.
  let spentSet: Set<string> = new Set()
  try {
    const nullUrl = new URL(
      'api/private-pool/v2/nullifiers/all',
      args.apiBaseUrl.endsWith('/') ? args.apiBaseUrl : args.apiBaseUrl + '/',
    )
    nullUrl.searchParams.set('network', args.network)
    const nr = await fetch(nullUrl.toString(), { cache: 'no-store' })
    if (nr.ok) {
      const nj = (await nr.json()) as { nullifiers?: string[] }
      spentSet = new Set((nj.nullifiers ?? []).map((n) => n.toLowerCase()))
    }
  } catch {
    // Best-effort: if we can't fetch nullifiers, the cashout tx
    // itself will fail loudly on duplicate-nullifier; the UI just
    // won't show the "already spent" hint upfront.
  }

  // 3. Walk every leaf. Trial-decrypt is cheap; we can afford the
  // full scan. First hit wins — by construction a code can only
  // belong to one leaf (the issuer's claim_credit_v3 created
  // exactly one).
  for (const leaf of body.leaves) {
    if (!leaf.ephemeral_pk_hex || !leaf.ciphertext_b64) continue

    const ephPk = Uint8Array.from(
      Buffer.from(leaf.ephemeral_pk_hex.replace(/^0x/, ''), 'hex'),
    )
    let ciphertext = Uint8Array.from(Buffer.from(leaf.ciphertext_b64, 'base64'))
    // V3 blobs may be stored as `ephPk || ciphertext` (128B / 160B);
    // strip the prefix if it matches the blob's ephemeral pk. Same
    // normalisation `fetchCreditPoolLeafForBearerRedeem` applies.
    if ((ciphertext.length === 128 || ciphertext.length === 160) && ephPk.length === 32) {
      let matchesPrefix = true
      for (let i = 0; i < 32; i++) {
        if (ciphertext[i] !== ephPk[i]) { matchesPrefix = false; break }
      }
      if (matchesPrefix) ciphertext = ciphertext.slice(32)
    }

    const target = leaf.commitment_hex.toLowerCase().startsWith('0x')
      ? leaf.commitment_hex.toLowerCase()
      : '0x' + leaf.commitment_hex.toLowerCase()

    const decrypted = tryDecryptNote({
      blob: {
        ephemeralPk: ephPk,
        ciphertext,
        commitment: Uint8Array.from(Buffer.from(target.replace(/^0x/, ''), 'hex')),
      },
      viewingSk: args.codeKeys.viewingSk,
    })
    if (!decrypted) continue

    // Decrypted — but a SUCCESSFUL trial-decrypt only means the blob
    // was encrypted with our viewing key. We still need to check
    // owner_pk binds to our spending_pk_field, otherwise the code
    // belongs to a different recipient who happens to share viewing
    // keys (impossible in practice — both derive deterministically
    // from the same seed — but worth asserting for safety).
    let ownerPkField = 0n
    for (const b of decrypted.ownerPk) ownerPkField = (ownerPkField << 8n) + BigInt(b)
    ownerPkField = ((ownerPkField % FIELD_MODULUS) + FIELD_MODULUS) % FIELD_MODULUS
    if (ownerPkField !== args.codeKeys.spendingPkField) continue

    // Convert blinding bytes → field. Same reduction the park flow
    // used when generating the blinding.
    let blindingField = 0n
    for (const b of decrypted.blinding) blindingField = (blindingField << 8n) + BigInt(b)
    blindingField = ((blindingField % FIELD_MODULUS) + FIELD_MODULUS) % FIELD_MODULUS

    const commitmentField = BigInt(target)

    // Spent-check via the pre-fetched nullifier set.
    const credNull = await deriveNullifierAsync({
      commitment: commitmentField,
      nullifierSk: args.codeKeys.nullifierSkField,
    })
    const credNullHex = '0x' + credNull.toString(16).padStart(64, '0')
    const alreadySpent = spentSet.has(credNullHex.toLowerCase())

    return {
      value: decrypted.value,
      blinding: blindingField,
      ownerPkField,
      commitmentField,
      commitmentHex: target,
      leafIndex: leaf.leaf_index,
      alreadySpent,
    }
  }
  return null
}

export async function submitCashOutV3ViaRelay(args: {
  apiBaseUrl: string
  payload: CashOutV3RelayPayload
}): Promise<{ signature: string }> {
  const url = new URL(
    'api/private-pool/v2/relay/cash-out-v3',
    args.apiBaseUrl.endsWith('/') ? args.apiBaseUrl : args.apiBaseUrl + '/',
  )
  url.searchParams.set('network', args.payload.network)
  const res = await fetch(url.toString(), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(args.payload),
  })
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw new Error(
      `relay/cash-out-v3 rejected (HTTP ${res.status}): ${(body as any).error ?? 'unknown'} — ${(body as any).detail ?? ''}`,
    )
  }
  return res.json() as Promise<{ signature: string }>
}

/// Fetch the current credit-pool merkle leaves for path reconstruction.
/// Returns leaves indexed in insertion order (leaf_index = array index).
export async function fetchCreditPoolLeaves(args: {
  apiBaseUrl: string
  network: string
}): Promise<{ commitmentField: bigint; leafIndex: number }[]> {
  const url = new URL(
    'api/private-pool/v2/credit-pool/leaves',
    args.apiBaseUrl.endsWith('/') ? args.apiBaseUrl : args.apiBaseUrl + '/',
  )
  url.searchParams.set('network', args.network)
  const res = await fetch(url.toString())
  if (!res.ok) {
    throw new Error(`fetchCreditPoolLeaves failed: HTTP ${res.status}`)
  }
  const body = (await res.json()) as {
    leaves: { commitment_hex: string; leaf_index: number }[]
  }
  return body.leaves.map((l) => ({
    commitmentField: BigInt(l.commitment_hex),
    leafIndex: l.leaf_index,
  }))
}

/// Fetch the latest credit-pool merkle root (caller uses it as the
/// `creditPoolRoot` witness input). Server returns the on-chain
/// `latest_root` from the CreditPoolStateAccount.
export async function fetchCreditPoolLatestRoot(args: {
  apiBaseUrl: string
  network: string
}): Promise<bigint> {
  const url = new URL(
    'api/private-pool/v2/credit-pool/root',
    args.apiBaseUrl.endsWith('/') ? args.apiBaseUrl : args.apiBaseUrl + '/',
  )
  url.searchParams.set('network', args.network)
  const res = await fetch(url.toString())
  if (!res.ok) {
    throw new Error(`fetchCreditPoolLatestRoot failed: HTTP ${res.status}`)
  }
  const body = (await res.json()) as { root_hex: string }
  return BigInt(body.root_hex)
}

export type V3CashableCreditPoolNote = {
  /// recipient-amount (post-fee) stored in the note
  value: bigint
  blindingField: bigint
  /// owner_pk field — recipient's spending_pk_field, embedded in commitment
  ownerPkField: bigint
  commitmentField: bigint
  commitmentHex: string
  leafIndex: number
  claimedAtSlot: number
  /// Poseidon2(commitment, nullifier_sk) — for spent-set membership check
  nullifierField: bigint
  spent: boolean
}

/// Discover credit-pool notes this device can cash out. Pulls
/// `/credit-pool/leaves` (which now joins encrypted blobs server-side),
/// trial-decrypts each blob with `viewingSk`, then filters to entries
/// where the decrypted `ownerPk` matches the caller's `spendingPkField`
/// — that's how we tell "this note is mine" without on-chain marker.
///
/// Spent check uses `/nullifiers/all` (same shared spent-set as main
/// pool — every credit_credit_v3 / cash_out_v3 nullifier is in there).
export async function discoverCashableCreditPoolNotesV3(args: {
  apiBaseUrl: string
  network: string
  viewingSk: Uint8Array
  /// Caller's spending_pk_field (Poseidon-1 of spending_sk).
  spendingPkField: bigint
  nullifierSkField: bigint
}): Promise<V3CashableCreditPoolNote[]> {
  // 1. Pull leaves + inline blobs in one round trip.
  const url = new URL(
    'api/private-pool/v2/credit-pool/leaves',
    args.apiBaseUrl.endsWith('/') ? args.apiBaseUrl : args.apiBaseUrl + '/',
  )
  url.searchParams.set('network', args.network)
  const res = await fetch(url.toString())
  if (!res.ok) throw new Error(`discoverCashableCreditPoolNotesV3: HTTP ${res.status}`)
  const body = (await res.json()) as {
    warming_up: boolean
    initialized: boolean
    leaves: Array<{
      commitment_hex: string
      leaf_index: number
      claimed_at_slot: number
      ephemeral_pk_hex: string | null
      ciphertext_b64: string | null
    }>
  }
  if (body.warming_up || !body.initialized) return []

  // 2. Trial-decrypt each blob; filter to those that decode AND whose
  // ownerPk matches our spendingPkField.
  const candidates: V3CashableCreditPoolNote[] = []
  for (const leaf of body.leaves) {
    if (!leaf.ephemeral_pk_hex || !leaf.ciphertext_b64) {
      console.warn('[discoverV3] leaf skipped: no blob', { leaf_index: leaf.leaf_index, commit: leaf.commitment_hex })
      continue
    }
    const ephHex = leaf.ephemeral_pk_hex.startsWith('0x') ? leaf.ephemeral_pk_hex.slice(2) : leaf.ephemeral_pk_hex
    const commitHex = leaf.commitment_hex.startsWith('0x') ? leaf.commitment_hex.slice(2) : leaf.commitment_hex
    const ephPk = Uint8Array.from(Buffer.from(ephHex, 'hex'))
    const commitment = Uint8Array.from(Buffer.from(commitHex, 'hex'))
    let ciphertext = Uint8Array.from(Buffer.from(leaf.ciphertext_b64, 'base64'))
    // V3 quirk: claim_credit_v3 handler stores `encrypted_note` (the full
    // ephPk || ciphertext package, 128B) into the blob's `ciphertext`
    // field — unlike deposit_note which gets ephPk as a separate
    // instruction arg and stores only the pure ciphertext (96B).
    // The frontend tryDecryptNote expects pure ciphertext, so we
    // strip the 32-byte ephPk prefix here when present.
    // Detection: ciphertext_len in (CIPHERTEXT_NO_MEMO + 32,
    // CIPHERTEXT_WITH_MEMO + 32) and the first 32 bytes match the
    // separately-stored ephPk field.
    if ((ciphertext.length === 128 || ciphertext.length === 160) && ephPk.length === 32) {
      const prefix = ciphertext.slice(0, 32)
      let matches = true
      for (let i = 0; i < 32; i++) {
        if (prefix[i] !== ephPk[i]) { matches = false; break }
      }
      if (matches) {
        ciphertext = ciphertext.slice(32)
      }
    }
    const note = tryDecryptNote({
      blob: { ephemeralPk: ephPk, commitment, ciphertext },
      viewingSk: args.viewingSk,
    })
    if (!note) {
      console.warn('[discoverV3] tryDecryptNote returned null', {
        leaf_index: leaf.leaf_index,
        commit: leaf.commitment_hex.slice(0, 18),
        ciphertext_len: ciphertext.length,
      })
      continue
    }
    // Filter: note.ownerPk must match caller's spending_pk. We compare
    // the bigint forms (decoded from BE bytes) because the field
    // element is what the circuit + commitment recompute use.
    let ownerPkField = 0n
    for (const b of note.ownerPk) ownerPkField = (ownerPkField << 8n) + BigInt(b)
    ownerPkField = ((ownerPkField % FIELD_MODULUS) + FIELD_MODULUS) % FIELD_MODULUS
    if (ownerPkField !== args.spendingPkField) {
      console.warn('[discoverV3] ownerPk mismatch', {
        leaf_index: leaf.leaf_index,
        note_ownerPk: '0x' + ownerPkField.toString(16),
        caller_spendingPk: '0x' + args.spendingPkField.toString(16),
      })
      continue
    }
    // blinding field
    let blindingField = 0n
    for (const b of note.blinding) blindingField = (blindingField << 8n) + BigInt(b)
    blindingField = ((blindingField % FIELD_MODULUS) + FIELD_MODULUS) % FIELD_MODULUS
    // Commitment field — recompute from plaintext to make sure the
    // on-chain leaf actually binds the decrypted (value, ownerPk,
    // blinding, 0) tuple. Saves us from acting on tampered storage.
    const recomputedCommitmentField = await deriveCommitment({
      value: note.value,
      ownerPk: ownerPkField,
      blinding: blindingField,
      memo: 0n,
    })
    let commitmentFieldFromHex = 0n
    for (const b of commitment) commitmentFieldFromHex = (commitmentFieldFromHex << 8n) + BigInt(b)
    commitmentFieldFromHex = ((commitmentFieldFromHex % FIELD_MODULUS) + FIELD_MODULUS) % FIELD_MODULUS
    if (recomputedCommitmentField !== commitmentFieldFromHex) {
      console.warn('[discoverV3] commitment recompute mismatch', {
        leaf_index: leaf.leaf_index,
        recomputed: '0x' + recomputedCommitmentField.toString(16),
        on_chain: '0x' + commitmentFieldFromHex.toString(16),
        note_value: note.value.toString(),
        memo_in_note: note.memo ? `bytes[${note.memo.length}]` : 'null',
      })
      continue
    }
    // Nullifier — Poseidon2(commitment, nullifier_sk).
    const nullifierField = await deriveNullifierAsync({
      commitment: recomputedCommitmentField,
      nullifierSk: args.nullifierSkField,
    })
    candidates.push({
      value: note.value,
      blindingField,
      ownerPkField,
      commitmentField: recomputedCommitmentField,
      commitmentHex: '0x' + commitHex,
      leafIndex: leaf.leaf_index,
      claimedAtSlot: leaf.claimed_at_slot,
      nullifierField,
      spent: false,
    })
  }

  // 3. Mark spent based on the shared spent-set.
  if (candidates.length === 0) return []
  try {
    const consumed = await (async () => {
      const u = new URL(
        'api/private-pool/v2/nullifiers/all',
        args.apiBaseUrl.endsWith('/') ? args.apiBaseUrl : args.apiBaseUrl + '/',
      )
      u.searchParams.set('network', args.network)
      const r = await fetch(u.toString())
      if (!r.ok) return new Set<string>()
      const b = (await r.json()) as { nullifiers: string[] }
      return new Set(b.nullifiers.map((n) => n.toLowerCase()))
    })()
    for (const c of candidates) {
      const nHex = '0x' + c.nullifierField.toString(16).padStart(64, '0')
      if (consumed.has(nHex.toLowerCase())) c.spent = true
    }
  } catch {
    // Spent-check best-effort. Leave spent=false on failure; cashout
    // will hit on-chain `already_consumed` if the user tries one.
  }
  return candidates
}

/// POST a JoinSplit blob to the off-chain relay. Caller invokes this AFTER
/// the on-chain tx confirms (otherwise the relay points at a commitment
/// that doesn't exist yet).
export async function relayJoinSplitBlob(args: {
  apiBaseUrl: string;
  network: string;
  blob: PreparedJoinSplitTx['blobs'][number];
  sourceTx?: string;
  senderPubkey?: string;
}): Promise<void> {
  const url = new URL('api/private-pool/v2/notes/relay-blob', args.apiBaseUrl.endsWith('/') ? args.apiBaseUrl : args.apiBaseUrl + '/');
  url.searchParams.set('network', args.network);
  const r = await fetch(url.toString(), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      commitment_hex: args.blob.commitmentHex,
      ephemeral_pk_hex: args.blob.ephemeralPkHex,
      ciphertext_b64: args.blob.ciphertextB64,
      source_tx: args.sourceTx ?? null,
      sender_pubkey: args.senderPubkey ?? null,
    }),
  });
  if (!r.ok) throw new Error(`relayJoinSplitBlob: ${r.status} ${await r.text()}`);
}
