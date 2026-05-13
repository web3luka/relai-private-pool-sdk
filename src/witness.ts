// Private Pool V2 — circuit witness builders + crypto helpers.
//
// Off-circuit mirrors of the in-circuit primitives + assembly logic
// that converts (user intent, on-chain state, owned notes) into the
// witness shape that snarkjs.fullProve() expects.
//
// Every primitive here MUST produce the same field element as its
// circom counterpart in `contracts/circuits/private-pool-v2/lib.circom`.
// Conformance is checked by Node-side smoke tests in
// `contracts/scripts/private-pool-v2/`.
//
// Poseidon implementation: `circomlibjs` (already a dep, used by V4).
// Async-init via `loadPoseidonBuilder()` — first call awaits the
// builder, subsequent calls reuse the cached instance.
//
// Reference: ADR-001 (commitment), ADR-002 (key derivation), ADR-003
// (encryption — separate file `private-pool-notes.ts`).

import {
  type DepositWitness,
  type WithdrawWitness,
  type JoinSplitWitness,
  type DecryptedNote,
  type OwnedNote,
  type MerklePath,
  type PaymentAddress,
  POOL_DEPTH,
  ASP_DEPTH,
} from './types'

// ─────────────────────────────────────────────────────────────────────
// Poseidon loader — same pattern as `shielded-private-links.ts`.
// `circomlibjs.buildPoseidon()` returns a callable that takes an array
// of field elements (bigint) and returns a Uint8Array which we lift
// back to bigint via `F.toObject`. We cache the builder promise so
// every call after the first is sync-ish.
// ─────────────────────────────────────────────────────────────────────

interface PoseidonField {
  toObject: (value: unknown) => bigint | string | number
}
interface PoseidonBuilder {
  (inputs: bigint[]): unknown
  F: PoseidonField
}

let poseidonBuilderPromise: Promise<PoseidonBuilder> | null = null

async function loadPoseidonBuilder(): Promise<PoseidonBuilder> {
  if (!poseidonBuilderPromise) {
    poseidonBuilderPromise = import('circomlibjs').then(
      (mod) => (mod as { buildPoseidon: () => Promise<PoseidonBuilder> }).buildPoseidon(),
    )
  }
  return await poseidonBuilderPromise
}

function liftPoseidonResult(builder: PoseidonBuilder, value: unknown): bigint {
  const lifted = builder.F && typeof builder.F.toObject === 'function'
    ? builder.F.toObject(value)
    : value
  const big = BigInt(String(lifted))
  return ((big % FIELD_MODULUS) + FIELD_MODULUS) % FIELD_MODULUS
}

async function poseidonHash(inputs: bigint[]): Promise<bigint> {
  const builder = await loadPoseidonBuilder()
  return liftPoseidonResult(builder, builder(inputs))
}

// ─────────────────────────────────────────────────────────────────────
// Field-element helpers — all circuit signals are BN254 scalar field
// elements. snarkjs accepts them as decimal strings; the bigint API
// keeps the rest of our code reasonable.
// ─────────────────────────────────────────────────────────────────────

/** BN254 scalar field modulus. */
export const FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n

/** Convert 32 little-endian bytes (or fewer; right-padded) to a field element. */
export function bytesToField(bytes: Uint8Array): bigint {
  if (bytes.length > 32) throw new Error('bytesToField: input > 32 bytes')
  let n = 0n
  for (let i = bytes.length - 1; i >= 0; i--) {
    n = (n << 8n) | BigInt(bytes[i] ?? 0)
  }
  return n % FIELD_MODULUS
}

/** Convert a field element to 32 little-endian bytes. */
export function fieldToBytes(n: bigint): Uint8Array {
  const out = new Uint8Array(32)
  let x = ((n % FIELD_MODULUS) + FIELD_MODULUS) % FIELD_MODULUS
  for (let i = 0; i < 32; i++) {
    out[i] = Number(x & 0xffn)
    x >>= 8n
  }
  return out
}

/** Field element → snarkjs witness string (decimal). */
export function fieldStr(n: bigint): string {
  return n.toString(10)
}

// ─────────────────────────────────────────────────────────────────────
// Commitment & nullifier — off-circuit mirrors of lib.circom.
// ─────────────────────────────────────────────────────────────────────

/**
 * Commitment per ADR-001:
 *   commitment = Poseidon4(value, owner_pk, blinding, memo_or_zero)
 */
export async function deriveCommitment(args: {
  value: bigint
  ownerPk: bigint
  blinding: bigint
  memo: bigint | null
}): Promise<bigint> {
  const memo = args.memo ?? 0n
  return poseidonHash([args.value, args.ownerPk, args.blinding, memo])
}

/**
 * Spending pubkey per ADR-002:
 *   spending_pk = Poseidon1(spending_sk)
 */
export async function deriveSpendingPk(spendingSk: bigint): Promise<bigint> {
  return poseidonHash([spendingSk])
}

/**
 * Nullifier per ADR-002:
 *   nullifier = Poseidon2(commitment, nullifier_sk)
 */
export async function deriveNullifier(args: {
  commitment: bigint
  nullifierSk: bigint
}): Promise<bigint> {
  return poseidonHash([args.commitment, args.nullifierSk])
}

/**
 * Merkle node hash per lib.circom MerkleRoot template:
 *   parent = Poseidon2(left, right)
 *
 * Used by witness builders that need to verify their own merkle path
 * against a published root before submitting a proof (catches
 * stale-witness bugs early).
 */
export async function merkleParent(left: bigint, right: bigint): Promise<bigint> {
  return poseidonHash([left, right])
}

/**
 * Recompute a merkle root from a leaf + path. Useful for client-side
 * sanity check ("does my path actually verify against the published
 * root?") before burning proof time.
 */
export async function recomputeMerkleRoot(args: {
  leaf: bigint
  pathElements: bigint[]
  pathIndices: number[]
}): Promise<bigint> {
  if (args.pathElements.length !== args.pathIndices.length) {
    throw new Error('recomputeMerkleRoot: pathElements / pathIndices length mismatch')
  }
  let hash = args.leaf
  for (let i = 0; i < args.pathElements.length; i++) {
    const sibling = args.pathElements[i]!
    const idx = args.pathIndices[i]!
    if (idx !== 0 && idx !== 1) {
      throw new Error(`recomputeMerkleRoot: pathIndices[${i}] must be 0 or 1, got ${idx}`)
    }
    if (idx === 0) {
      hash = await merkleParent(hash, sibling)
    } else {
      hash = await merkleParent(sibling, hash)
    }
  }
  return hash
}

// ─────────────────────────────────────────────────────────────────────
// Owned note enrichment — given a DecryptedNote, fill in the cached
// commitment + nullifier so the rest of the pipeline can reuse them.
// ─────────────────────────────────────────────────────────────────────

export async function enrichOwnedNote(args: {
  note: DecryptedNote
  leafIndex: number
  receivedAtSlot: number
  spent: boolean
  nullifierSk: bigint
}): Promise<OwnedNote> {
  const { note, leafIndex, receivedAtSlot, spent, nullifierSk } = args
  const commitment = await deriveCommitment({
    value: note.value,
    ownerPk: bytesToField(note.ownerPk),
    blinding: bytesToField(note.blinding),
    memo: note.memo ? bytesToField(note.memo) : null,
  })
  const nullifier = await deriveNullifier({ commitment, nullifierSk })
  return {
    ...note,
    leafIndex,
    receivedAtSlot,
    spent,
    commitment: fieldToBytes(commitment),
    nullifier: fieldToBytes(nullifier),
  }
}

// ─────────────────────────────────────────────────────────────────────
// Deposit witness builder.
// ─────────────────────────────────────────────────────────────────────

export interface DepositInputs {
  /** Output note being created. */
  recipient: PaymentAddress
  /** Random 32-byte blinding for the new note. */
  blinding: Uint8Array
  /** Optional 32-byte memo. */
  memo: Uint8Array | null
  /** USDC value entering the pool, in micro-USDC. */
  publicValue: bigint
  /** Hash of the SPL source account (binds proof to caller). */
  depositorAddrHash: bigint
  /** Relayer fee, micro-USDC. */
  fee: bigint
}

export function buildDepositWitness(inputs: DepositInputs): DepositWitness {
  // Note: Deposit witness needs no Poseidon hashing — the circuit
  // computes the commitment from inputs. So this builder stays sync.

  if (inputs.publicValue < 0n) throw new Error('publicValue must be non-negative')
  if (inputs.fee < 0n) throw new Error('fee must be non-negative')
  if (inputs.fee > inputs.publicValue) throw new Error('fee exceeds publicValue')

  return {
    ownerPk: fieldStr(bytesToField(inputs.recipient.spendingPk)),
    blinding: fieldStr(bytesToField(inputs.blinding)),
    memo: fieldStr(inputs.memo ? bytesToField(inputs.memo) : 0n),
    publicValue: fieldStr(inputs.publicValue),
    depositorAddrHash: fieldStr(inputs.depositorAddrHash),
    fee: fieldStr(inputs.fee),
  }
}

// ─────────────────────────────────────────────────────────────────────
// Withdraw witness builder.
// ─────────────────────────────────────────────────────────────────────

export interface WithdrawInputs {
  /** The note being spent (must have spent: false). */
  note: OwnedNote
  /** Caller's spending key (to prove authority). */
  spendingSk: bigint
  /** Caller's nullifier key (to derive `note.nullifier`). */
  nullifierSk: bigint
  /** Pool merkle inclusion proof for `note.commitment`. */
  poolPath: MerklePath
  /** ASP merkle inclusion proof for `note.commitment`. */
  aspPath: MerklePath
  /** Recipient address hash (binds the proof). */
  publicAddress: bigint
  /** USDC paid out to recipient (== note.value − fee). */
  publicValue: bigint
  /** Relayer fee, micro-USDC. */
  fee: bigint
}

export async function buildWithdrawWitness(inputs: WithdrawInputs): Promise<WithdrawWitness> {
  // Sanity checks — fail fast before the prover spends 30s on garbage.
  if (inputs.note.spent) throw new Error('cannot withdraw an already-spent note')
  if (inputs.publicValue + inputs.fee !== inputs.note.value) {
    throw new Error(
      `balance mismatch: publicValue (${inputs.publicValue}) + fee (${inputs.fee}) ` +
      `≠ note.value (${inputs.note.value})`,
    )
  }
  if (inputs.poolPath.pathElements.length !== POOL_DEPTH) {
    throw new Error(`pool path depth ${inputs.poolPath.pathElements.length} ≠ ${POOL_DEPTH}`)
  }
  if (inputs.aspPath.pathElements.length !== ASP_DEPTH) {
    throw new Error(`asp path depth ${inputs.aspPath.pathElements.length} ≠ ${ASP_DEPTH}`)
  }

  // Verify the witness reconstructs to the published root before
  // submitting — catches stale paths or bad indexer data early.
  const leaf = bytesToField(inputs.note.commitment)
  const recomputedPool = await recomputeMerkleRoot({
    leaf,
    pathElements: inputs.poolPath.pathElements.map(bytesToField),
    pathIndices: inputs.poolPath.pathIndices,
  })
  if (recomputedPool !== bytesToField(inputs.poolPath.root)) {
    throw new Error('pool path does not verify against published root')
  }

  return {
    value: fieldStr(inputs.note.value),
    ownerPk: fieldStr(bytesToField(inputs.note.ownerPk)),
    blinding: fieldStr(bytesToField(inputs.note.blinding)),
    memo: fieldStr(inputs.note.memo ? bytesToField(inputs.note.memo) : 0n),
    spendingSk: fieldStr(inputs.spendingSk),
    nullifierSk: fieldStr(inputs.nullifierSk),
    poolPathElements: inputs.poolPath.pathElements.map((b) => fieldStr(bytesToField(b))),
    poolPathIndices: inputs.poolPath.pathIndices,
    aspPathElements: inputs.aspPath.pathElements.map((b) => fieldStr(bytesToField(b))),
    aspPathIndices: inputs.aspPath.pathIndices,
    publicValue: fieldStr(inputs.publicValue),
    publicAddress: fieldStr(inputs.publicAddress),
    fee: fieldStr(inputs.fee),
  }
}

// ─────────────────────────────────────────────────────────────────────
// JoinSplit2x2 witness builder.
// ─────────────────────────────────────────────────────────────────────

export interface JoinSplitInputs {
  /** Two input notes being spent. */
  inputs: [OwnedNote, OwnedNote]
  /** Merkle paths for each input (pool + ASP). */
  inputPoolPaths: [MerklePath, MerklePath]
  inputAspPaths: [MerklePath, MerklePath]

  /** Caller's spending key (must derive to both inputs' ownerPk). */
  spendingSk: bigint
  /** Caller's nullifier key. */
  nullifierSk: bigint

  /** Two output notes being created. */
  outputs: [DecryptedNote, DecryptedNote]

  /** Public-side flow. Set ONE of in/out non-zero, the other to 0n. */
  publicValueIn: bigint
  publicValueOut: bigint
  /** Counterparty hash if publicValueIn or publicValueOut > 0; else 0n. */
  publicAddress: bigint
  /** Relayer fee. */
  fee: bigint
}

export async function buildJoinSplitWitness(inputs: JoinSplitInputs): Promise<JoinSplitWitness> {
  // Hard assertions — fail fast.
  if (inputs.inputs[0].spent || inputs.inputs[1].spent) {
    throw new Error('cannot spend an already-spent note')
  }
  if (
    inputs.inputs[0].commitment.every((b, i) => b === inputs.inputs[1].commitment[i])
  ) {
    throw new Error(
      'both inputs share the same commitment — would produce identical nullifiers; ' +
      'use distinct dummy notes (DUMMY_A vs DUMMY_B from pool config) for padding',
    )
  }
  if (inputs.publicValueIn > 0n && inputs.publicValueOut > 0n) {
    throw new Error('only one of publicValueIn / publicValueOut may be non-zero')
  }

  // Balance equation:
  //   sum(inputValues) + publicValueIn === sum(outputValues) + publicValueOut + fee
  const inputSum = inputs.inputs[0].value + inputs.inputs[1].value
  const outputSum = inputs.outputs[0].value + inputs.outputs[1].value
  const lhs = inputSum + inputs.publicValueIn
  const rhs = outputSum + inputs.publicValueOut + inputs.fee
  if (lhs !== rhs) {
    throw new Error(
      `balance mismatch: ${inputSum} + ${inputs.publicValueIn} (in) ≠ ${outputSum} + ` +
      `${inputs.publicValueOut} (out) + ${inputs.fee} (fee)`,
    )
  }

  // Verify both pool paths against same root (the circuit asserts this).
  const root0 = bytesToField(inputs.inputPoolPaths[0].root)
  const root1 = bytesToField(inputs.inputPoolPaths[1].root)
  if (root0 !== root1) {
    throw new Error('both inputs must verify against the same pool root snapshot')
  }

  // ASP roots same check.
  const asp0 = bytesToField(inputs.inputAspPaths[0].root)
  const asp1 = bytesToField(inputs.inputAspPaths[1].root)
  if (asp0 !== asp1) {
    throw new Error('both inputs must verify against the same ASP root snapshot')
  }

  // Verify each input's witness path against its claimed root —
  // rejects stale or wrong indexer data before we burn 30-60s of CPU.
  for (let i = 0; i < 2; i++) {
    const note = inputs.inputs[i]!
    const poolPath = inputs.inputPoolPaths[i]!
    const aspPath = inputs.inputAspPaths[i]!
    const leaf = bytesToField(note.commitment)
    const recomputedPool = await recomputeMerkleRoot({
      leaf,
      pathElements: poolPath.pathElements.map(bytesToField),
      pathIndices: poolPath.pathIndices,
    })
    if (recomputedPool !== bytesToField(poolPath.root)) {
      throw new Error(`input ${i} pool path does not verify against root`)
    }
    const recomputedAsp = await recomputeMerkleRoot({
      leaf,
      pathElements: aspPath.pathElements.map(bytesToField),
      pathIndices: aspPath.pathIndices,
    })
    if (recomputedAsp !== bytesToField(aspPath.root)) {
      throw new Error(`input ${i} ASP path does not verify against root`)
    }
  }

  // Spend authority sanity — derived spending_pk should match BOTH
  // input notes' ownerPk. Circuit constraint G enforces this; we
  // catch wallet-mixup bugs before the prover.
  const spendingPk = await deriveSpendingPk(inputs.spendingSk)
  for (let i = 0; i < 2; i++) {
    const note = inputs.inputs[i]!
    const ownerField = bytesToField(note.ownerPk)
    if (spendingPk !== ownerField) {
      throw new Error(
        `input ${i} ownerPk does not match the provided spending key — ` +
        `did you switch wallets? expected ${spendingPk}, got ${ownerField}`,
      )
    }
  }

  return {
    inputValue1:       fieldStr(inputs.inputs[0].value),
    inputOwnerPk1:     fieldStr(bytesToField(inputs.inputs[0].ownerPk)),
    inputBlinding1:    fieldStr(bytesToField(inputs.inputs[0].blinding)),
    inputMemo1:        fieldStr(inputs.inputs[0].memo ? bytesToField(inputs.inputs[0].memo) : 0n),
    inputPoolPath1:    inputs.inputPoolPaths[0].pathElements.map((b) => fieldStr(bytesToField(b))),
    inputPoolIndices1: inputs.inputPoolPaths[0].pathIndices,
    inputAspPath1:     inputs.inputAspPaths[0].pathElements.map((b) => fieldStr(bytesToField(b))),
    inputAspIndices1:  inputs.inputAspPaths[0].pathIndices,

    inputValue2:       fieldStr(inputs.inputs[1].value),
    inputOwnerPk2:     fieldStr(bytesToField(inputs.inputs[1].ownerPk)),
    inputBlinding2:    fieldStr(bytesToField(inputs.inputs[1].blinding)),
    inputMemo2:        fieldStr(inputs.inputs[1].memo ? bytesToField(inputs.inputs[1].memo) : 0n),
    inputPoolPath2:    inputs.inputPoolPaths[1].pathElements.map((b) => fieldStr(bytesToField(b))),
    inputPoolIndices2: inputs.inputPoolPaths[1].pathIndices,
    inputAspPath2:     inputs.inputAspPaths[1].pathElements.map((b) => fieldStr(bytesToField(b))),
    inputAspIndices2:  inputs.inputAspPaths[1].pathIndices,

    spendingSk:  fieldStr(inputs.spendingSk),
    nullifierSk: fieldStr(inputs.nullifierSk),

    outputValue1:    fieldStr(inputs.outputs[0].value),
    outputOwnerPk1:  fieldStr(bytesToField(inputs.outputs[0].ownerPk)),
    outputBlinding1: fieldStr(bytesToField(inputs.outputs[0].blinding)),
    outputMemo1:     fieldStr(inputs.outputs[0].memo ? bytesToField(inputs.outputs[0].memo) : 0n),

    outputValue2:    fieldStr(inputs.outputs[1].value),
    outputOwnerPk2:  fieldStr(bytesToField(inputs.outputs[1].ownerPk)),
    outputBlinding2: fieldStr(bytesToField(inputs.outputs[1].blinding)),
    outputMemo2:     fieldStr(inputs.outputs[1].memo ? bytesToField(inputs.outputs[1].memo) : 0n),

    publicValueIn:  fieldStr(inputs.publicValueIn),
    publicValueOut: fieldStr(inputs.publicValueOut),
    publicAddress:  fieldStr(inputs.publicAddress),
    fee:            fieldStr(inputs.fee),
  }
}
