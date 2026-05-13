// Private Pool V2 — concrete TypeScript types.
//
// Single source of truth for shapes flowing between:
//   - Browser key derivation (lib/private-pool-keys.ts)
//   - Note encryption (lib/private-pool-notes.ts)
//   - Witness builder (lib/private-pool-witness.ts)
//   - Browser prover (lib/private-pool-prover.ts)
//   - On-chain submission (api/private-pool/v2/* routes)
//   - Node-side circuit smoke tests (contracts/scripts/private-pool-v2/)
//
// Reference: docs/PRIVATE_POOL_V2_DESIGN.md §17 (Appendix), ADR-001
// (commitment), ADR-002 (key derivation), ADR-003 (encryption).

// ─────────────────────────────────────────────────────────────────────
// Constants — kept in code (not env) because changing them changes
// the circuit + on-chain program; not a runtime tunable.
// ─────────────────────────────────────────────────────────────────────

/** Pool merkle tree depth — 4B notes capacity. */
export const POOL_DEPTH = 32

/** ASP merkle tree depth — same as pool for symmetric witness costs. */
export const ASP_DEPTH = 32

/** USDC base unit (6 decimals → micro-USDC). */
export const USDC_DECIMALS = 6

// ─────────────────────────────────────────────────────────────────────
// Payment address — share-friendly identifier the recipient hands to
// senders. Encodes both spending and viewing public keys (ADR-002).
// ─────────────────────────────────────────────────────────────────────
export interface PaymentAddress {
  /** 32-byte spending public key (Poseidon1(spending_sk)) — used in commitments. */
  spendingPk: Uint8Array
  /** 32-byte X25519 viewing public key — used to encrypt notes for the recipient. */
  viewingPk: Uint8Array
}

/** Base58Check encoding of `spendingPk || viewingPk`. ~88-char string. */
export type PaymentAddressString = string

// ─────────────────────────────────────────────────────────────────────
// Note material — the contents of a single private balance entry.
//
// `commitment` is computed from (value, ownerPk, blinding, memo) per
// ADR-001. `spent` and `leafIndex` are off-chain tracking fields the
// browser maintains; on-chain data only includes the commitment.
// ─────────────────────────────────────────────────────────────────────

export interface DecryptedNote {
  /** Micro-USDC value stored in the note. */
  value: bigint
  /** 32-byte recipient pubkey (== owner spending_pk). */
  ownerPk: Uint8Array
  /** 32-byte random blinding factor. */
  blinding: Uint8Array
  /** Optional 32-byte memo, or null if no memo. */
  memo: Uint8Array | null
}

export interface OwnedNote extends DecryptedNote {
  /** Position in the pool's commitment tree, set when the note was added. */
  leafIndex: number
  /** Slot at which the note was added on chain. */
  receivedAtSlot: number
  /** True iff we've observed a tx that spent this note's nullifier. */
  spent: boolean
  /** Cached commitment (= Poseidon4 of the note fields). */
  commitment: Uint8Array
  /** Cached nullifier (= Poseidon2(commitment, nullifier_sk)). */
  nullifier: Uint8Array
}

// ─────────────────────────────────────────────────────────────────────
// Encrypted note blob — the on-chain (or indexer-served) wire format.
// Per ADR-003: ChaCha20-Poly1305 + X25519 ephemeral.
// ─────────────────────────────────────────────────────────────────────
export interface EncryptedNoteBlob {
  /** 32-byte commitment of the note this blob describes. */
  commitment: Uint8Array
  /** 32-byte X25519 ephemeral public key the sender used. */
  ephemeralPk: Uint8Array
  /** ChaCha20-Poly1305 ciphertext + 16-byte tag (96 bytes for memo-less, 128 with memo). */
  ciphertext: Uint8Array
  /** Slot at which the blob was added on chain. */
  slot: number
  /** Position in the commitment tree (matches OwnedNote.leafIndex). */
  leafIndex: number
}

// ─────────────────────────────────────────────────────────────────────
// Merkle inclusion witness — pool or ASP path proving membership.
// ─────────────────────────────────────────────────────────────────────
export interface MerklePath {
  /** 32-byte hash siblings, leaf-to-root order (length == depth). */
  pathElements: Uint8Array[]
  /** Bit per level: 0 = leaf is left child, 1 = leaf is right child (length == depth). */
  pathIndices: number[]
  /** 32-byte root that this path verifies under. */
  root: Uint8Array
}

// ─────────────────────────────────────────────────────────────────────
// Circuit witnesses — what we feed to snarkjs.fullProve().
//
// Field elements are passed as decimal strings (snarkjs's preferred
// shape). Arrays match circuit signal array sizes (32-deep paths).
// ─────────────────────────────────────────────────────────────────────

/** Witness for `Deposit.circom`. */
export interface DepositWitness {
  // private
  ownerPk: string
  blinding: string
  memo: string

  // public
  publicValue: string
  depositorAddrHash: string
  fee: string
}

/** Witness for `Withdraw.circom`. */
export interface WithdrawWitness {
  // private
  value: string
  ownerPk: string
  blinding: string
  memo: string
  spendingSk: string
  nullifierSk: string

  poolPathElements: string[]   // length POOL_DEPTH
  poolPathIndices: number[]    // length POOL_DEPTH
  aspPathElements: string[]    // length ASP_DEPTH
  aspPathIndices: number[]     // length ASP_DEPTH

  // public
  publicValue: string
  publicAddress: string
  fee: string
}

/** Witness for `CashoutProof.circom` (ADR-012 V3). */
export interface CashoutProofWitness {
  // private
  value: string
  ownerPk: string
  blinding: string
  memo: string
  spendingSk: string
  nullifierSk: string

  // Credit-pool merkle inclusion (depth 24).
  creditPoolPathElements: string[]
  creditPoolPathIndices: number[]

  // public
  publicValue: string
  publicAddress: string
  fee: string
}

/** Witness for `JoinSplit2x2.circom`. */
export interface JoinSplitWitness {
  // ── input note 1 ──
  inputValue1: string
  inputOwnerPk1: string
  inputBlinding1: string
  inputMemo1: string
  inputPoolPath1: string[]
  inputPoolIndices1: number[]
  inputAspPath1: string[]
  inputAspIndices1: number[]

  // ── input note 2 ──
  inputValue2: string
  inputOwnerPk2: string
  inputBlinding2: string
  inputMemo2: string
  inputPoolPath2: string[]
  inputPoolIndices2: number[]
  inputAspPath2: string[]
  inputAspIndices2: number[]

  // ── spending authority ──
  spendingSk: string
  nullifierSk: string

  // ── output note 1 ──
  outputValue1: string
  outputOwnerPk1: string
  outputBlinding1: string
  outputMemo1: string

  // ── output note 2 ──
  outputValue2: string
  outputOwnerPk2: string
  outputBlinding2: string
  outputMemo2: string

  // ── public inputs ──
  publicValueIn: string
  publicValueOut: string
  publicAddress: string
  fee: string
}

// ─────────────────────────────────────────────────────────────────────
// Public signals — what the verifier consumes after fullProve().
//
// Order matches circom's "outputs in source order, then public inputs
// alphabetical" — see circuit headers for canonical layout. The
// on-chain program reads these in the same order.
// ─────────────────────────────────────────────────────────────────────

export interface DepositPublicSignals {
  /** outputCommitment */
  outputCommitment: string
  /** depositorAddrHash */
  depositorAddrHash: string
  /** fee */
  fee: string
  /** publicValue */
  publicValue: string
}

export interface WithdrawPublicSignals {
  /** nullifier */
  nullifier: string
  /** root */
  root: string
  /** aspRoot */
  aspRoot: string
  /** fee */
  fee: string
  /** publicAddress */
  publicAddress: string
  /** publicValue */
  publicValue: string
}

export interface JoinSplitPublicSignals {
  /** inputNullifier1 */
  inputNullifier1: string
  /** inputNullifier2 */
  inputNullifier2: string
  /** outputCommitment1 */
  outputCommitment1: string
  /** outputCommitment2 */
  outputCommitment2: string
  /** root */
  root: string
  /** aspRoot */
  aspRoot: string
  /** fee */
  fee: string
  /** publicAddress */
  publicAddress: string
  /** publicValueIn */
  publicValueIn: string
  /** publicValueOut */
  publicValueOut: string
}

// ─────────────────────────────────────────────────────────────────────
// Proof + tx envelopes — what the client sends to the server route.
// ─────────────────────────────────────────────────────────────────────

export interface Groth16Proof {
  pi_a: string[]
  pi_b: string[][]
  pi_c: string[]
  protocol: 'groth16'
  curve: 'bn128'
}

export interface DepositTx {
  proof: Groth16Proof
  publicSignals: DepositPublicSignals
  encryptedNote: EncryptedNoteBlob
}

export interface WithdrawTx {
  proof: Groth16Proof
  publicSignals: WithdrawPublicSignals
}

export interface JoinSplitTx {
  proof: Groth16Proof
  publicSignals: JoinSplitPublicSignals
  /** Length 2; one blob per output commitment. */
  encryptedNotes: [EncryptedNoteBlob, EncryptedNoteBlob]
}

// ─────────────────────────────────────────────────────────────────────
// Pool config — fetched at /api/private-pool/v2/config.
// ─────────────────────────────────────────────────────────────────────

export interface PoolConfig {
  /** Solana program ID hosting the pool (or EVM contract address). */
  programId: string
  /** USDC mint / token contract for this pool. */
  usdcMint: string
  /** Relayer pubkey (sponsored fee payer). */
  relayerAddress: string
  /** Network identifier — `solana-devnet`, `solana`, etc. */
  network: string
  /** Current pool merkle root (hex). */
  currentRoot: string
  /** Most recent ASP root (hex). */
  currentAspRoot: string
  /** Snapshot age — seconds since the ASP root was published. */
  aspAgeSeconds: number
  /** 32-byte commitment of `DUMMY_A` — used to pad single-input JoinSplits. */
  dummyACommitment: string
  /** 32-byte commitment of `DUMMY_B` — used in 0-input edge cases. */
  dummyBCommitment: string
}
