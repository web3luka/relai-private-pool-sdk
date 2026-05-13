// Public API surface of the Private Pool V2 SDK.
//
// Most files have unique top-level exports and are re-exported via
// `export *`. A handful of names collide between modules — those are
// re-exported explicitly here, with a documented canonical choice.
//
// For granular access (and smaller bundles), import from subpaths:
//   import { ... } from '@relai-fi/private-pool-sdk/client'
//   import { ... } from '@relai-fi/private-pool-sdk/keys'
//   ...

// ── Modules with unique exports ───────────────────────────────────────────

export * from './keys';
export * from './prover';
export * from './registry';
export * from './storage';

// ── Modules with name collisions — selective re-exports ──────────────────

// `types.ts` declares `interface DecryptedNote / OwnedNote / EncryptedNoteBlob`,
// while `encryption.ts` and `discovery.ts` declare `type` aliases of the
// same names with the actual runtime shape. The `type` aliases are the
// canonical definitions; the interfaces in `types.ts` are kept for
// backwards reference only and not re-exported here.
export {
  POOL_DEPTH,
  ASP_DEPTH,
  USDC_DECIMALS,
  type PaymentAddress,
  type PaymentAddressString,
  type MerklePath,
  type DepositWitness,
  type WithdrawWitness,
  type JoinSplitWitness,
  type DepositPublicSignals,
  type WithdrawPublicSignals,
  type JoinSplitPublicSignals,
  type Groth16Proof,
  type DepositTx,
  type WithdrawTx,
  type JoinSplitTx,
  type PoolConfig,
} from './types';

// `encryption.ts` is the canonical home of the note-format types.
export * from './encryption';

// `witness.ts` exports `deriveNullifier(args: {...})` — the comprehensive,
// witness-shape variant. `discovery.ts` exports a smaller
// `deriveNullifier(commitmentField, nullifierSkField)` overload — that one
// is available via the `/discovery` subpath. The barrel exports the
// witness version as canonical.
export {
  fieldToBytes,
  buildDepositWitness,
  buildWithdrawWitness,
  buildJoinSplitWitness,
  recomputeMerkleRoot,
  enrichOwnedNote,
  deriveCommitment,
  deriveNullifier,
  merkleParent,
  type DepositInputs,
  type WithdrawInputs,
  type JoinSplitInputs,
} from './witness';

// `discovery.ts` — re-export the high-level discovery API, but skip
// `deriveNullifier` (already exported from witness.ts above) and the
// `fieldToBytes32BE / poseidon1` re-exports (canonical home is keys.ts).
export {
  fetchCommitmentLeaves,
  fetchEncryptedNoteBlobs,
  fetchNullifierStatus,
  fetchAllNullifiers,
  trialDecryptBlobs,
  discoverOwnedNotes,
  attachSpentStatus,
  attachSpentStatusSequential,
  totalUnspentBalance,
  balanceBreakdown,
  type OwnedNote,
} from './discovery';

// `client.ts` declares its own `fieldToBytes32BE` returning Buffer (used
// internally for PDA derivation). The canonical Uint8Array version lives
// in keys.ts and is exported via `export * from './keys'` above; the
// Buffer version is intentionally not re-exported.
export {
  loadConfig,
  prepareDepositTransaction,
  prepareWithdrawTransaction,
  prepareWithdrawRelayPayload,
  submitWithdrawViaRelay,
  prepareJoinSplitTransaction,
  prepareJoinSplitRelayPayload,
  submitJoinSplitViaRelay,
  relaySponsoredTransaction,
  relayJoinSplitBlob,
  type PrivatePoolV2Config,
  type PrepareDepositArgs,
  type PreparedDepositTx,
  type PrepareWithdrawArgs,
  type PreparedWithdrawTx,
  type PreparedWithdrawRelay,
  type WithdrawRelayPayload,
  type PrepareJoinSplitArgs,
  type PreparedJoinSplitTx,
  type PreparedJoinSplitRelay,
  type PrepareJoinSplitRelayArgs,
  type JoinSplitRelayPayload,
  type JoinSplitNoteRecipient,
} from './client';
