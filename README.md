# @relai-fi/private-pool-sdk

Client SDK for the RelAI Private Pool — a Sapling-style shielded UTXO pool for USDC on Solana with JoinSplit transfers, recursive credit-pool cashouts, and **unlinkable bearer codes** (short Wi-Fi-style codes or long base58 seeds) that anyone holding the string can redeem to any wallet.

> **Status:** `0.0.1-devnet` — devnet-only. Program ID + circuit artefacts are pinned to the devnet deployment. Not audited.

## What's inside

- **Shielded transfers** — Sapling-style 2-in/2-out JoinSplit, hidden amounts + counterparties
- **Wallet-derived keys** — every Solana wallet gets a deterministic `(viewing_pk, spending_sk)` pair from a one-time signature
- **Bearer payment codes** — issue a code to nobody in particular; whoever holds the string can claim, on any wallet
  - **Long** — 32-byte seed → base58 (~44 chars), full 256-bit entropy
  - **Short** — 10-byte seed → `XXXX-XXXX-XXXX-XXXX` base32, Wi-Fi-style, 80-bit entropy (dictatable over the phone)
- **Public-key registry** — `wallet_pubkey → viewing_pk` lookup so senders can encrypt for a recipient that's never appeared on chain before
- **Encrypted note discovery** — trial-decrypt the on-chain commitment tree to find every note addressed to you

## Install

```bash
npm install @relai-fi/private-pool-sdk@devnet
# peer deps (your app's existing versions are fine):
npm install @solana/web3.js snarkjs
```

## Subpath imports

The SDK ships with per-module entry points. Import from the narrowest subpath that has what you need — the barrel (`@relai-fi/private-pool-sdk`) re-exports everything but pulls in the full transitive surface (snarkjs alone is ~1 MB gzipped).

```ts
import { loadConfig, prepareDepositTransaction } from '@relai-fi/private-pool-sdk/client'
import { derivePrivatePoolKeys, generateCodeSeed, deriveCodeKeys } from '@relai-fi/private-pool-sdk/keys'
import { discoverOwnedNotes } from '@relai-fi/private-pool-sdk/discovery'
import { buildJoinSplitWitness } from '@relai-fi/private-pool-sdk/witness'
```

Available subpaths: `/client`, `/keys`, `/registry`, `/storage`, `/encryption`, `/discovery`, `/witness`, `/prover`, `/types`.

## Quickstart — deposit USDC into the pool

```ts
import { Connection } from '@solana/web3.js'
import { loadConfig, prepareDepositTransaction } from '@relai-fi/private-pool-sdk/client'
import { derivePrivatePoolKeys, buildKeyChallengeMessage } from '@relai-fi/private-pool-sdk/keys'

const connection = new Connection('https://api.devnet.solana.com', 'confirmed')

// 1. Derive per-wallet keys from a one-time signature (Phantom popup).
const challengeBytes = buildKeyChallengeMessage()
const signature = await wallet.signMessage(challengeBytes)
const keys = await derivePrivatePoolKeys(signature)

// 2. Load on-chain config (program ID, USDC mint, ASP registry).
const cfg = await loadConfig({
  apiBaseUrl: 'https://api.relai.fi',
  network: 'solana-devnet',
})

// 3. Build + send the deposit tx.
const prepared = await prepareDepositTransaction({
  cfg,
  keys,
  connection,
  walletPubkey: wallet.publicKey,
  amountMicroUsdc: 100_000n,    // 0.10 USDC
})
const sig = await wallet.sendTransaction(prepared.transaction, connection)
```

## Issue a private payment code (bearer)

A "private payment code" is a string that anyone holding it can redeem out of the issuer's private balance, to any wallet — without the issuer signing the redemption. The issuer parks an encrypted note in the credit-pool tree, and the code itself carries the seed needed to spend it.

There are two formats with identical security model but different ergonomics:

| Format | Encoding                      | Length    | Entropy | When to use                              |
| ------ | ----------------------------- | --------- | ------- | ---------------------------------------- |
| Long   | base58 of 32 bytes            | ~44 chars | 256-bit | URL-only sharing, max security           |
| Short  | base32 dashed: `XXXX-XXXX-…`  | 19 chars  | 80-bit  | Dictatable codes, gift cards, voice/SMS  |

```ts
import {
  generateCodeSeed,
  encodeCodeSeed,
  encodeShortCode,
  deriveCodeKeys,
} from '@relai-fi/private-pool-sdk/keys'
import {
  prepareClaimCreditV3RelayPayloadAsBearer,
} from '@relai-fi/private-pool-sdk/client'

// 1. Generate a fresh seed in the desired format.
const seed = generateCodeSeed('short')          // or 'long'
const codeString = seed.length === 10
  ? encodeShortCode(seed)                       // → 'AIHR-7BXJ-MYDL-AYOU'
  : encodeCodeSeed(seed)                        // → base58 (~44 chars)

// 2. Derive code-bound keys (no wallet signature needed).
const codeKeys = await deriveCodeKeys(seed)

// 3. Park an encrypted note under those keys via your existing
//    private balance (consumes 2 of your own notes, JoinSplit-style).
const claimPayload = await prepareClaimCreditV3RelayPayloadAsBearer({
  cfg,
  issuerKeys: keys,             // YOUR wallet-derived private balance keys
  codeKeys,                     // bearer keys derived from the seed
  notes: ownedNotes,            // 2 unspent notes covering valueMicroUsdc
  amountMicroUsdc: 100_000n,    // 0.10 USDC parked under the code
  walletPubkey: wallet.publicKey,
  connection,
})

// 4. Submit the park tx (you sign once; the code is live after confirmation).
await wallet.sendTransaction(claimPayload.transaction, connection)

// 5. Share `codeString` with the recipient — that's the entire bearer instrument.
//    They never need your wallet address, signature, or balance.
```

## Redeem a private payment code

Receiver only needs the code string and a destination wallet — they don't need a relationship with the issuer, a private balance of their own, or even a Solana wallet that's ever touched the pool before.

```ts
import {
  decodeCodeAuto,
  deriveCodeKeys,
} from '@relai-fi/private-pool-sdk/keys'
import {
  discoverCreditPoolLeafByCodeKeys,
  prepareCashOutV3RelayPayloadAsBearer,
  submitCashOutV3ViaRelay,
} from '@relai-fi/private-pool-sdk/client'

// 1. Decode the code string. Auto-detects short vs long format.
const { seed } = decodeCodeAuto('AIHR-7BXJ-MYDL-AYOU')
const codeKeys = await deriveCodeKeys(seed)

// 2. Scan the credit pool for the note this code unlocks.
//    (Direct lookup by `commitmentHex` is faster — use it when the
//    redeem URL carries `&commitment=…`. Falls back to trial-decryption
//    across all leaves when the receiver only has the raw code.)
const leaf = await discoverCreditPoolLeafByCodeKeys({
  cfg,
  codeKeys,
  apiBaseUrl: 'https://api.relai.fi',
  network: 'solana-devnet',
})
if (!leaf) throw new Error('Code already redeemed or never funded.')

// 3. Build a bearer cash-out — `recipientWallet` is whatever address
//    the receiver wants the USDC delivered to. Can be brand-new.
const cashoutPayload = await prepareCashOutV3RelayPayloadAsBearer({
  cfg,
  codeKeys,
  leaf,
  recipientWallet: new PublicKey('…receiver pubkey…'),
})

// 4. Hand the payload to RelAI's relayer — no wallet signature needed
//    on the receiver side, the relayer pays SOL gas.
const result = await submitCashOutV3ViaRelay({
  apiBaseUrl: 'https://api.relai.fi',
  network: 'solana-devnet',
  payload: cashoutPayload,
})
```

## Module map

| Subpath        | What lives there                                                                                                                                  |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `/client`      | Tx builders: `deposit`, `withdraw`, `join_split`, credit-pool `claim_credit_v3` + `cash_out_v3` (both wallet-bound + bearer variants)             |
| `/keys`        | Wallet-derived viewing/spending keys; code-derived bearer keys; base32 short-code + base58 long-code encoders                                     |
| `/registry`    | Lookup `wallet_pubkey → viewing_pk` for sender-side encryption (send to a recipient that's never appeared on chain)                               |
| `/storage`     | Cached-keys + PIN unlock (browser only — `localStorage` / WebCrypto-AES)                                                                          |
| `/encryption`  | X25519 + ChaCha20-Poly1305 note blobs                                                                                                             |
| `/discovery`   | Trial-decrypt scans of the commitment tree, balance breakdown, spent-status enrichment                                                            |
| `/witness`     | Circuit witnesses + Poseidon helpers (`deriveCommitment`, `deriveNullifier`, `merkleParent`)                                                      |
| `/prover`      | snarkjs Groth16 wrappers (`proveDeposit`, `proveWithdraw`, `proveJoinSplit`, `proveCashoutProof`)                                                 |
| `/types`       | Shared TS types + protocol constants (`POOL_DEPTH`, `ASP_DEPTH`, `USDC_DECIMALS`)                                                                 |

## Peer dependencies

- **`@solana/web3.js`** — `^1.95.0`. The SDK builds `VersionedTransaction`s and reads accounts via your `Connection`.
- **`snarkjs`** — `^0.7.0`. Used by `/prover` for Groth16 witness generation + proving. Heavy (~1 MB gzipped); only import the `/prover` subpath when you actually need to prove client-side.

## Security model (TL;DR)

- **Wallet-bound flows** (deposit / send / withdraw): keys derived from a fixed challenge signature. Losing the wallet but keeping the seed phrase lets you re-derive identical keys → no central recovery, no central leak.
- **Bearer codes**: anyone with the code string can redeem to any wallet. The issuer cannot revoke once issued (they can cash the code out to themselves before anyone else does — first-spend wins). Think "cash" — losing the code = losing the money.
- **ASP screening** (Approved Set Provider, devnet-only today): every deposit gets an `OFAC + chainalysis` screening pass before its note is spendable. Pending/blocked states surface via `/deposit-status/:commitmentHex`. The screening is a compliance gate at deposit time, not a runtime freeze.
- **Not audited.** Trusted-setup ceremony + independent ZK audit are queued before mainnet. Treat devnet balances as test funds.

## License

MIT
