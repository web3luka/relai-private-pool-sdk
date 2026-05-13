# @relai-fi/private-pool-sdk

Client SDK for the RelAI Private Pool V2 — a Sapling-style shielded UTXO pool for USDC on Solana with JoinSplit transfers, recursive credit-pool cashouts, and unlinkable bearer codes.

> **Status:** `0.0.1-devnet` — devnet-only. Program ID + circuit artifacts are tied to the devnet deployment. Not audited.

## Install

```bash
npm install @relai-fi/private-pool-sdk@devnet
# peer deps:
npm install @solana/web3.js snarkjs
```

## Subpath imports

The SDK is shipped as ESM with per-module entry points. Import from the narrowest subpath that has what you need — the barrel (`@relai-fi/private-pool-sdk`) re-exports everything but pulls in the full transitive surface.

```ts
import { loadConfig, prepareDepositTransaction } from '@relai-fi/private-pool-sdk/client'
import { derivePrivatePoolKeys, generateCodeSeed } from '@relai-fi/private-pool-sdk/keys'
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
const sig = await wallet.signMessage(buildKeyChallengeMessage())
const keys = await derivePrivatePoolKeys(sig)

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

## Module map

| Subpath        | What lives there                                                                  |
| -------------- | --------------------------------------------------------------------------------- |
| `/client`      | Tx builders for `deposit`, `withdraw`, `join_split`, V3 credit-pool flows         |
| `/keys`        | Wallet-derived viewing/spending keys, code-derived bearer keys, short-code base32 |
| `/registry`    | Lookup `wallet_pubkey → viewing_pk` for sender-side encryption                    |
| `/storage`     | Cached-keys + PIN unlock (browser only)                                           |
| `/encryption`  | X25519 + ChaCha20-Poly1305 note blobs                                             |
| `/discovery`   | Trial-decrypt scans, balance breakdown, spent-status enrichment                   |
| `/witness`     | Circuit witnesses + Poseidon helpers (`deriveCommitment`, `deriveNullifier`)      |
| `/prover`      | snarkjs Groth16 wrappers (`proveDeposit`, `proveWithdraw`, `proveJoinSplit`)      |
| `/types`       | Shared TS types + protocol constants (`POOL_DEPTH`, `ASP_DEPTH`, `USDC_DECIMALS`) |

## Peer dependencies

- **`@solana/web3.js`** — `^1.95.0`. The SDK builds `VersionedTransaction`s and reads accounts via your `Connection`.
- **`snarkjs`** — `^0.7.0`. Used by `/prover` for Groth16 witness generation + proving. Heavy (~1 MB gzipped); only import the `/prover` subpath when you actually need to prove.

## License

MIT
