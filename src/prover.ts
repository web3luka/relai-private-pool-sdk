// Private Pool V2 — browser-side Groth16 prover wrapper.
//
// One callable per circuit. Each callable:
//   1. Lazy-loads snarkjs (esm side-import; ~700 KB once cached)
//   2. Calls `groth16.fullProve(witness, wasmUrl, zkeyUrl)`
//   3. Packs the proof into the 256-byte layout the on-chain verifier
//      expects (matches V4 `encodeGroth16Proof` rationale; see
//      `shielded-browser-prover.ts` for the EVM-style G2 swap details)
//   4. Returns `{ proofBytes, publicSignals, proveMs }`
//
// The wrapper is intentionally NOT a Web Worker (yet). snarkjs runs the
// WASM witness generator on the main thread; for joinsplit (~33k constraints)
// fullProve takes ~1s on an M1, ~3-5s on a 5-yr-old laptop. UI freeze is
// noticeable but tolerable as a v1 — Faza 6 promotes this to a worker
// once we have UX progress callbacks.
//
// Wasm/zkey URLs default to the staged artifacts under `/zk/private-pool-v2/`
// (the `zk:build-private-pool-v2` script copies `Deposit.wasm`,
// `deposit_final.zkey`, etc. into `frontend/public/zk/...`).

import type {
  DepositWitness,
  WithdrawWitness,
  JoinSplitWitness,
  CashoutProofWitness,
} from './types';

type SnarkJsModule = typeof import('snarkjs');
type Groth16Proof = {
  pi_a: [string, string, string];
  pi_b: [[string, string], [string, string], [string, string]];
  pi_c: [string, string, string];
  protocol?: string;
  curve?: string;
};

const DEFAULT_ARTIFACT_BASE = '/zk/private-pool-v2';

const ARTIFACTS = {
  deposit: {
    wasm: 'deposit.wasm',
    zkey: 'deposit.zkey',
  },
  withdraw: {
    wasm: 'withdraw.wasm',
    zkey: 'withdraw.zkey',
  },
  joinsplit: {
    wasm: 'joinsplit2x2.wasm',
    zkey: 'joinsplit2x2.zkey',
  },
  /// ADR-012 V3 — cashout from credit pool tree. Smaller circuit
  /// (~7k constraints, depth-24 tree, no ASP layer) so this prover
  /// runs noticeably faster than Withdraw on mid-range hardware.
  cashoutproof: {
    wasm: 'cashoutproof.wasm',
    zkey: 'cashoutproof.zkey',
  },
} as const;

export type CircuitName = keyof typeof ARTIFACTS;

// ── snarkjs loader ───────────────────────────────────────────────────────

let snarkjsModulePromise: Promise<SnarkJsModule> | null = null;
async function loadSnarkJsModule(): Promise<SnarkJsModule> {
  if (!snarkjsModulePromise) {
    // Dynamic import keeps the ~700 KB snarkjs bundle out of the
    // initial JS payload — only loaded when the user actually starts
    // a deposit / withdraw / joinsplit flow.
    snarkjsModulePromise = import('snarkjs') as Promise<SnarkJsModule>;
  }
  return snarkjsModulePromise;
}

// ── Proof byte packing ──────────────────────────────────────────────────
//
// `groth16.exportSolidityCallData` produces the EVM-style ordering with
// G2 Fp2 swap. Solana's alt_bn128_pairing syscall uses the same
// convention, so we forward the swapped output as-is. (Verified end-to-end
// by V4 ASP integration AND by the V2 E2E scripts in
// `contracts/scripts/private-pool-v2/`.)

function fieldToBytes32BE(value: bigint): Uint8Array {
  const hex = value.toString(16).padStart(64, '0');
  return Uint8Array.from(Buffer.from(hex, 'hex'));
}

async function packProofForSolana(
  snarkjs: SnarkJsModule,
  proof: Groth16Proof,
  publicSignals: string[],
): Promise<Uint8Array> {
  if (typeof snarkjs.groth16.exportSolidityCallData !== 'function') {
    throw new Error('snarkjs.groth16.exportSolidityCallData unavailable');
  }
  const rawCalldata = await snarkjs.groth16.exportSolidityCallData(proof, publicSignals);
  const parsed = JSON.parse(`[${rawCalldata}]`) as [
    [string, string],
    [[string, string], [string, string]],
    [string, string],
    string[],
  ];
  const [a, b, c] = parsed;
  const out = new Uint8Array(256);
  out.set(fieldToBytes32BE(BigInt(a[0])), 0);
  out.set(fieldToBytes32BE(BigInt(a[1])), 32);
  out.set(fieldToBytes32BE(BigInt(b[0][0])), 64);
  out.set(fieldToBytes32BE(BigInt(b[0][1])), 96);
  out.set(fieldToBytes32BE(BigInt(b[1][0])), 128);
  out.set(fieldToBytes32BE(BigInt(b[1][1])), 160);
  out.set(fieldToBytes32BE(BigInt(c[0])), 192);
  out.set(fieldToBytes32BE(BigInt(c[1])), 224);
  return out;
}

// ── Generic prove ────────────────────────────────────────────────────────

export type ProveResult = {
  proofBytes: Uint8Array; // 256-byte Solana layout
  publicSignals: string[]; // decimal field-element strings, in circuit order
  proveMs: number;
};

export type ProveOptions = {
  /// Override the default `/zk/private-pool-v2/` artifact base. Useful
  /// for hosting artifacts on a CDN or for swapping in dev artifacts.
  artifactBaseUrl?: string;
};

async function proveCircuit(
  circuit: CircuitName,
  witness: Record<string, unknown>,
  options: ProveOptions = {},
): Promise<ProveResult> {
  const base = (options.artifactBaseUrl ?? DEFAULT_ARTIFACT_BASE).replace(/\/+$/, '');
  const wasm = `${base}/${ARTIFACTS[circuit].wasm}`;
  const zkey = `${base}/${ARTIFACTS[circuit].zkey}`;
  const snarkjs = await loadSnarkJsModule();
  const t0 = (typeof performance !== 'undefined' ? performance : Date).now();
  const { proof, publicSignals } = (await snarkjs.groth16.fullProve(witness, wasm, zkey)) as {
    proof: Groth16Proof;
    publicSignals: string[];
  };
  const proofBytes = await packProofForSolana(snarkjs, proof, publicSignals);
  const proveMs = ((typeof performance !== 'undefined' ? performance : Date).now()) - t0;
  return { proofBytes, publicSignals, proveMs };
}

// ── Per-circuit thin wrappers (typed witnesses) ──────────────────────────

export async function proveDeposit(
  witness: DepositWitness,
  options: ProveOptions = {},
): Promise<ProveResult> {
  return proveCircuit('deposit', witness as unknown as Record<string, unknown>, options);
}

export async function proveWithdraw(
  witness: WithdrawWitness,
  options: ProveOptions = {},
): Promise<ProveResult> {
  return proveCircuit('withdraw', witness as unknown as Record<string, unknown>, options);
}

export async function proveJoinSplit(
  witness: JoinSplitWitness,
  options: ProveOptions = {},
): Promise<ProveResult> {
  return proveCircuit('joinsplit', witness as unknown as Record<string, unknown>, options);
}

/// ADR-012 V3 — cashout from credit pool tree.
export async function proveCashoutProof(
  witness: CashoutProofWitness,
  options: ProveOptions = {},
): Promise<ProveResult> {
  return proveCircuit('cashoutproof', witness as unknown as Record<string, unknown>, options);
}

/// Untyped escape hatch — useful for benchmarks or for circuits not yet
/// type-modelled in `private-pool-types.ts`.
export async function proveAny(
  circuit: CircuitName,
  witness: Record<string, unknown>,
  options: ProveOptions = {},
): Promise<ProveResult> {
  return proveCircuit(circuit, witness, options);
}

/// Hex preview helper for the proof bytes — handy for logging without
/// dumping all 256 bytes.
export function proofPreview(bytes: Uint8Array): string {
  if (bytes.length === 0) return '0x';
  const head = Buffer.from(bytes.slice(0, 8)).toString('hex');
  const tail = Buffer.from(bytes.slice(-8)).toString('hex');
  return `0x${head}…${tail} (${bytes.length} bytes)`;
}
