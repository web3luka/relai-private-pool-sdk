import { defineConfig } from 'tsup';

// Build config mirrors the public `exports` map in package.json — every
// subpath consumer can import from gets its own entry point so tsup can
// emit a dedicated chunk and tree-shake unrelated code out.
//
// Why split entries instead of one big bundle:
//   • `/prover` pulls snarkjs (~1 MB gzipped). Apps that only need
//     `/keys` or `/discovery` shouldn't pay that cost.
//   • Per-subpath chunks let bundlers (Next.js / Vite) drop unused
//     entries before they hit the client bundle.
//
// Externals: peer deps + heavy crypto libs stay outside the bundle so
// consumers' own versions take effect (avoids snarkjs / @solana/web3.js
// being doubly loaded). `circomlibjs` is also externalised — it's a
// dep but pulling its full WASM table inline would balloon the bundle.

export default defineConfig({
  entry: [
    'src/index.ts',
    'src/client.ts',
    'src/keys.ts',
    'src/registry.ts',
    'src/storage.ts',
    'src/encryption.ts',
    'src/discovery.ts',
    'src/witness.ts',
    'src/prover.ts',
    'src/types.ts',
  ],
  format: ['esm', 'cjs'],
  dts: true,
  splitting: false,
  sourcemap: true,
  clean: true,
  minify: false,
  target: 'es2020',
  external: [
    '@solana/web3.js',
    'snarkjs',
    'circomlibjs',
  ],
});
