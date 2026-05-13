// Ambient declarations for libraries that don't ship their own types.
// Both circomlibjs and snarkjs are JS-only — we treat them as `any`
// here so the SDK can be typechecked and downstream consumers don't
// need to wire up the same shims.

declare module 'circomlibjs' {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  export const buildPoseidon: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const _default: any;
  export default _default;
}

declare module 'snarkjs' {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  export const groth16: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  export const plonk: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  export const fflonk: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const _default: any;
  export default _default;
}
