export interface G1 {x: string; y: string;}
export interface Fp2 {c0: string; c1: string;}
export interface G2 {x: Fp2; y: Fp2;}
export interface VerificationKey {alpha: G1; beta: G2; gamma: G2; delta: G2; ic: G1[];}
export interface Proof {a: G1; b: G2; c: G1;}
export interface GeneratedStep {locking: string; unlocking: string;}
export function produceTransaction(vk: VerificationKey, proof: Proof, publicInputs: string[]): GeneratedStep[];
