export const VERSION: string;
export interface Jwk { kty: string; kid?: string; n?: string; e?: string; crv?: string; x?: string; y?: string; alg?: string; use?: string }
export interface Jwks { keys: Jwk[] }
export type JwksInput = Jwks | Jwk | Array<Jwks | Jwk>;
export interface RequestInput { tool: string; action: string; resource?: string | null; args?: Record<string, unknown> }
export interface MandateSnapshot {
  mandate_id: string; version: number; agent_id: string; owner_id: string; currency: string; settlement_chain: string;
  status: string; per_tx_limit: string | null; daily_limit: string | null; monthly_limit: string | null;
  per_entity_limit: string | null; entity_key: string | null; relational_cap: boolean; expires_at: string | null;
  agent_may_read_limits: boolean;
}
export type MandateReveal = { snapshot: MandateSnapshot; salt: string; version?: number } | (MandateSnapshot & { salt: string });
export interface PolicyReveal { org_id?: string; version?: number; cedar_text?: string; cedar?: string; profile?: Record<string, unknown> | null; salt?: string }
export interface VerificationResult {
  readonly valid: boolean;
  signatureValid: boolean;
  kind: "receipt" | "allow" | "budget" | "unknown";
  header: Record<string, unknown>;
  claims: Record<string, unknown>;
  kid: string | null;
  expired: boolean | null;
  errors: string[];
  warnings: string[];
  argsHashMatch: boolean | null;
  mandateMatch: boolean | null;
  policyMatch: boolean | null;
  /** the counterparty's settlement confirmation embedded in the receipt, re-verified against its JWKS (null when none was supplied) */
  confirmationMatch: boolean | null;
  confirmationErrors: string[];
  confirmation: Record<string, unknown> | null;
}
export interface ConfirmationCheck { ok: boolean; errors: string[]; issuer: string | null; kid: string | null; claims: Record<string, unknown> }
export const CONFIRMATION_TYP: string;
export const CONFIRMATION_ALGS: string[];
export function checkConfirmation(claims: Record<string, unknown>, counterpartyJwks: JwksInput, opts?: { now?: number }): ConfirmationCheck;
/** `now`: epoch seconds to judge exp and iat against; undefined or null = the current time. */
export function verifyToken(token: string, jwks: JwksInput, opts?: { now?: number | null; issuer?: string | null }): VerificationResult;
/** Any option name not listed here is an error in the result. `now`: epoch seconds, or undefined/null for the current time; a value that is not a finite number is an error. */
export function verify(token: string, jwks: JwksInput, opts?: { request?: RequestInput; mandateReveal?: MandateReveal; policyReveal?: PolicyReveal | string; payeeReveal?: { payee: string; salt: string }; counterpartyJwks?: JwksInput; now?: number | null; issuer?: string | null }): VerificationResult;
export function canonicalArgsHash(tool: string, action: string, resource: string | null | undefined, args: Record<string, unknown> | undefined): string;
export function checkRequestBinding(claims: Record<string, unknown>, request: RequestInput): boolean;
export const MANDATE_FIELDS: string[];
export function mandateCanonicalString(snapshot: MandateSnapshot, salt: string): string;
export function mandateCommitment(snapshot: MandateSnapshot, salt: string): string;
export function checkMandateReveal(claims: Record<string, unknown>, reveal: MandateReveal): boolean;
export function policyCanonicalString(orgId: string, version: number, cedarText: string, profile: Record<string, unknown> | null, salt: string): string;
export function policyCommitment(orgId: string, version: number, cedarText: string, profile: Record<string, unknown> | null, salt: string): string;
export function checkPolicyReveal(claims: Record<string, unknown>, reveal: PolicyReveal | string): boolean;

/** The approval evidence a bundle carries, as far as this version looks at it: its bytes are compared with the digest in the receipt and nothing inside it is read. */
export interface SignedApproval {
  label: string;
  /** its bytes hash to the digest a verified receipt names */
  anchored: boolean;
  evidence_ok: boolean | null;
  /** always null: this version does not verify the owner's signature */
  signature_ok: null;
  /** always null: this version returns no terms */
  terms: null;
  errors: string[]; ok: boolean;
}
/** What this version says about the owner's approval. It compares the evidence with the digest in a verified receipt and does NOT verify the owner's signature: `verdict` is "NOT CHECKED" or "INVALID", never anything better, and `valid` is never true. The bundle's own `valid` and the process exit code do not say what was checked about the approval: read `verdict`. */
export interface ApprovalResult {
  /** the answer in one word, in this program's own words */
  verdict: "NOT CHECKED" | "INVALID";
  /** one short reason for the verdict, in this program's own words */
  why: string;
  /** false = the block contradicts the receipt (the bundle is then invalid); null otherwise. Never true in this version. */
  valid: false | null;
  /** always null in this version */
  consistent: null;
  record: string | null;
  /** the receipt's, never the block's */
  method: string | null; scope: string | null; names: string | null;
  /** always null in this version */
  terms: null;
  /** the organization's own statements (dates, approver id, applied): not verified */
  stated: Record<string, string>;
  signed: SignedApproval | null;
  /** always empty: listed changes to a mandate are counted (`changes_listed`), not checked */
  changes: never[]; changes_listed: number;
  errors: string[]; warnings: string[];
}
/** These options pin the owner's key and site in versions that verify the owner's signature. This version does not: passing any of them (to verifyApproval or verifyBundle, with or without an approval in the bundle) is an error in the result, so that a requirement that cannot be enforced never looks as if it was. */
export interface ApprovalOptions {
  approverKeys?: string[];
  origins?: string[];
  rpIds?: string[];
}
/** Compare a bundle's `approval` block with the claims of a receipt YOU verified with a key YOU hold (null = no such receipt: nothing is compared). The claims are trusted as given: pass nothing you did not verify. Never throws. */
export function verifyApproval(approval: unknown, receiptClaims?: Record<string, unknown> | null, options?: ApprovalOptions): ApprovalResult;

export const BUNDLE_VERSION: string;
/** Any option name not listed here makes the result invalid, and nothing is verified. */
export interface BundleOptions extends ApprovalOptions {
  /** saved receipt keys; without them the receipt (and so the approval) is checked only against the key inside the bundle */
  receiptJwks?: JwksInput;
  /** saved checkpoint keys; without them the bundle's own are used and a warning says so */
  checkpointJwks?: JwksInput;
  /** Solana JSON-RPC URL: also check the append and anchor transactions on the network */
  rpc?: string;
  now?: number;
  /** roots to trust for RFC 3161 timestamps inside the bundle: PEM text (string or bytes), certificates, or a list of those; undefined or null for the packaged DigiCert and Sectigo roots. Any item that holds no usable certificate makes the result invalid. */
  tsaRoots?: null | string | Uint8Array | import("node:crypto").X509Certificate | Array<string | Uint8Array | import("node:crypto").X509Certificate>;
}
export interface BundleResult {
  valid: boolean;
  decision_id: string | null;
  events: Array<Record<string, unknown>>;
  receipt_valid: boolean | null; receipt_anchored: boolean | null;
  receipt_claims: Record<string, unknown>;
  links_ok: boolean | null; rpc_ok: boolean | null; rpc_checks: Array<Record<string, unknown>>;
  /** null when the bundle carries no approval block and the receipt names no approval. Its `verdict` is separate from the bundle's `valid`. */
  approval: ApprovalResult | null;
  /** "receipt" when a receipt valid in full names this decision, so the approval evidence could be compared with it, else null. The receipt key may still be the bundle's own: a warning then says so. */
  approval_anchor: string | null;
  errors: string[]; warnings: string[];
}
/** Verify an evidence bundle offline. Never throws: a value that is not a bundle of the defined shape is an invalid result (`bundle is malformed: …`). An approval block that contradicts the receipt makes the bundle invalid; a valid bundle does not mean the approval was verified, and in this version it never is: read `approval.verdict`. */
export function verifyBundle(bundle: unknown, options?: BundleOptions): Promise<BundleResult>;
export function merkleRootFrom(leaf: string, proof: string[], index: number): string;
export function checkTxCarriesRoot(rpcUrl: string, signature: string, programId: string, rootHex: string): Promise<{ tx: string; found: boolean; succeeded: boolean | null; root_in_instruction: boolean; ok?: boolean; error?: string }>;
