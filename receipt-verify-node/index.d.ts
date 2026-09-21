export const VERSION: string;
export interface Jwk { kty: string; kid?: string; n?: string; e?: string; alg?: string; use?: string }
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
}
export function verifyToken(token: string, jwks: JwksInput, opts?: { now?: number; issuer?: string | null }): VerificationResult;
export function verify(token: string, jwks: JwksInput, opts?: { request?: RequestInput; mandateReveal?: MandateReveal; policyReveal?: PolicyReveal | string; now?: number; issuer?: string | null }): VerificationResult;
export function canonicalArgsHash(tool: string, action: string, resource: string | null | undefined, args: Record<string, unknown> | undefined): string;
export function checkRequestBinding(claims: Record<string, unknown>, request: RequestInput): boolean;
export const MANDATE_FIELDS: string[];
export function mandateCanonicalString(snapshot: MandateSnapshot, salt: string): string;
export function mandateCommitment(snapshot: MandateSnapshot, salt: string): string;
export function checkMandateReveal(claims: Record<string, unknown>, reveal: MandateReveal): boolean;
export function policyCanonicalString(orgId: string, version: number, cedarText: string, profile: Record<string, unknown> | null, salt: string): string;
export function policyCommitment(orgId: string, version: number, cedarText: string, profile: Record<string, unknown> | null, salt: string): string;
export function checkPolicyReveal(claims: Record<string, unknown>, reveal: PolicyReveal | string): boolean;
