import type { AppealStatus, Classification, IncidentStatus } from "./types";

export const VERDICT_LABEL: Record<Classification, string> = {
  ALIGNED: "Aligned",
  SUSPICIOUS_OMISSION: "Suspicious omission",
  CRITICAL_MALICIOUS_PAYLOAD: "Critical payload",
};

export const VERDICT_GLYPH: Record<Classification, string> = {
  ALIGNED: "=",
  SUSPICIOUS_OMISSION: "≈",
  CRITICAL_MALICIOUS_PAYLOAD: "≠",
};

export const STATUS_LABEL: Record<IncidentStatus, string> = {
  DISMISSED: "Dismissed",
  PENDING_CHALLENGE: "Challenge window open",
  APPEALED: "Under appeal",
  CONFIRMED: "Verdict upheld",
  OVERTURNED: "Overturned",
  INCONCLUSIVE: "Inconclusive",
  PAID: "Paid out",
  EXPIRED: "Refunded",
};

export const APPEAL_LABEL: Record<AppealStatus, string> = {
  PENDING: "Awaiting ruling",
  UPHELD: "Appeal upheld",
  REJECTED: "Appeal rejected",
  INCONCLUSIVE: "Inconclusive",
};

// Contract error codes -> what the person can do about it.
const ERROR_TEXT: Record<string, string> = {
  ERR_INSUFFICIENT_BOND: "The bond is below the minimum for this action.",
  ERR_CHALLENGE_WINDOW_ACTIVE: "The challenge window is still open. Payouts unlock when it closes.",
  ERR_CHALLENGE_WINDOW_CLOSED: "The challenge window has closed, so this incident can no longer be appealed.",
  ERR_MALFORMED_CALLDATA: "The calldata is malformed. It needs 0x, a 4-byte selector, and whole 32-byte argument words.",
  ERR_INVALID_ADDRESS: "The target contract must be a non-zero 0x address with 40 hex characters.",
  ERR_INVALID_INPUT: "One of the inputs is out of range. Check lengths and amounts.",
  ERR_EMPTY_REBUTTAL: "The rebuttal is empty.",
  ERR_UNBOUND_REBUTTAL: "The rebuttal must quote this incident's calldata hash.",
  ERR_UNKNOWN_DAO: "That DAO is not registered.",
  ERR_UNKNOWN_INCIDENT: "That incident does not exist.",
  ERR_DUPLICATE_INCIDENT: "This proposal already has an open incident.",
  ERR_DUPLICATE_DAO: "That timelock is already registered.",
  ERR_INVALID_STATE: "This action is not available at the incident's current stage.",
  ERR_SELF_APPEAL: "Reporters cannot appeal their own flag.",
  ERR_UNAUTHORIZED: "Only the owner or registrant can do this.",
  ERR_NOTHING_TO_CLAIM: "There is nothing to withdraw for this account.",
  ERR_TRANSFER: "The transfer could not be queued. Try again.",
  LLM_ERROR: "Validators could not agree on a verdict. Try again.",
};

export function explainError(raw: string): string {
  const code = raw.match(/ERR_[A-Z_]+|LLM_ERROR/)?.[0];
  if (code && ERROR_TEXT[code]) return ERROR_TEXT[code];
  if (/user rejected|denied/i.test(raw)) return "The wallet request was declined.";
  if (/insufficient funds/i.test(raw)) return "This account does not have enough GEN for the bond and fees.";
  return raw.length > 220 ? `${raw.slice(0, 220)}…` : raw;
}
