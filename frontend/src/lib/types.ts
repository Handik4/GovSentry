export type Classification = "ALIGNED" | "SUSPICIOUS_OMISSION" | "CRITICAL_MALICIOUS_PAYLOAD";

export type IncidentStatus =
  | "DISMISSED"
  | "PENDING_CHALLENGE"
  | "APPEALED"
  | "CONFIRMED"
  | "OVERTURNED"
  | "INCONCLUSIVE"
  | "PAID"
  | "EXPIRED";

export type AppealStatus = "PENDING" | "UPHELD" | "REJECTED" | "INCONCLUSIVE";

export interface ArgumentWord {
  word: string;
  as_uint: string;
  as_address?: string;
}

export interface Disassembly {
  selector: string;
  signature: string;
  privileged: boolean;
  argument_words: ArgumentWord[];
}

export interface Dao {
  dao_id: number;
  registrant: string;
  target_timelock: string;
  name: string;
  description_url: string;
  bounty_escrow: string;
  selector_schema: string;
  registered_at: number;
}

export interface Appeal {
  incident_id: number;
  appellant: string;
  bond: string;
  rebuttal: string;
  rebuttal_hash: string;
  status: AppealStatus;
  rationale: string;
  filed_at: number;
}

export interface Incident {
  incident_id: number;
  dao_id: number;
  proposal_id: number;
  target_contract: string;
  raw_calldata: string;
  prose_description: string;
  decoded: Disassembly;
  calldata_hash: string;
  prose_hash: string;
  reporter: string;
  bond: string;
  reserved_bounty: string;
  classification: Classification;
  rationale: string;
  status: IncidentStatus;
  flagged_at: number;
  unlock_time: number;
  appeal_award: string;
  appeal: Appeal | null;
}

export interface Ledger {
  total_deposited: string;
  total_bonded: string;
  total_claimable: string;
  total_slashed: string;
  total_disbursed: string;
  solvent: boolean;
}

export interface Constants {
  MIN_REPORTER_BOND: string;
  MIN_APPEAL_BOND: string;
  CHALLENGE_WINDOW: number;
  APPEAL_RESOLUTION_TIMEOUT: number;
  BOUNTY_CRITICAL: string;
  BOUNTY_SUSPICIOUS: string;
  DISMISSAL_FEE_BPS: number;
  LOSER_BOND_TO_WINNER_BPS: number;
}

export interface Verdict {
  classification: Classification;
  rationale: string;
}
