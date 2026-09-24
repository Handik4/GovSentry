# GovSentry Architecture

GovSentry is a GenLayer intelligent contract that intercepts malicious DAO
governance proposals. It checks whether a proposal's description truthfully
represents the calldata the proposal will execute, and it runs an economic game
(bonds, a challenge window, appeals, and bounties) around that check.

## 1. Threat model

Governance hijacks usually pass because voters read the description, not the
bytecode. A typical attack:

| Proposal prose                         | Actual calldata                                  |
| -------------------------------------- | ------------------------------------------------ |
| "Routine parameter adjustment"         | `transferOwnership(attacker)`                    |
| "Refresh keeper heartbeat interval"    | `mint(attacker, 1_000_000e18)`                   |
| "Upgrade oracle adapter to v2.1"       | `upgradeTo(backdooredImplementation)`            |
| "Rebalance treasury"                   | `transfer(attacker, treasuryBalance)`            |

GovSentry turns spotting this mismatch into a paid, bonded, contestable job.

## 2. Components

```
                     +-------------------------------+
  reporter --bond--> | flag_proposal                 |
                     |  1. strict calldata validation|
                     |  2. deterministic disassembly | --> ground truth facts
                     |  3. LLM semantic check        | --> validator consensus
                     |  4. verdict + challenge lock  |
                     +-------------------------------+
                                   |
             +---------------------+----------------------+
             |                     |                      |
          ALIGNED        SUSPICIOUS_OMISSION /     (no appeal filed,
          DISMISSED      CRITICAL_MALICIOUS_PAYLOAD  window lapses)
             |           PENDING_CHALLENGE ----------------+
      expire_incident          |                           |
      (90% refund)      file_appeal (bond, bound proof)    |
                               |                           |
                          APPEALED                         |
                               |                           |
                        resolve_appeal (LLM + consensus)   |
             +-----------------+-----------------+         |
          UPHELD            REJECTED        INCONCLUSIVE   |
          OVERTURNED        CONFIRMED -------------------->+--> claim_payout -> PAID
          (reporter slashed)                  |
                                        expire_incident (full refunds) -> EXPIRED
```

### 2.1 Deterministic disassembly

`_disassemble` runs identically on every node, with no LLM and no network access:

- It validates calldata strictly: a `0x` prefix, lowercase hex, a 4-byte
  selector that is not `0x00000000`, arguments in whole 32-byte words, and at
  most 8192 hex characters.
- It resolves the selector against a built-in table of privileged selectors
  (`transferOwnership`, `mint`, `upgradeTo`, `grantRole`, ...), plus the DAO's
  own verified ABI registered via `register_selectors`.
- It decodes each argument word as a `uint256` and, where the upper 12 bytes are
  zero, also as a candidate address.
- It marks the call `privileged` if the function name contains a privileged
  keyword, or if the selector is unknown.

These facts go into the prompt as **authoritative ground truth**, so the
LLM judges the prose against decoded facts rather than guessing at raw hex.

### 2.2 LLM semantic check and consensus

`_semantic_alignment_check` and `_appeal_review` both use
`gl.vm.run_nondet(leader_fn, validator_fn)`:

- **Leader** runs the prompt with `response_format="json"`. It parses the
  response defensively, accepting alternative key names (`classification` /
  `verdict` / `label`) and case or spacing variants of the values, and rejects
  anything outside the allowed classifications with an `[LLM_ERROR]`.
- **Validator** re-runs the prompt on its own and agrees only if it reaches
  the same categorical value: the `classification` for flags, or the
  `outcome` for appeals. Rationale text may differ. A leader failure always
  counts as a disagreement, which forces leader rotation instead of locking in
  a bad state.

Prompt-injection hardening: every untrusted field (the prose, the rebuttal, the
DAO name, and the stored rationale) is wrapped in its own tag, and `<` / `>`
are rewritten to `(` / `)` so the text cannot close its tag. The prompt
tells the model to treat tagged text as data, and to disregard rebuttal claims
that contradict the ground truth.

## 3. Economics

| Parameter                  | Value        |
| -------------------------- | ------------ |
| `MIN_REPORTER_BOND`        | 1.0 GEN      |
| `MIN_APPEAL_BOND`          | 2.0 GEN      |
| `CHALLENGE_WINDOW`         | 86400 s      |
| `APPEAL_RESOLUTION_TIMEOUT`| 3 days after unlock |
| `BOUNTY_CRITICAL`          | 5.0 GEN (capped by DAO escrow) |
| `BOUNTY_SUSPICIOUS`        | 1.0 GEN (capped by DAO escrow) |
| `DISMISSAL_FEE_BPS`        | 10% of reporter bond |
| `LOSER_BOND_TO_WINNER_BPS` | 50% of the losing bond |

**Bounty funding.** DAO sponsors fund a per-DAO bounty escrow, either with value
attached to `register_dao` or later through `fund_bounty_escrow`. When a flag is
classified as deceptive, its bounty is *reserved* from the escrow at once, so
the same escrow can never be promised to two incidents. If an appeal overturns
the flag, or the incident ends inconclusive, the reservation goes back to the
escrow. A registrant can withdraw only the unreserved part of the escrow.

**Settlement matrix.**

| Outcome                         | Reporter                              | Appellant                      | Protocol treasury |
| ------------------------------- | ------------------------------------- | ------------------------------ | ----------------- |
| Unchallenged deceptive flag     | bond + bounty                         | -                              | -                 |
| Appeal REJECTED (CONFIRMED)     | bond + bounty + 50% of appeal bond    | loses bond                     | 50% of appeal bond |
| Appeal UPHELD (OVERTURNED)      | loses bond                            | bond + 50% of reporter bond    | 50% of reporter bond |
| Appeal INCONCLUSIVE / stalled   | full refund                           | full refund                    | -                 |
| Flag ALIGNED (DISMISSED)        | 90% refund                            | -                              | 10% of bond       |

Incentives: a reporter profits only from a verdict that survives the challenge
window. An appellant profits only by showing the prose really did disclose the
effect. Spamming benign proposals costs 10% per flag, and appealing a correct
verdict costs 50% of the appeal bond.

## 4. Ledger and solvency

The contract keeps every unit of GEN it holds in exactly one bucket:

- `total_bonded`: reporter bonds, appeal bonds, DAO escrows, and bounty
  reservations tied to live incidents.
- `total_claimable`: refunds and awards that are owed and ready for `withdraw()`.
- `total_slashed`: the protocol treasury, which the owner can move out with
  `sweep_treasury`.

`total_deposited` is the net balance the contract holds: value received minus
value disbursed. After every transaction the following invariant holds:

```
total_deposited == total_bonded + total_claimable + total_slashed
```

`get_ledger()` exposes it as `solvent`. `total_disbursed` records total outflow
for audit, so `inflow == total_deposited + total_disbursed`. The test
`test_exact_ledger_accounting_across_full_game` checks both identities after
every step of a scenario that exercises every settlement path.

Outbound transfers follow checks-effects-interactions. Ledger debits are
applied first, then `gl.chain.Account(to).emit_transfer(..., on="finalized")`
is enqueued. If enqueuing fails, the transaction reverts, which also restores
the debits.

## 5. Evidence binding

`file_appeal` requires the rebuttal to quote the incident's `calldata_hash`,
which is `sha256` over the normalized calldata. Evidence written for one
incident therefore cannot be replayed against another. Each incident's
commitment is unique to its calldata, and
`test_rebuttal_bound_to_other_incident_rejected` covers this. Empty rebuttals
(including whitespace-only ones) fail with `ERR_EMPTY_REBUTTAL`. Rebuttals that
don't quote the hash fail with `ERR_UNBOUND_REBUTTAL`.

## 6. Error codes

All business errors carry the `[EXPECTED]` prefix, so the result is
deterministic across validators:

`ERR_INSUFFICIENT_BOND`, `ERR_CHALLENGE_WINDOW_ACTIVE`, `ERR_CHALLENGE_WINDOW_CLOSED`,
`ERR_MALFORMED_CALLDATA`, `ERR_INVALID_ADDRESS`, `ERR_INVALID_INPUT`,
`ERR_EMPTY_REBUTTAL`, `ERR_UNBOUND_REBUTTAL`, `ERR_UNKNOWN_DAO`,
`ERR_UNKNOWN_INCIDENT`, `ERR_DUPLICATE_INCIDENT`, `ERR_DUPLICATE_DAO`,
`ERR_INVALID_STATE`, `ERR_SELF_APPEAL`, `ERR_UNAUTHORIZED`,
`ERR_NOTHING_TO_CLAIM`, `ERR_TRANSFER`.

LLM misbehavior raises `[LLM_ERROR]`.

## 7. Read API

The dashboard renders from views alone, without an indexer:

- `get_counts()` returns `{dao_count, incident_count}`.
- `list_daos(start_id, limit)` and `list_incidents(start_id, limit)` return
  pages of up to 50 records. Each incident includes its raw calldata, its
  description, the deterministic disassembly under `decoded`, and its appeal
  (or `None`).
- `get_incident`, `get_appeal`, `get_dao`, `get_ledger`, `get_constants`,
  `get_claimable` and `disassemble(dao_id, calldata)` return single records.

The flag form's dry run calls `flag_proposal` as a leader-only simulation and
reads the verdict from the non-deterministic block's output (`eq_outputs[0]`).
The model really runs, but nothing is posted or stored.

## 8. Known limitations

- A flag covers a single call (`target_contract`, `raw_calldata`). Batched
  proposals with several actions must be flagged one action at a time.
- Nested dynamic ABI arguments (`bytes`, arrays) appear as raw words and are
  not decoded recursively.
- The contract does not check that the flagged calldata matches the calldata
  actually queued in the remote timelock. Appellants can contest a
  misrepresentation in their rebuttal, and a future version could verify it
  cross-chain through an `eth_call` under `strict_eq`.
- Direct-mode tests run only the leader path, plus captured validators via
  `run_validator`. Full multi-validator consensus should be exercised with
  integration tests against a GenLayer network before production use.
