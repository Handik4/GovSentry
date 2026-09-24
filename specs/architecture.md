# GovSentry Architecture

GovSentry (v0.3.0) is a GenLayer intelligent contract that intercepts
malicious DAO governance proposals. It checks whether a proposal's on-chain
description truthfully represents the calldata the proposal will execute, and
it runs an economic game (bonds, a challenge window, appeals, and bounties)
around that check.

**Interceptor, defined.** GovSentry is an on-chain automated firewall/oracle.
It never executes, queues, or cancels anything on the DAO's own chain. Its
output is a consensus threat verdict with a bonded challenge window, meant to be
consumed by a DAO Guardian, an emergency pause module, or a veto-capable
multisig that blocks the proposal before its timelock ETA.

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
                     +----------------------------------+
  reporter --bond--> | report_proposal                  |
  (dao, id, action,  |  1. web consensus: read action + | --> governor on the
   created_block)    |     description from the chain   |     DAO's chain
                     |  2. deterministic disassembly    | --> ground truth facts
                     |  3. LLM semantic check           | --> validator consensus
                     |  4. verdict + challenge lock     |
                     +----------------------------------+
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

### 2.1 Web consensus verification pipeline

A reporter names a proposal action; it supplies no calldata and no prose.
`_read_proposal_action` sends one JSON-RPC batch to the owner-curated endpoint
for the DAO's chain (`set_chain_rpc`):

| id | Call | Purpose |
| -- | ---- | ------- |
| 0 | `eth_call governor.getActions(id)` | GovernorBravo stored actions (empty arrays for unknown ids) |
| 1 | `eth_call governor.proposalDetails(id)` | OpenZeppelin `GovernorStorage` actions + `descriptionHash` (reverts for unknown ids) |
| 2 | `eth_getLogs` for `ProposalCreated` in `created_block`, from the governor only | the proposal description |

The stored actions are authoritative, because they are what the governor will
queue. The event must carry identical targets, values, signatures and
calldatas (`ERR_PROPOSAL_MISMATCH` otherwise), and on OpenZeppelin governors
`keccak256(description)` must equal `descriptionHash`. Logs from any other
address are ignored, so a contract that emits a look-alike event cannot supply
the description. Bravo actions with a non-empty `signature` are reassembled as
`keccak256(signature)[:4] ++ args`, which is exactly the call the timelock
makes. ABI payloads are decoded by a small bounds-checked decoder in the
contract (`uint256`, `address`, `bytes32`, `string`, `bytes`, `T[]`).

The leader returns a normalized dict (target, value, signature, calldata,
description capped at 12000 characters, its sha256, the action count). Each
validator re-fetches and requires an identical dict. Failures are classified:

| Prefix | Examples | Validator rule |
| ------ | -------- | -------------- |
| `[EXTERNAL]` | `ERR_PROPOSAL_NOT_FOUND`, `ERR_INVALID_ACTION_INDEX`, `ERR_PROPOSAL_MISMATCH`, `ERR_RPC` | must match the leader's message exactly |
| `[TRANSIENT]` | `ERR_RPC_UNAVAILABLE` (HTTP 5xx/429, network) | agree if both are transient; the call reverts |
| other | anything unexpected | disagree, forcing leader rotation |

### 2.2 DAO verification

`register_dao(timelock, governor, chain_id, ...)` reads `timelock.admin()` the
same way (`_read_timelock_admin`). The DAO is `VERIFIED` when the admin is the
declared governor and `UNVERIFIED_REGISTRAR` otherwise, including when the
timelock has no `admin()` getter. Only a `VERIFIED` registration claims the
`chain_id:timelock` key, so pairing a real timelock with a fake governor
neither passes nor blocks the real registration. Reports against unverified
DAOs revert with `ERR_UNVERIFIED_DAO`. `refresh_verification(dao_id)`
re-reads the admin after a governor migration and releases the key if the
pairing no longer holds.

### 2.3 Deterministic disassembly

`_disassemble` runs identically on every node, with no LLM and no network access:

- Calldata read from chain is disassembled leniently, never rejected: empty
  calldata is a `NATIVE_TRANSFER`, unaligned trailing bytes are reported as
  `unaligned_trailing_hex`, and calldata beyond 8192 hex characters is
  truncated with `calldata_truncated` set. The forwarded `native_value_wei` and
  the proposer's `declared_signature` (Bravo) are added to the facts. A
  proposer therefore cannot evade analysis by padding the payload.
- The `disassemble(dao_id, calldata)` preview view keeps the strict
  validation for client input: a `0x` prefix, lowercase hex, a 4-byte selector
  that is not `0x00000000`, arguments in whole 32-byte words, and at most 8192
  hex characters.
- It resolves the selector against a built-in table of privileged selectors
  (`transferOwnership`, `mint`, `upgradeTo`, `grantRole`, ...), which always
  wins, then the DAO's own ABI registered via `register_selectors`. Every
  registered entry must satisfy `keccak256(signature)[:4] == selector`
  (`ERR_INVALID_SELECTOR_PREIMAGE`), and well-known selectors cannot be
  registered at all (`ERR_IMMUTABLE_SELECTOR`), which also rules out
  deliberate 4-byte collisions against them.
- It decodes each argument word as a `uint256` and, where the upper 12 bytes are
  zero, also as a candidate address.
- It marks the call `privileged` if the function name contains a privileged
  keyword, or if the selector is unknown.

These facts go into the prompt as **authoritative ground truth**, so the
LLM judges the prose against decoded facts rather than guessing at raw hex.

### 2.4 LLM semantic check and consensus

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
| `ESCROW_CLOSURE_NOTICE`    | 14 days      |

**Bounty funding.** DAO sponsors fund a per-DAO bounty escrow, either with value
attached to `register_dao` or later through `fund_bounty_escrow`. When a flag is
classified as deceptive, its bounty is *reserved* from the escrow at once, so
the same escrow can never be promised to two incidents. If an appeal overturns
the flag, or the incident ends inconclusive, the reservation goes back to the
escrow. A registrant can withdraw only the unreserved part of the escrow, and
only after `request_escrow_closure(dao_id)` has run for
`ESCROW_CLOSURE_NOTICE` (14 days) while the DAO has no unresolved incident
(`open_incidents == 0`; `ERR_CLOSURE_NOTICE` / `ERR_UNRESOLVED_INCIDENTS`
otherwise). Reporters can keep reporting during the notice, and every incident
they open pins the escrow until it reaches `PAID`, `OVERTURNED` or `EXPIRED`.
`cancel_escrow_closure` resets the notice.

**Deduplication.** One live incident per `dao_id:proposal_id:action_index`.
Each action of a multi-action proposal is reported and judged on its own, so
reporting a harmless decoy action cannot block the malicious one.

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
which is `sha256` over the calldata read from chain. Evidence written for one
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
`ERR_NOTHING_TO_CLAIM`, `ERR_TRANSFER`, `ERR_INVALID_SELECTOR_PREIMAGE`,
`ERR_IMMUTABLE_SELECTOR`, `ERR_UNKNOWN_CHAIN`, `ERR_UNVERIFIED_DAO`,
`ERR_CLOSURE_NOTICE`, `ERR_UNRESOLVED_INCIDENTS`.

Answers derived from the DAO's chain carry `[EXTERNAL]`
(`ERR_PROPOSAL_NOT_FOUND`, `ERR_INVALID_ACTION_INDEX`, `ERR_PROPOSAL_MISMATCH`,
`ERR_RPC`); RPC availability failures carry `[TRANSIENT]`
(`ERR_RPC_UNAVAILABLE`). LLM misbehavior raises `[LLM_ERROR]`.

## 7. Read API

The dashboard renders from views alone, without an indexer:

- `get_counts()` returns `{dao_count, incident_count}`.
- `list_daos(start_id, limit)` and `list_incidents(start_id, limit)` return
  pages of up to 50 records. Each incident includes its raw calldata, its
  description, the deterministic disassembly under `decoded`, and its appeal
  (or `None`).
- `get_incident`, `get_appeal`, `get_dao`, `get_ledger`, `get_constants`,
  `get_claimable`, `get_chain_rpc` and `disassemble(dao_id, calldata)` return
  single records. DAO records include `governor`, `chain_id`, `verification`,
  `timelock_admin`, `closure_requested_at`, `closure_unlocks_at` and
  `open_incidents`; incidents include `action_index`, `created_block`,
  `native_value`, `declared_signature` and `prose_truncated`.

The flag form's dry run calls `report_proposal` as a leader-only simulation.
Its non-deterministic outputs arrive in order: `eq_outputs[0]` is the proposal
read from chain and `eq_outputs[1]` is the verdict. Both are shown; nothing is
posted or stored.

## 8. Residual risks and limitations

- **Curated RPC trust.** All validators read the one endpoint the owner
  registered for a chain. A lying endpoint could feed every validator the same
  false proposal; the event/storage cross-check and `descriptionHash` raise
  the bar but do not remove this. Several independent endpoints per chain,
  with agreement required, is the natural next step.
- **Public RPC availability.** Free endpoints rate-limit or block validator
  egress. During the v0.3.0 bootstrap, Blast's public endpoint served
  `admin()` but returned 503 for the `eth_getLogs` batch; the owner repointed
  chain 1 to MEV Blocker with `set_chain_rpc`. Failures revert as
  `[TRANSIENT]` rather than locking in bad state.
- **Governor coverage.** GovernorBravo (`getActions`) and OpenZeppelin
  `GovernorStorage` (`proposalDetails`) are supported. Other governors cannot
  be reported against yet.
- **Unknown selectors skew verdicts.** Unregistered selectors are marked
  privileged. On the live Compound demo, validators disagreed on the verdict
  until the DAO registered its `setVersion(((uint64,uint64,uint64),string))`
  selector; afterwards they reached `MAJORITY_AGREE`. Sponsors should register
  their full ABI.
- **Verification scope.** `VERIFIED` proves the timelock answers to the
  declared governor, not that the registrant speaks for the DAO. A third party
  can sponsor a correctly paired DAO at the cost of its own escrow.
- **Escrow pinning.** Open incidents block escrow withdrawal, so a reporter can
  delay a closure by filing flags, paying a 10% dismissal fee for each one
  that is dismissed.
- **Verdicts are advisory.** Protection depends on a Guardian or pause module
  acting on the verdict before the timelock ETA.
- Nested dynamic ABI arguments (`bytes`, arrays) appear as raw words and are
  not decoded recursively.
- Direct-mode tests run only the leader path, plus captured validators via
  `run_validator`. The v0.3.0 bootstrap exercised the full pipeline against
  mainnet on Studio Next (see `deployments/studio.json`); broader integration
  tests are still advisable before production use.
