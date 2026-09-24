"""Regression proofs for the v0.3.0 security review.

Each section reproduces one audit finding against the hardened contract and
asserts the fix holds:

  1. Critical - fabricated proposal drain (reporter-supplied calldata/prose)
  2. Critical - selector spoofing via register_selectors
  3. High     - single-action DoS through dao_id:proposal_id deduplication
  4. High     - third-party DAO registration / timelock squatting
  5. High     - instant bounty escrow rug
"""

import json

import pytest

from conftest import (
    ATTACKER,
    ATTO,
    CALLDATA_MINT,
    CALLDATA_OWNERSHIP,
    CALLDATA_SET_FEE,
    CHALLENGE_WINDOW,
    CREATED_BLOCK,
    ESCROW,
    ESCROW_CLOSURE_NOTICE,
    GOVERNOR,
    PROSE_DECEPTIVE,
    PROSE_HONEST,
    RPC_PATTERN,
    TARGET,
    TIMELOCK,
    _llm_payload,
    action,
    assert_solvent,
    deploy,
    flag,
    mock_proposal,
    mock_timelock_admin,
    mock_verdict,
    proposal_created_log,
    register,
    report,
    start_clock,
    warp_to,
)

BOUNTY_CRITICAL = 5 * ATTO
FAKE_GOVERNOR = "0x" + "99" * 20


@pytest.fixture
def env(direct_vm, direct_deploy, direct_alice):
    contract = deploy(direct_deploy)
    t0 = start_clock(direct_vm)
    dao_id = register(contract, direct_vm, direct_alice)
    return contract, t0, dao_id


def _ledger_snapshot(contract) -> dict:
    return {k: v for k, v in contract.get_ledger().items()}


# ===================================================================
# 1. Critical: fabricated proposal drain
# ===================================================================
#
# Before: flag_proposal(dao_id, proposal_id, target, raw_calldata, prose)
# trusted the reporter for everything the verdict depends on, so a reporter
# could invent a "deceptive" proposal and collect the bounty unchallenged.
# After: report_proposal takes only (dao_id, proposal_id, action_index,
# created_block); the action and the description are read from the governor.


def test_reporter_can_no_longer_supply_calldata_or_prose(env):
    contract, _, _ = env
    assert not hasattr(contract, "flag_proposal")


def test_fake_proposal_id_fails_verification(env, direct_vm, direct_bob):
    """GovernorBravo returns empty arrays for a proposal id that was never
    created. No incident is opened and no bond or bounty moves."""
    contract, _, dao_id = env
    before = _ledger_snapshot(contract)
    mock_verdict(direct_vm, "CRITICAL_MALICIOUS_PAYLOAD")
    mock_proposal(direct_vm, 999, [], "", logs=[])
    with direct_vm.expect_revert("ERR_PROPOSAL_NOT_FOUND"):
        report(contract, direct_vm, direct_bob, dao_id, proposal_id=999)
    direct_vm.value = 0
    assert contract.get_counts()["incident_count"] == 0
    assert _ledger_snapshot(contract) == before
    assert int(contract.get_dao(dao_id)["bounty_escrow"]) == ESCROW


def test_proposal_without_creation_event_fails_verification(env, direct_vm, direct_bob):
    """getActions answers but no ProposalCreated(id) sits in created_block."""
    contract, _, dao_id = env
    mock_proposal(direct_vm, 7, [action(CALLDATA_OWNERSHIP)], PROSE_DECEPTIVE, logs=[])
    with direct_vm.expect_revert("ERR_PROPOSAL_NOT_FOUND"):
        report(contract, direct_vm, direct_bob, dao_id, proposal_id=7)
    direct_vm.value = 0


def test_event_from_a_different_contract_is_ignored(env, direct_vm, direct_bob):
    """A ProposalCreated log emitted by an attacker contract in the same
    block cannot supply the description."""
    contract, _, dao_id = env
    actions = [action(CALLDATA_OWNERSHIP)]
    forged = proposal_created_log(7, actions, PROSE_HONEST, governor=FAKE_GOVERNOR)
    mock_proposal(direct_vm, 7, actions, PROSE_HONEST, logs=[forged])
    with direct_vm.expect_revert("ERR_PROPOSAL_NOT_FOUND"):
        report(contract, direct_vm, direct_bob, dao_id, proposal_id=7)
    direct_vm.value = 0


def test_event_disagreeing_with_get_actions_is_rejected(env, direct_vm, direct_bob):
    contract, _, dao_id = env
    queued = [action(CALLDATA_OWNERSHIP)]
    announced = [action(CALLDATA_SET_FEE)]
    mock_proposal(
        direct_vm, 7, queued, PROSE_HONEST, logs=[proposal_created_log(7, announced, PROSE_HONEST)]
    )
    with direct_vm.expect_revert("ERR_PROPOSAL_MISMATCH"):
        report(contract, direct_vm, direct_bob, dao_id, proposal_id=7)
    direct_vm.value = 0


def test_incident_records_on_chain_action_and_description(env, direct_vm, direct_bob):
    """The verdict is computed over what the governor will execute, and the
    model is shown the on-chain description rather than reporter text."""
    contract, _, dao_id = env
    direct_vm.mock_llm(
        r"refresh keeper heartbeat interval",  # only matches the on-chain prose
        _llm_payload({"classification": "CRITICAL_MALICIOUS_PAYLOAD", "rationale": "hidden ownership"}),
    )
    mock_proposal(direct_vm, 42, [action(CALLDATA_OWNERSHIP)], PROSE_DECEPTIVE)
    incident_id = report(contract, direct_vm, direct_bob, dao_id, proposal_id=42)

    i = contract.get_incident(incident_id)
    assert i["raw_calldata"] == CALLDATA_OWNERSHIP
    assert i["target_contract"] == TARGET
    assert i["prose_description"] == PROSE_DECEPTIVE
    assert i["created_block"] == CREATED_BLOCK
    assert i["action_index"] == 0
    assert i["decoded"]["signature"] == "transferOwnership(address)"
    assert i["classification"] == "CRITICAL_MALICIOUS_PAYLOAD"
    assert int(i["reserved_bounty"]) == BOUNTY_CRITICAL


def test_bravo_signature_actions_are_reassembled(env, direct_vm, direct_bob):
    """Bravo stores `signature` separately and calldata as bare arguments;
    the timelock prepends keccak(signature)[:4]. GovSentry must analyse the
    call exactly as the timelock will make it."""
    contract, _, dao_id = env
    mock_verdict(direct_vm, "CRITICAL_MALICIOUS_PAYLOAD")
    args_only = "0x" + CALLDATA_MINT[10:]
    mock_proposal(direct_vm, 5, [action(args_only, signature="mint(address,uint256)")], PROSE_DECEPTIVE)
    incident_id = report(contract, direct_vm, direct_bob, dao_id, proposal_id=5)
    i = contract.get_incident(incident_id)
    assert i["raw_calldata"] == CALLDATA_MINT
    assert i["declared_signature"] == "mint(address,uint256)"
    assert i["decoded"]["signature"] == "mint(address,uint256)"
    assert i["decoded"]["argument_words"][0]["as_address"] == "0x" + ATTACKER


def test_unaligned_or_value_carrying_actions_cannot_evade_analysis(env, direct_vm, direct_bob):
    """Padding calldata or sending bare ETH used to be unrepresentable; now
    it is disassembled and disclosed to the model instead of rejected."""
    contract, _, dao_id = env
    mock_verdict(direct_vm, "CRITICAL_MALICIOUS_PAYLOAD")
    padded = CALLDATA_OWNERSHIP + "ab"
    mock_proposal(
        direct_vm, 8, [action(padded), action("0x", target="0x" + ATTACKER, value=500 * ATTO)], PROSE_DECEPTIVE
    )
    first = report(contract, direct_vm, direct_bob, dao_id, proposal_id=8, action_index=0)
    second = report(contract, direct_vm, direct_bob, dao_id, proposal_id=8, action_index=1)
    assert contract.get_incident(first)["decoded"]["unaligned_trailing_hex"] == 2
    drain = contract.get_incident(second)
    assert drain["decoded"]["signature"] == "NATIVE_TRANSFER"
    assert drain["decoded"]["native_value_wei"] == str(500 * ATTO)
    assert drain["native_value"] == str(500 * ATTO)


def test_openzeppelin_governor_proposals_are_verified(env, direct_vm, direct_bob):
    """OpenZeppelin GovernorStorage (e.g. the current Compound Governor)
    exposes proposalDetails instead of getActions; its descriptionHash also
    pins the event description."""
    contract, _, dao_id = env
    mock_verdict(direct_vm, "CRITICAL_MALICIOUS_PAYLOAD")
    mock_proposal(direct_vm, 609, [action(CALLDATA_OWNERSHIP)], PROSE_DECEPTIVE, oz=True)
    i = contract.get_incident(report(contract, direct_vm, direct_bob, dao_id, proposal_id=609))
    assert i["raw_calldata"] == CALLDATA_OWNERSHIP
    assert i["prose_description"] == PROSE_DECEPTIVE
    assert i["declared_signature"] == ""


def test_openzeppelin_description_must_match_description_hash(env, direct_vm, direct_bob):
    contract, _, dao_id = env
    mock_proposal(
        direct_vm, 609, [action(CALLDATA_OWNERSHIP)], PROSE_HONEST, oz=True, description_hash=b"\x11" * 32
    )
    with direct_vm.expect_revert("ERR_PROPOSAL_MISMATCH"):
        report(contract, direct_vm, direct_bob, dao_id, proposal_id=609)
    direct_vm.value = 0


def test_proposal_fetch_validator_requires_identical_chain_data(env, direct_vm, direct_bob):
    contract, _, dao_id = env
    mock_verdict(direct_vm, "CRITICAL_MALICIOUS_PAYLOAD")
    flag(contract, direct_vm, direct_bob, dao_id, proposal_id=3)
    fetch = -2  # captured nondet blocks: [proposal fetch, semantic verdict]

    assert direct_vm.run_validator(index=fetch) is True
    mock_proposal(direct_vm, 3, [action(CALLDATA_SET_FEE)], PROSE_DECEPTIVE)
    assert direct_vm.run_validator(index=fetch) is False


def test_proposal_fetch_validator_classifies_errors(env, direct_vm, direct_bob):
    contract, _, dao_id = env
    mock_verdict(direct_vm, "CRITICAL_MALICIOUS_PAYLOAD")
    flag(contract, direct_vm, direct_bob, dao_id, proposal_id=3)
    fetch = -2

    # Leader saw a transient outage; so does the validator: agree.
    direct_vm._web_mocks[:] = []
    direct_vm.mock_web(RPC_PATTERN, {"method": "POST", "status": 503, "body": ""})
    assert direct_vm.run_validator(index=fetch, leader_error=Exception("[TRANSIENT] ERR_RPC_UNAVAILABLE")) is True
    # Leader claims "not found" while the validator can read the proposal.
    mock_proposal(direct_vm, 3, [action(CALLDATA_OWNERSHIP)], PROSE_DECEPTIVE)
    assert (
        direct_vm.run_validator(index=fetch, leader_error=Exception("[EXTERNAL] ERR_PROPOSAL_NOT_FOUND x"))
        is False
    )


def test_reports_require_a_curated_chain_rpc(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = deploy(direct_deploy)
    mock_timelock_admin(direct_vm, GOVERNOR)
    direct_vm.sender = direct_alice
    with direct_vm.expect_revert("ERR_UNKNOWN_CHAIN"):
        contract.register_dao(TIMELOCK, GOVERNOR, 10, "Example DAO", "https://example.org/dao")
    direct_vm.sender = direct_bob
    with direct_vm.expect_revert("ERR_UNAUTHORIZED"):
        contract.set_chain_rpc(10, "https://evil.example.org")


# ===================================================================
# 2. Critical: selector spoofing
# ===================================================================


def test_spoofed_selector_registration_reverts(env, direct_vm, direct_alice):
    """PoC: map mint's selector to a harmless-looking name."""
    contract, _, dao_id = env
    direct_vm.sender = direct_alice
    with direct_vm.expect_revert("ERR_INVALID_SELECTOR_PREIMAGE"):
        contract.register_selectors(dao_id, '{"0x40c10f19": "refreshHeartbeat()"}')
    assert contract.disassemble(dao_id, CALLDATA_MINT)["signature"] == "mint(address,uint256)"


def test_mislabelled_custom_selector_reverts(env, direct_vm, direct_alice):
    contract, _, dao_id = env
    direct_vm.sender = direct_alice
    with direct_vm.expect_revert("ERR_INVALID_SELECTOR_PREIMAGE"):
        contract.register_selectors(dao_id, '{"0x69fe0e2d": "setKeeperInterval(uint256)"}')


def test_well_known_selectors_are_immutable(env, direct_vm, direct_alice):
    """Even a true preimage cannot re-register a well-known privileged
    selector (guards against deliberate 4-byte collisions)."""
    contract, _, dao_id = env
    direct_vm.sender = direct_alice
    with direct_vm.expect_revert("ERR_IMMUTABLE_SELECTOR"):
        contract.register_selectors(dao_id, '{"0x40c10f19": "mint(address,uint256)"}')


def test_one_bad_entry_rejects_the_whole_schema(env, direct_vm, direct_alice):
    contract, _, dao_id = env
    direct_vm.sender = direct_alice
    with direct_vm.expect_revert("ERR_INVALID_SELECTOR_PREIMAGE"):
        contract.register_selectors(
            dao_id, '{"0x69fe0e2d": "setFee(uint256)", "0xf2fde38b": "setKeeperInterval(uint256)"}'
        )
    assert contract.get_dao(dao_id)["selector_schema"] == "{}"


def test_honest_selectors_still_register(env, direct_vm, direct_alice):
    contract, _, dao_id = env
    direct_vm.sender = direct_alice
    contract.register_selectors(dao_id, '{"0x69FE0E2D": "setFee(uint256)"}')
    assert contract.disassemble(dao_id, CALLDATA_SET_FEE)["signature"] == "setFee(uint256)"


# ===================================================================
# 3. High: single-action DoS
# ===================================================================


@pytest.fixture
def two_action_proposal(env, direct_vm):
    """Proposal 12: a harmless setFee decoy followed by an ownership hijack."""
    contract, t0, dao_id = env
    direct_vm.mock_llm(
        r'"selector": "0x69fe0e2d"', _llm_payload({"classification": "ALIGNED", "rationale": "fee"})
    )
    direct_vm.mock_llm(
        r'"selector": "0xf2fde38b"',
        _llm_payload({"classification": "CRITICAL_MALICIOUS_PAYLOAD", "rationale": "hijack"}),
    )
    mock_proposal(
        direct_vm, 12, [action(CALLDATA_SET_FEE), action(CALLDATA_OWNERSHIP)], "Adjust the swap fee to 30 bps."
    )
    return contract, t0, dao_id


def test_multi_action_reports_are_independent(two_action_proposal, direct_vm, direct_bob, direct_charlie):
    """PoC: an attacker reports the decoy action first. The malicious
    action must remain reportable by someone else."""
    contract, _, dao_id = two_action_proposal
    decoy = report(contract, direct_vm, direct_charlie, dao_id, proposal_id=12, action_index=0)
    real = report(contract, direct_vm, direct_bob, dao_id, proposal_id=12, action_index=1)

    assert decoy != real
    d, r = contract.get_incident(decoy), contract.get_incident(real)
    assert (d["action_index"], d["classification"], d["status"]) == (0, "ALIGNED", "DISMISSED")
    assert (r["action_index"], r["classification"], r["status"]) == (
        1,
        "CRITICAL_MALICIOUS_PAYLOAD",
        "PENDING_CHALLENGE",
    )
    assert r["raw_calldata"] == CALLDATA_OWNERSHIP
    assert int(r["reserved_bounty"]) == BOUNTY_CRITICAL
    assert contract.get_dao(dao_id)["open_incidents"] == 2
    assert_solvent(contract)


def test_same_action_still_deduplicated(two_action_proposal, direct_vm, direct_bob, direct_charlie):
    contract, _, dao_id = two_action_proposal
    report(contract, direct_vm, direct_bob, dao_id, proposal_id=12, action_index=1)
    with direct_vm.expect_revert("ERR_DUPLICATE_INCIDENT"):
        report(contract, direct_vm, direct_charlie, dao_id, proposal_id=12, action_index=1)
    direct_vm.value = 0


def test_action_index_beyond_proposal_rejected(two_action_proposal, direct_vm, direct_bob):
    contract, _, dao_id = two_action_proposal
    with direct_vm.expect_revert("ERR_INVALID_ACTION_INDEX"):
        report(contract, direct_vm, direct_bob, dao_id, proposal_id=12, action_index=2)
    direct_vm.value = 0


# ===================================================================
# 4. High: third-party registration / timelock squatting
# ===================================================================


def test_timelock_admin_resolution_flags_unverified_dao(direct_vm, direct_deploy, direct_bob):
    """PoC: a third party registers a real timelock with a governor it
    controls. admin() shows the timelock does not answer to that governor."""
    contract = deploy(direct_deploy)
    start_clock(direct_vm)
    squat = register(contract, direct_vm, direct_bob, governor=FAKE_GOVERNOR, admin=GOVERNOR)
    dao = contract.get_dao(squat)
    assert dao["verification"] == "UNVERIFIED_REGISTRAR"
    assert dao["timelock_admin"] == GOVERNOR

    mock_verdict(direct_vm, "CRITICAL_MALICIOUS_PAYLOAD")
    with direct_vm.expect_revert("ERR_UNVERIFIED_DAO"):
        flag(contract, direct_vm, direct_bob, squat)
    direct_vm.value = 0


def test_unverified_registration_cannot_squat_the_timelock(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = deploy(direct_deploy)
    start_clock(direct_vm)
    register(contract, direct_vm, direct_bob, governor=FAKE_GOVERNOR, admin=GOVERNOR)
    real = register(contract, direct_vm, direct_alice)  # governor == admin()
    assert contract.get_dao(real)["verification"] == "VERIFIED"


def test_timelock_without_admin_getter_is_unverified(direct_vm, direct_deploy, direct_alice):
    contract = deploy(direct_deploy)
    dao_id = register(contract, direct_vm, direct_alice, admin=None)
    dao = contract.get_dao(dao_id)
    assert dao["verification"] == "UNVERIFIED_REGISTRAR"
    assert dao["timelock_admin"] == ""


def test_refresh_verification_tracks_governor_migration(env, direct_vm, direct_alice, direct_bob):
    contract, _, dao_id = env
    mock_timelock_admin(direct_vm, "0x" + "77" * 20)  # governance migrated away
    direct_vm.sender = direct_bob
    assert contract.refresh_verification(dao_id) == "UNVERIFIED_REGISTRAR"
    # The stale entry released the timelock, so the new pairing can claim it.
    newcomer = register(contract, direct_vm, direct_alice, governor="0x" + "77" * 20, admin="0x" + "77" * 20)
    assert contract.get_dao(newcomer)["verification"] == "VERIFIED"


def test_admin_validator_requires_identical_chain_data(env, direct_vm):
    # env's register_dao is the most recent nondet block.
    assert direct_vm.run_validator() is True
    mock_timelock_admin(direct_vm, FAKE_GOVERNOR)
    assert direct_vm.run_validator() is False


# ===================================================================
# 5. High: escrow rug
# ===================================================================


def test_instant_escrow_withdrawal_reverts_without_closure_notice(env, direct_vm, direct_alice):
    """PoC: the sponsor front-runs a pending payout by pulling the escrow."""
    contract, _, dao_id = env
    direct_vm.sender = direct_alice
    with direct_vm.expect_revert("ERR_CLOSURE_NOTICE"):
        contract.withdraw_bounty_escrow(dao_id, ESCROW)
    assert int(contract.get_dao(dao_id)["bounty_escrow"]) == ESCROW


def test_withdrawal_waits_for_the_full_notice(env, direct_vm, direct_alice):
    contract, t0, dao_id = env
    direct_vm.sender = direct_alice
    assert contract.request_escrow_closure(dao_id) == t0 + ESCROW_CLOSURE_NOTICE
    assert contract.get_dao(dao_id)["closure_unlocks_at"] == t0 + ESCROW_CLOSURE_NOTICE

    warp_to(direct_vm, t0 + ESCROW_CLOSURE_NOTICE - 1)
    with direct_vm.expect_revert("ERR_CLOSURE_NOTICE"):
        contract.withdraw_bounty_escrow(dao_id, ESCROW)
    warp_to(direct_vm, t0 + ESCROW_CLOSURE_NOTICE)
    assert int(contract.withdraw_bounty_escrow(dao_id, ESCROW)) == ESCROW
    assert_solvent(contract)


def test_unresolved_incident_blocks_withdrawal_after_notice(env, direct_vm, direct_alice, direct_bob):
    """Reporters can still act during the notice, and whatever they open
    pins the escrow until it settles."""
    contract, t0, dao_id = env
    direct_vm.sender = direct_alice
    contract.request_escrow_closure(dao_id)
    mock_verdict(direct_vm, "CRITICAL_MALICIOUS_PAYLOAD")
    incident_id = flag(contract, direct_vm, direct_bob, dao_id)

    warp_to(direct_vm, t0 + ESCROW_CLOSURE_NOTICE)
    direct_vm.sender = direct_alice
    with direct_vm.expect_revert("ERR_UNRESOLVED_INCIDENTS"):
        contract.withdraw_bounty_escrow(dao_id, 1)

    contract.claim_payout(incident_id)
    assert contract.get_dao(dao_id)["open_incidents"] == 0
    direct_vm.sender = direct_alice
    free = ESCROW - BOUNTY_CRITICAL
    assert int(contract.withdraw_bounty_escrow(dao_id, free)) == free
    assert_solvent(contract)


def test_closure_is_registrant_only_and_cancellable(env, direct_vm, direct_alice, direct_bob):
    contract, t0, dao_id = env
    direct_vm.sender = direct_bob
    with direct_vm.expect_revert("ERR_UNAUTHORIZED"):
        contract.request_escrow_closure(dao_id)

    direct_vm.sender = direct_alice
    contract.request_escrow_closure(dao_id)
    with direct_vm.expect_revert("ERR_INVALID_STATE"):
        contract.request_escrow_closure(dao_id)
    contract.cancel_escrow_closure(dao_id)
    assert contract.get_dao(dao_id)["closure_requested_at"] == 0

    warp_to(direct_vm, t0 + ESCROW_CLOSURE_NOTICE + CHALLENGE_WINDOW)
    with direct_vm.expect_revert("ERR_CLOSURE_NOTICE"):
        contract.withdraw_bounty_escrow(dao_id, ESCROW)


def test_every_terminal_state_releases_the_escrow_pin(env, direct_vm, direct_bob):
    contract, _, dao_id = env
    mock_verdict(direct_vm, "ALIGNED")
    dismissed = flag(contract, direct_vm, direct_bob, dao_id, proposal_id=1, calldata=CALLDATA_SET_FEE)
    assert contract.get_dao(dao_id)["open_incidents"] == 1
    contract.expire_incident(dismissed)
    assert contract.get_dao(dao_id)["open_incidents"] == 0
    assert_solvent(contract)


# ===================================================================
# Deployment guard
# ===================================================================


def test_runner_header_is_a_standalone_json_block():
    """GenVM parses the whole leading comment block as the runner JSON.
    Direct mode does not, so a stray comment line there only fails on a
    real network (`invalid_contract runner malformed`)."""
    with open("contracts/gov_sentry.py", encoding="utf-8") as f:
        lines = f.read().splitlines()
    block = []
    for line in lines:
        if not line.startswith("#"):
            break
        block.append(line.lstrip("#").strip())
    header = json.loads(" ".join(block))
    assert header["Depends"].startswith("py-genlayer:")
