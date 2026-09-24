"""GovSentry proposal lifecycle: registration, flagging, appeals, settlement."""

import pytest

from conftest import (
    APPEAL_BOND,
    ATTO,
    CALLDATA_MINT,
    CALLDATA_OWNERSHIP,
    CALLDATA_SET_FEE,
    CHALLENGE_WINDOW,
    CONTRACT,
    GOVERNOR,
    ESCROW,
    PROSE_DECEPTIVE,
    PROSE_HONEST,
    REPORTER_BOND,
    TARGET,
    TIMELOCK,
    appeal,
    assert_solvent,
    bound_rebuttal,
    deploy,
    flag,
    hex_of,
    mock_appeal,
    mock_verdict,
    register,
    sha256_hex,
    start_clock,
    warp_to,
)

BOUNTY_CRITICAL = 5 * ATTO
BOUNTY_SUSPICIOUS = 1 * ATTO


@pytest.fixture
def env(direct_vm, direct_deploy, direct_alice):
    contract = deploy(direct_deploy)
    t0 = start_clock(direct_vm)
    dao_id = register(contract, direct_vm, direct_alice)
    return contract, t0, dao_id


# ----------------------------------------------------------------- registry


def test_register_dao_records_target_and_escrow(env, direct_alice):
    contract, t0, dao_id = env
    dao = contract.get_dao(dao_id)
    assert dao_id == 1
    assert dao["target_timelock"] == TIMELOCK
    assert dao["registrant"].lower() == hex_of(direct_alice).lower()
    assert int(dao["bounty_escrow"]) == ESCROW
    assert dao["registered_at"] == t0
    assert dao["governor"] == GOVERNOR
    assert dao["verification"] == "VERIFIED"
    assert dao["timelock_admin"] == GOVERNOR
    ledger = assert_solvent(contract)
    assert int(ledger["total_deposited"]) == ESCROW
    assert int(ledger["total_bonded"]) == ESCROW


def test_register_duplicate_timelock_rejected(env, direct_vm, direct_bob):
    contract, _, _ = env
    with direct_vm.expect_revert("ERR_DUPLICATE_DAO"):
        register(contract, direct_vm, direct_bob, timelock=TIMELOCK.upper().replace("0X", "0x"))
    direct_vm.value = 0


def test_register_selectors_extends_disassembly(env, direct_vm, direct_alice):
    contract, _, dao_id = env
    before = contract.disassemble(dao_id, CALLDATA_SET_FEE)
    assert before["signature"] == "UNKNOWN"
    assert before["privileged"] is True

    direct_vm.sender = direct_alice
    contract.register_selectors(dao_id, '{"0x69FE0E2D": "setFee(uint256)"}')
    after = contract.disassemble(dao_id, CALLDATA_SET_FEE)
    assert after["signature"] == "setFee(uint256)"
    assert after["privileged"] is False
    assert after["argument_words"][0]["as_uint"] == "30"


def test_disassemble_decodes_ownership_transfer(env):
    contract, _, dao_id = env
    facts = contract.disassemble(dao_id, CALLDATA_OWNERSHIP)
    assert facts["selector"] == "0xf2fde38b"
    assert facts["signature"] == "transferOwnership(address)"
    assert facts["privileged"] is True
    assert facts["argument_words"][0]["as_address"] == "0x" + "33" * 20


# ----------------------------------------------------------------- flagging


def test_happy_path_deceptive_proposal_is_critical(env, direct_vm, direct_bob):
    contract, t0, dao_id = env
    mock_verdict(direct_vm, "CRITICAL_MALICIOUS_PAYLOAD", "prose hides transferOwnership")

    incident_id = flag(contract, direct_vm, direct_bob, dao_id, proposal_id=42)

    inc = contract.get_incident(incident_id)
    assert incident_id == 1
    assert inc["classification"] == "CRITICAL_MALICIOUS_PAYLOAD"
    assert inc["status"] == "PENDING_CHALLENGE"
    assert inc["rationale"] == "prose hides transferOwnership"
    assert inc["dao_id"] == dao_id and inc["proposal_id"] == 42
    assert inc["target_contract"] == TARGET
    assert inc["calldata_hash"] == sha256_hex(CALLDATA_OWNERSHIP)
    assert inc["prose_hash"] == sha256_hex(PROSE_DECEPTIVE)
    assert inc["reporter"].lower() == hex_of(direct_bob).lower()
    assert int(inc["bond"]) == REPORTER_BOND
    assert inc["flagged_at"] == t0
    assert inc["unlock_time"] == t0 + CHALLENGE_WINDOW
    assert int(inc["reserved_bounty"]) == BOUNTY_CRITICAL
    assert int(contract.get_dao(dao_id)["bounty_escrow"]) == ESCROW - BOUNTY_CRITICAL
    assert_solvent(contract)


def test_suspicious_omission_reserves_smaller_bounty(env, direct_vm, direct_bob):
    contract, _, dao_id = env
    mock_verdict(direct_vm, "SUSPICIOUS_OMISSION")
    incident_id = flag(contract, direct_vm, direct_bob, dao_id, calldata=CALLDATA_MINT)
    inc = contract.get_incident(incident_id)
    assert inc["classification"] == "SUSPICIOUS_OMISSION"
    assert inc["status"] == "PENDING_CHALLENGE"
    assert int(inc["reserved_bounty"]) == BOUNTY_SUSPICIOUS


def test_llm_verdict_aliases_are_normalized(env, direct_vm, direct_bob):
    contract, _, dao_id = env
    direct_vm.mock_llm(
        r".*security auditor.*",
        b'{"verdict": "critical malicious payload", "reasoning": "drain"}',
    )
    incident_id = flag(contract, direct_vm, direct_bob, dao_id)
    inc = contract.get_incident(incident_id)
    assert inc["classification"] == "CRITICAL_MALICIOUS_PAYLOAD"
    assert inc["rationale"] == "drain"


def test_aligned_proposal_is_dismissed_and_expired_with_fee(env, direct_vm, direct_bob):
    contract, _, dao_id = env
    mock_verdict(direct_vm, "ALIGNED")
    incident_id = flag(
        contract, direct_vm, direct_bob, dao_id, calldata=CALLDATA_SET_FEE, prose=PROSE_HONEST
    )
    inc = contract.get_incident(incident_id)
    assert inc["status"] == "DISMISSED"
    assert int(inc["reserved_bounty"]) == 0

    assert contract.expire_incident(incident_id) == "EXPIRED"
    fee = REPORTER_BOND // 10
    assert int(contract.get_claimable(hex_of(direct_bob))) == REPORTER_BOND - fee
    ledger = assert_solvent(contract)
    assert int(ledger["total_slashed"]) == fee

    direct_vm.sender = direct_bob
    assert int(contract.withdraw()) == REPORTER_BOND - fee
    assert int(contract.get_claimable(hex_of(direct_bob))) == 0
    ledger = assert_solvent(contract)
    assert int(ledger["total_claimable"]) == 0


# --------------------------------------------------------------- settlement


def test_claim_payout_after_window_pays_bond_plus_bounty(env, direct_vm, direct_bob):
    contract, t0, dao_id = env
    mock_verdict(direct_vm, "CRITICAL_MALICIOUS_PAYLOAD")
    incident_id = flag(contract, direct_vm, direct_bob, dao_id)

    warp_to(direct_vm, t0 + CHALLENGE_WINDOW)
    paid = int(contract.claim_payout(incident_id))

    assert paid == REPORTER_BOND + BOUNTY_CRITICAL
    assert contract.get_incident(incident_id)["status"] == "PAID"
    ledger = assert_solvent(contract)
    assert int(ledger["total_disbursed"]) == paid
    assert int(ledger["total_deposited"]) == ESCROW - BOUNTY_CRITICAL


def test_rejected_appeal_confirms_and_rewards_reporter(env, direct_vm, direct_bob, direct_charlie):
    contract, t0, dao_id = env
    mock_verdict(direct_vm, "CRITICAL_MALICIOUS_PAYLOAD")
    incident_id = flag(contract, direct_vm, direct_bob, dao_id)

    appeal(contract, direct_vm, direct_charlie, incident_id, bound_rebuttal(contract, incident_id))
    assert contract.get_incident(incident_id)["status"] == "APPEALED"
    assert contract.get_appeal(incident_id)["status"] == "PENDING"
    assert_solvent(contract)

    mock_appeal(direct_vm, "REJECTED", "calldata contradicts rebuttal")
    assert contract.resolve_appeal(incident_id) == "REJECTED"
    inc = contract.get_incident(incident_id)
    assert inc["status"] == "CONFIRMED"
    assert int(inc["appeal_award"]) == APPEAL_BOND // 2
    appeal_rec = contract.get_appeal(incident_id)
    assert appeal_rec["status"] == "REJECTED"
    assert appeal_rec["rationale"] == "calldata contradicts rebuttal"
    ledger = assert_solvent(contract)
    assert int(ledger["total_slashed"]) == APPEAL_BOND // 2

    warp_to(direct_vm, t0 + CHALLENGE_WINDOW)
    paid = int(contract.claim_payout(incident_id))
    assert paid == REPORTER_BOND + BOUNTY_CRITICAL + APPEAL_BOND // 2
    assert_solvent(contract)


def test_upheld_appeal_overturns_and_slashes_reporter(env, direct_vm, direct_bob, direct_charlie):
    contract, t0, dao_id = env
    mock_verdict(direct_vm, "CRITICAL_MALICIOUS_PAYLOAD")
    incident_id = flag(contract, direct_vm, direct_bob, dao_id)
    appeal(contract, direct_vm, direct_charlie, incident_id, bound_rebuttal(contract, incident_id))

    mock_appeal(direct_vm, "UPHELD")
    assert contract.resolve_appeal(incident_id) == "UPHELD"

    inc = contract.get_incident(incident_id)
    assert inc["status"] == "OVERTURNED"
    assert int(inc["reserved_bounty"]) == 0
    assert int(contract.get_dao(dao_id)["bounty_escrow"]) == ESCROW
    award = REPORTER_BOND // 2
    assert int(contract.get_claimable(hex_of(direct_charlie))) == APPEAL_BOND + award
    ledger = assert_solvent(contract)
    assert int(ledger["total_slashed"]) == REPORTER_BOND - award

    warp_to(direct_vm, t0 + CHALLENGE_WINDOW)
    with direct_vm.expect_revert("ERR_INVALID_STATE"):
        contract.claim_payout(incident_id)

    direct_vm.sender = direct_charlie
    assert int(contract.withdraw()) == APPEAL_BOND + award
    assert_solvent(contract)


def test_overturned_proposal_can_be_reflagged(env, direct_vm, direct_bob, direct_charlie):
    contract, _, dao_id = env
    mock_verdict(direct_vm, "SUSPICIOUS_OMISSION")
    first = flag(contract, direct_vm, direct_bob, dao_id, proposal_id=7)
    appeal(contract, direct_vm, direct_charlie, first, bound_rebuttal(contract, first))
    mock_appeal(direct_vm, "UPHELD")
    contract.resolve_appeal(first)

    second = flag(contract, direct_vm, direct_charlie, dao_id, proposal_id=7)
    assert second == first + 1
    assert contract.get_incident(second)["status"] == "PENDING_CHALLENGE"


def test_inconclusive_appeal_expires_with_full_refunds(env, direct_vm, direct_bob, direct_charlie):
    contract, _, dao_id = env
    mock_verdict(direct_vm, "CRITICAL_MALICIOUS_PAYLOAD")
    incident_id = flag(contract, direct_vm, direct_bob, dao_id)
    appeal(contract, direct_vm, direct_charlie, incident_id, bound_rebuttal(contract, incident_id))

    mock_appeal(direct_vm, "INCONCLUSIVE")
    assert contract.resolve_appeal(incident_id) == "INCONCLUSIVE"
    assert contract.get_incident(incident_id)["status"] == "INCONCLUSIVE"

    contract.expire_incident(incident_id)
    assert contract.get_incident(incident_id)["status"] == "EXPIRED"
    assert int(contract.get_claimable(hex_of(direct_bob))) == REPORTER_BOND
    assert int(contract.get_claimable(hex_of(direct_charlie))) == APPEAL_BOND
    assert int(contract.get_dao(dao_id)["bounty_escrow"]) == ESCROW
    ledger = assert_solvent(contract)
    assert int(ledger["total_slashed"]) == 0


def test_stalled_appeal_expires_only_after_timeout(env, direct_vm, direct_bob, direct_charlie):
    contract, t0, dao_id = env
    mock_verdict(direct_vm, "CRITICAL_MALICIOUS_PAYLOAD")
    incident_id = flag(contract, direct_vm, direct_bob, dao_id)
    appeal(contract, direct_vm, direct_charlie, incident_id, bound_rebuttal(contract, incident_id))

    deadline = t0 + CHALLENGE_WINDOW + 3 * 86400
    warp_to(direct_vm, deadline - 1)
    with direct_vm.expect_revert("ERR_INVALID_STATE"):
        contract.expire_incident(incident_id)

    warp_to(direct_vm, deadline)
    contract.expire_incident(incident_id)
    assert contract.get_appeal(incident_id)["status"] == "INCONCLUSIVE"
    assert int(contract.get_claimable(hex_of(direct_bob))) == REPORTER_BOND
    assert int(contract.get_claimable(hex_of(direct_charlie))) == APPEAL_BOND
    assert_solvent(contract)


def test_sweep_treasury_moves_slashed_funds(env, direct_vm, direct_bob, direct_owner):
    contract, _, dao_id = env
    mock_verdict(direct_vm, "ALIGNED")
    incident_id = flag(contract, direct_vm, direct_bob, dao_id, calldata=CALLDATA_SET_FEE)
    contract.expire_incident(incident_id)
    fee = REPORTER_BOND // 10

    direct_vm.sender = direct_owner
    assert int(contract.sweep_treasury("0x" + "44" * 20, fee)) == fee
    ledger = assert_solvent(contract)
    assert int(ledger["total_slashed"]) == 0


# --------------------------------------------------------- consensus logic


def test_validator_agrees_on_matching_classification(env, direct_vm, direct_bob):
    contract, _, dao_id = env
    mock_verdict(direct_vm, "CRITICAL_MALICIOUS_PAYLOAD", "leader wording")
    flag(contract, direct_vm, direct_bob, dao_id)

    direct_vm.clear_mocks()
    mock_verdict(direct_vm, "CRITICAL_MALICIOUS_PAYLOAD", "different wording")
    assert direct_vm.run_validator() is True


def test_validator_rejects_divergent_classification(env, direct_vm, direct_bob):
    contract, _, dao_id = env
    mock_verdict(direct_vm, "CRITICAL_MALICIOUS_PAYLOAD")
    flag(contract, direct_vm, direct_bob, dao_id)

    direct_vm.clear_mocks()
    mock_verdict(direct_vm, "ALIGNED")
    assert direct_vm.run_validator() is False


def test_validator_rejects_leader_failure(env, direct_vm, direct_bob):
    contract, _, dao_id = env
    mock_verdict(direct_vm, "CRITICAL_MALICIOUS_PAYLOAD")
    flag(contract, direct_vm, direct_bob, dao_id)
    assert direct_vm.run_validator(leader_error=Exception("[LLM_ERROR] garbage")) is False


def test_appeal_validator_compares_outcome(env, direct_vm, direct_bob, direct_charlie):
    contract, _, dao_id = env
    mock_verdict(direct_vm, "CRITICAL_MALICIOUS_PAYLOAD")
    incident_id = flag(contract, direct_vm, direct_bob, dao_id)
    appeal(contract, direct_vm, direct_charlie, incident_id, bound_rebuttal(contract, incident_id))
    mock_appeal(direct_vm, "REJECTED")
    contract.resolve_appeal(incident_id)

    direct_vm.clear_mocks()
    mock_appeal(direct_vm, "REJECTED", "independent reasoning")
    assert direct_vm.run_validator() is True
    direct_vm.clear_mocks()
    mock_appeal(direct_vm, "UPHELD")
    assert direct_vm.run_validator() is False


# ------------------------------------------------------------- feed views


def test_feed_views_expose_counts_pages_and_inline_appeals(env, direct_vm, direct_bob, direct_charlie):
    contract, _, dao_id = env
    assert contract.get_counts() == {"dao_count": 1, "incident_count": 0}
    assert contract.list_incidents(1, 10) == []

    mock_verdict(direct_vm, "CRITICAL_MALICIOUS_PAYLOAD")
    first = flag(contract, direct_vm, direct_bob, dao_id, proposal_id=1)
    flag(contract, direct_vm, direct_bob, dao_id, proposal_id=2, calldata=CALLDATA_MINT)
    rebuttal = bound_rebuttal(contract, first)
    appeal(contract, direct_vm, direct_charlie, first, rebuttal)

    assert contract.get_counts() == {"dao_count": 1, "incident_count": 2}
    page = contract.list_incidents(1, 10)
    assert [p["incident_id"] for p in page] == [1, 2]
    assert page[0]["raw_calldata"] == CALLDATA_OWNERSHIP
    assert page[0]["prose_description"] == PROSE_DECEPTIVE
    assert page[0]["decoded"]["signature"] == "transferOwnership(address)"
    assert page[0]["appeal"]["rebuttal"] == rebuttal
    assert page[1]["appeal"] is None
    assert page[1]["decoded"]["signature"] == "mint(address,uint256)"
    assert [p["incident_id"] for p in contract.list_incidents(2, 1)] == [2]
    assert contract.list_incidents(0, 0) == []

    daos = contract.list_daos(1, 50)
    assert len(daos) == 1 and daos[0]["dao_id"] == dao_id
