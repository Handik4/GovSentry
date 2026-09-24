#!/usr/bin/env python3
"""Bootstrap a deployed GovSentry: curate the Ethereum mainnet RPC, register
the Compound Governance Timelock with its governor, and attach its admin
selectors.

Usage:
    python scripts/bootstrap.py                  # uses deployments/studio.json
    python scripts/bootstrap.py --demo-incident  # only report the demo proposal

Transaction hashes and explorer links are appended to the deployment record.
"""

import argparse
import json
import sys

from genlayer_py import create_account, create_client

from _env import ROOT, load_env
from deploy import NETWORKS, fee_options, resolve_network

RECORD = ROOT / "deployments" / "studio.json"
# Test-network bounty escrow seeded for the bootstrap DAO (atto-GEN).
BOOTSTRAP_ESCROW = 10 * 10**18

# Ethereum mainnet endpoint validators read governors through. It must accept
# JSON-RPC batches and serve historical eth_getLogs, without an API key, to
# the validators' own egress. (Blast's public endpoint answered admin() but
# returned 503 to validators for the eth_getLogs batch.)
CHAIN_ID = 1
CHAIN_RPC = "https://rpc.mevblocker.io"

DAO = {
    "target_timelock": "0x6d903f6003cca6255D85CcA4D3B5E5146dC33925",
    # Compound Governor (OpenZeppelin GovernorStorage); the timelock's admin().
    "governor": "0x309a862bbc1a00e45506cb8a802d1ff10004c8c0",
    "chain_id": CHAIN_ID,
    "name": "Compound Governance Timelock",
    "description_url": "https://compound.finance/governance",
}

# Selectors computed as keccak256(signature)[:4].
COMPOUND_SELECTORS = {
    "b71d1a0c": "_setPendingAdmin(address)",
    "e9c714f2": "_acceptAdmin()",
    "fca7820b": "_setReserveFactor(uint256)",
    "e4028eee": "_setCollateralFactor(address,uint256)",
    "a76b3fda": "_supportMarket(address)",
    "27efe3cb": "_grantComp(address,uint256)",
    "e177246e": "setDelay(uint256)",
    # Version marker the current Compound proposals call first.
    "8889c6ab": "setVersion(((uint64,uint64,uint64),string))",
}


def send(client, account, address, method, args, wait_until, value=0):
    tx_hash = client.write_contract(
        address=address,
        function_name=method,
        account=account,
        args=args,
        value=value,
        fees=fee_options(client),
    )
    print(f"{method:<20} tx {tx_hash}")
    receipt = client.wait_for_transaction_receipt(
        transaction_hash=tx_hash, wait_until=wait_until, retries=200
    )
    lifecycle = receipt.get("lifecycle") or {}
    status = {
        "state": lifecycle.get("state"),
        "consensus": receipt.get("result_name"),
        "execution": receipt.get("txExecutionResultName"),
    }
    print(f"{'':<20} {status}")
    return tx_hash, status


# A real Compound proposal for the demo feed. Validators read its first action
# and its description from mainnet; nothing about it is supplied here.
DEMO_INCIDENT = {
    "proposal_id": 609,
    "action_index": 0,
    "created_block": 26024021,  # block of its ProposalCreated event
}
REPORTER_BOND = 10**18


def main() -> int:
    parser = argparse.ArgumentParser(description="Bootstrap a deployed GovSentry.")
    parser.add_argument(
        "--demo-incident",
        action="store_true",
        help="Skip DAO setup and file one demonstration flag against DAO #1.",
    )
    args = parser.parse_args()

    if not RECORD.exists():
        print("error: deployments/studio.json not found; run scripts/deploy.py first", file=sys.stderr)
        return 1
    record = json.loads(RECORD.read_text(encoding="utf-8"))
    env = load_env()
    private_key = env.get("GENLAYER_PRIVATE_KEY")
    if not private_key:
        print("error: GENLAYER_PRIVATE_KEY is required", file=sys.stderr)
        return 1

    network = record["network"] if record["network"] in NETWORKS else "studio_next"
    chain, rpc, explorer = resolve_network(network, record.get("rpc_url"))
    account = create_account(private_key)
    client = create_client(chain=chain, endpoint=rpc, account=account)
    address = record["contract_address"]

    if args.demo_incident:
        d = DEMO_INCIDENT
        tx, status = send(
            client, account, address, "report_proposal",
            [1, d["proposal_id"], d["action_index"], d["created_block"]],
            "finalized", value=REPORTER_BOND,
        )
        incident = client.read_contract(address=address, function_name="get_incident", args=[1])
        print(f"verdict  : {incident['classification']} ({incident['status']})")
        record["demo_incident"] = {
            "method": "report_proposal",
            **d,
            "tx_hash": tx,
            **status,
            "explorer_url": f"{explorer}/tx/{tx}" if explorer else None,
            "classification": incident["classification"],
        }
        RECORD.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        return 0

    bootstrap = []
    rpc_tx, rpc_status = send(
        client, account, address, "set_chain_rpc", [CHAIN_ID, CHAIN_RPC], "finalized"
    )
    bootstrap.append({"method": "set_chain_rpc", "tx_hash": rpc_tx, **rpc_status})

    reg_tx, reg_status = send(
        client, account, address, "register_dao",
        [DAO["target_timelock"], DAO["governor"], DAO["chain_id"], DAO["name"], DAO["description_url"]],
        "finalized",
    )
    bootstrap.append({"method": "register_dao", "tx_hash": reg_tx, **reg_status})

    sel_tx, sel_status = send(
        client, account, address, "register_selectors",
        [1, json.dumps(COMPOUND_SELECTORS, sort_keys=True)], "finalized",
    )
    bootstrap.append({"method": "register_selectors", "tx_hash": sel_tx, **sel_status})

    esc_tx, esc_status = send(
        client, account, address, "fund_bounty_escrow", [1], "finalized", value=BOOTSTRAP_ESCROW
    )
    bootstrap.append({"method": "fund_bounty_escrow", "tx_hash": esc_tx, **esc_status})

    dao = client.read_contract(address=address, function_name="get_dao", args=[1])
    print(json.dumps(dao, indent=2, default=str))

    for entry in bootstrap:
        entry["explorer_url"] = f"{explorer}/tx/{entry['tx_hash']}" if explorer else None
    record["bootstrap"] = bootstrap
    record["bootstrap_dao"] = {"dao_id": 1, **DAO}
    RECORD.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(f"recorded : {RECORD.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
