#!/usr/bin/env python3
"""Deploy GovSentry to a GenLayer network and record the deployment.

Usage:
    python scripts/deploy.py                          # Studio Next (default)
    python scripts/deploy.py --network localnet
    python scripts/deploy.py --network studionet --endpoint https://...

The signer is read from GENLAYER_PRIVATE_KEY (environment or a local .env
file). The deployer becomes the contract owner (treasury sweep authority).
Hosted deployments are recorded in deployments/<network>.json.
"""

import argparse
import hashlib
import json
import sys
import time

from genlayer_py import chains, create_account, create_client

from _env import ROOT, load_env

CONTRACT_PATH = ROOT / "contracts" / "gov_sentry.py"
DEPLOYMENTS_DIR = ROOT / "deployments"

# name -> (genlayer-py chain, RPC endpoint override, explorer base URL)
NETWORKS = {
    "studio_next": (
        chains.studio_devnet,
        "https://studio-next.genlayer.com/api",
        "https://explorer-studio-next.genlayer.com",
    ),
    "studio_dev": (
        chains.studio_devnet,
        "https://studio-dev.genlayer.com/api",
        "https://explorer-studio-dev.genlayer.com",
    ),
    "studionet": (chains.studionet, None, None),
    "localnet": (chains.localnet, None, None),
}


def resolve_network(name: str, endpoint: str | None):
    chain, default_endpoint, explorer = NETWORKS[name]
    rpc = endpoint or default_endpoint or chain.rpc_urls["default"]["http"][0]
    if explorer is None:
        explorer = (chain.block_explorers or {}).get("default", {}).get("url")
    return chain, rpc, explorer


def contract_address(receipt) -> str | None:
    """Pull the deployed address out of a receipt (localnet and testnet shapes)."""
    for section in ("tx_data_decoded", "data"):
        data = receipt.get(section) if hasattr(receipt, "get") else None
        if isinstance(data, dict) and data.get("contract_address"):
            return data["contract_address"]
    return None


def fee_options(client):
    """Fee distribution for networks with an active fee policy, else None."""
    try:
        if not client.get_current_fee_policy().get("enabled"):
            return None
    except Exception:
        return None
    return client.estimate_transaction_fees()


def runner_hash(source: str) -> str:
    """The runner JSON inside the leading comment block (a version tag line
    may precede it, as GenVM allows)."""
    block = []
    for line in source.splitlines():
        if not line.startswith("#"):
            break
        block.append(line.lstrip("#").strip())
    text = " ".join(block)
    return json.loads(text[text.index("{"):])["Depends"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Deploy the GovSentry intelligent contract.")
    parser.add_argument("--network", choices=sorted(NETWORKS), default="studio_next")
    parser.add_argument("--endpoint", help="Override the network RPC endpoint.")
    parser.add_argument(
        "--wait-until",
        choices=("decided", "finalized"),
        default="decided",
        help="Receipt stage to wait for before reporting the address.",
    )
    parser.add_argument(
        "--fund",
        action="store_true",
        help="Top up the deployer from the Studio dev faucet (test networks only).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    env = load_env()
    private_key = env.get("GENLAYER_PRIVATE_KEY")
    if not private_key and args.network != "localnet":
        print("error: GENLAYER_PRIVATE_KEY is required for hosted networks", file=sys.stderr)
        return 1

    chain, rpc, explorer = resolve_network(args.network, args.endpoint)
    account = create_account(private_key) if private_key else create_account()
    client = create_client(chain=chain, endpoint=rpc, account=account)

    source = CONTRACT_PATH.read_text(encoding="utf-8")
    print(f"deployer : {account.address}")
    print(f"network  : {args.network} ({rpc})")
    if args.fund:
        client.fund_account(account.address, 50 * 10**18)
    print(f"balance  : {client.w3.eth.get_balance(account.address)} atto-GEN")
    tx_hash = client.deploy_contract(
        code=source, account=account, args=[], fees=fee_options(client)
    )
    print(f"tx       : {tx_hash}")

    receipt = client.wait_for_transaction_receipt(transaction_hash=tx_hash, wait_until=args.wait_until)
    address = contract_address(receipt)
    execution = receipt.get("txExecutionResultName")
    print(f"contract : {address}")
    print(f"execution: {execution}")
    if not address:
        return 2
    if execution != "FINISHED_WITH_RETURN":
        # The address is assigned even when the constructor or the runner
        # header fails; nothing is deployed there, so do not record it.
        print("error: deployment did not finish with a return", file=sys.stderr)
        return 3

    if args.network != "localnet":
        DEPLOYMENTS_DIR.mkdir(exist_ok=True)
        record = {
            "network": args.network,
            "chain_id": chain.id,
            "rpc_url": rpc,
            "contract_address": address,
            "deploy_tx_hash": tx_hash if isinstance(tx_hash, str) else "0x" + bytes(tx_hash).hex(),
            "deployer": account.address,
            "explorer_url": f"{explorer}/address/{address}" if explorer else None,
            "deploy_tx_url": f"{explorer}/tx/{tx_hash}" if explorer else None,
            "source": "contracts/gov_sentry.py",
            "source_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
            "runner": runner_hash(source),
            "deploy_status": {
                "state": (receipt.get("lifecycle") or {}).get("state"),
                "consensus": receipt.get("result_name"),
                "execution": receipt.get("txExecutionResultName"),
            },
            "deployed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        out = DEPLOYMENTS_DIR / "studio.json"
        out.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        print(f"recorded : {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
