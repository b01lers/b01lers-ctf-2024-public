import json
from pathlib import Path

import eth_sandbox
from web3 import Web3


def deploy(web3: Web3, deployer_address: str, player_address: str) -> str:
    tx = {
    'from': deployer_address,
    'gasPrice': web3.toWei('0', 'gwei'),
    'nonce': web3.eth.getTransactionCount(deployer_address),
    'data': json.loads(Path("compiled/burgercoin.sol/burgercoin.json").read_text())["bytecode"]["object"]
    }
    rcpt = eth_sandbox.sendTransaction(web3, tx)

    return rcpt.contractAddress

eth_sandbox.run_launcher([
    eth_sandbox.new_launch_instance_action(deploy),
    eth_sandbox.new_kill_instance_action(),
    eth_sandbox.new_get_flag_action()
])
