from bitcoinlib.services.bitcoind import BitcoindClient
from bitcoinlib.blocks import Block


def get_burnchain_block(block_hash, base_url="http://127.0.0.1:8332"):
    client = BitcoindClient(base_url=base_url)
    block = client.proxy.getblock(block_hash, 0)
    return Block.parse(bytes.fromhex(block))
