import unittest
from pystacks.block import NakamotoBlock
from pystacks.transaction import TransactionPayload, TenureChangeCause


class TestNakamotoBlock(unittest.TestCase):

    def test_testnet_first_block(self):
        block_hex = "000000000000000140000000000062e0802cd83cba6930e50fe81d265c6f14d248c93f3de30d7cb8c66040d87fc17f39e1b5c36bc7fb5c4d97cc611a168e2cca186848be1e37f724b890eb40fbed5ae35ab7251fcb26bfa103c57fe4c0a5225bd73b61b3ea685eab3d311c758e5a8c5cd98b3608c3ba576127481a45a4f9dad7ce9a4844790000000067783274019af82fad474b1ff5be1ac20cac626a9edc60889ffdf64f85bf0a03becab97b57504c13d0f5ecd8fb3ff2a557b6d061529789d323a28ced10f6b1d0602f0021010000000200dc739b8c03f8604d9e77d30dc614ea59322ef0d7e5760b1951a8ab3962864ab44b58b23bf5ea01b80d22aa34595f7de2bc99e2defbf83b0de5ec3362bd5985a701371c7e8558a163c102e914d3da84050de953219a3cc311f38fdc3d8cb96ce5864dad098ba60403d92549793b600862d36d2e11d75d6b24097dfdc77ecb75b3a8013800000027ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000002808000000004002d58c278d1c9e1a8a26236ac81b543193c10e347000000000000013f000000000000000000008f1299694590fa87abbc5b583e6902e2d30ef5eaa612df026519cb8cf25517e8647f9d0d7823ac90ac282bd3c992c2f1d301cd6aa022b27d2759278e8088cf35010200000000072cd83cba6930e50fe81d265c6f14d248c93f3de3f0a15ade31fae1d3fd5092df666de00193c2c1b92cd83cba6930e50fe81d265c6f14d248c93f3de30d7cb8c66040d87fc17f39e1b5c36bc7fb5c4d97cc611a168e2cca186848be1e00000001002d58c278d1c9e1a8a26236ac81b543193c10e347808000000004002d58c278d1c9e1a8a26236ac81b543193c10e347000000000000014000000000000000000001bb538302f88e112fcbb7ecf4464654fc885d0a7bcbea7807d757923f4ada9cc651c9ebc04396b5c18bb2299ad86c1f8e0ab87fb4966427b4d122a543d9cbdf3f01020000000008000000000000000000000000000000000000000000000000000000000000000009b5914425d9209e868204a7ec6dd54eacf37a15c6baa60aa22a4fe3356f6b09ed34aa001e5658c5e143cac1d627aeb584e97364946b20eae77d88b43a73d5cf78a4df12933ac8033fb65d7d1230eea207"
        nakamoto_block = NakamotoBlock.from_hex(block_hex)
        self.assertEqual(
            nakamoto_block.block_id().hex(),
            "e87cd1a389d70b9c5dba386c3c7efeabd40d0bee926632e0bcce2dda2824d045",
        )
        self.assertEqual(
            nakamoto_block.block_hash().hex(),
            "8d08f09c153b7e0416c692eac497886b9a31f490ede288d6214e63526cad6218",
        )
        self.assertEqual(
            nakamoto_block.header.parent_block_id.hex(),
            "0d7cb8c66040d87fc17f39e1b5c36bc7fb5c4d97cc611a168e2cca186848be1e",
        )
        self.assertEqual(nakamoto_block.header.height, 320)
        self.assertEqual(len(nakamoto_block.transactions), 2)

        self.assertIsInstance(
            nakamoto_block.transactions[0].payload, TransactionPayload.TenureChange
        )
        self.assertIsInstance(
            nakamoto_block.transactions[0].payload.cause, TenureChangeCause.BlockFound
        )

        self.assertIsInstance(
            nakamoto_block.transactions[1].payload, TransactionPayload.NakamotoCoinbase
        )
