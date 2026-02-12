import unittest
from pystacks.utils import (
    stx_mainnet_address_from_private_key,
    sha256,
    stx_address_to_principal_data,
)
from pystacks.curves import get_public_key


class TestAddress(unittest.TestCase):

    def test_from_seed(self):
        addr = stx_mainnet_address_from_private_key(sha256(b"blocksimulate"))
        self.assertEqual(addr, "ST1WPX9J4Y1T8DEGB515K2R34SMTW8P7RQATEN3QR")

    def test_to_principal(self):
        addr = "ST1WPX9J4Y1T8DEGB515K2R34SMTW8P7RQATEN3QR"
        self.assertEqual(
            stx_address_to_principal_data(addr),
            {
                "Standard": [
                    26,
                    [
                        121,
                        110,
                        166,
                        68,
                        240,
                        116,
                        134,
                        186,
                        11,
                        40,
                        75,
                        49,
                        96,
                        100,
                        205,
                        53,
                        196,
                        88,
                        248,
                        186,
                    ],
                ]
            },
        )
