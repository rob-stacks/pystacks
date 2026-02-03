import unittest
from pystacks.transaction import (
    TransactionPayload,
    TransactionAuth,
    TransactionSpendingCondition,
    HashMode,
    TransactionPublicKeyEncoding,
)
from pystacks.utils import generate_key
from io import BytesIO


class TestTransaction(unittest.TestCase):

    def test_unsupported_payload(self):
        self.assertRaises(
            TransactionPayload.Unsupported,
            TransactionPayload.from_stream,
            BytesIO(b"\xff"),
        )
