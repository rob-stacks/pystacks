import unittest
from pystacks.transaction import (
    TransactionAuthField,
    TransactionSpendingCondition,
    HashMode,
    TransactionPublicKeyEncoding,
    TransactionAuthFlags,
)
from pystacks.curves import generate_private_key, generate_private_and_public_keys


class TestSig(unittest.TestCase):

    def test_single_sig(self):
        private_key = generate_private_key()
        single_sig = TransactionSpendingCondition.Singlesig()
        single_sig.hash_mode = HashMode.Singlesig.P2PKH()
        single_sig.key_encoding = TransactionPublicKeyEncoding.Compressed()
        single_sig.nonce = 100
        single_sig.tx_fee = 100
        single_sig.sign(b"!HelloWorldHelloWorldHelloWorld!", private_key)
        self.assertIsNotNone(single_sig.signer)
        self.assertIsNotNone(single_sig.signature)
        self.assertTrue(single_sig.verify(b"!HelloWorldHelloWorldHelloWorld!"))

    def test_single_sig_uncompressed(self):
        private_key = generate_private_key()
        single_sig = TransactionSpendingCondition.Singlesig()
        single_sig.hash_mode = HashMode.Singlesig.P2PKH()
        single_sig.key_encoding = TransactionPublicKeyEncoding.Uncompressed()
        single_sig.nonce = 200
        single_sig.tx_fee = 200
        single_sig.sign(b"!HelloWorldHelloWorldHelloWorld!", private_key)
        self.assertIsNotNone(single_sig.signer)
        self.assertIsNotNone(single_sig.signature)
        self.assertTrue(single_sig.verify(b"!HelloWorldHelloWorldHelloWorld!"))

    def test_single_sig_segwit(self):
        private_key = generate_private_key()
        single_sig = TransactionSpendingCondition.Singlesig()
        single_sig.hash_mode = HashMode.Singlesig.P2WPKH()
        single_sig.key_encoding = TransactionPublicKeyEncoding.Compressed()
        single_sig.nonce = 100
        single_sig.tx_fee = 100
        single_sig.sign(b"!HelloWorldHelloWorldHelloWorld!", private_key)
        self.assertIsNotNone(single_sig.signer)
        self.assertIsNotNone(single_sig.signature)
        self.assertTrue(single_sig.verify(b"!HelloWorldHelloWorldHelloWorld!"))

    def test_single_sig_unsupported_auth_mode(self):
        private_key = generate_private_key()
        single_sig = TransactionSpendingCondition.Singlesig()
        single_sig.hash_mode = HashMode.Multisig.P2SH()
        single_sig.key_encoding = TransactionPublicKeyEncoding.Compressed()
        single_sig.nonce = 100
        single_sig.tx_fee = 100
        self.assertRaises(
            TransactionSpendingCondition.Singlesig.Unsupported,
            single_sig.sign,
            b"!HelloWorldHelloWorldHelloWorld!",
            private_key,
        )

    def test_multi_sig_1_of_1(self):
        private_key0, public_key0 = generate_private_and_public_keys()
        multi_sig = TransactionSpendingCondition.Multisig()
        multi_sig.hash_mode = HashMode.Multisig.P2SH()
        multi_sig.fields = [TransactionAuthField.PublicKey(False, public_key0)]
        multi_sig.signatures_required = 1
        multi_sig.tx_fee = 100
        multi_sig.nonce = 1000
        multi_sig.sign(
            b"*HelloWorldHelloWorldHelloWorld*",
            private_key0,
        )
        self.assertIsNotNone(multi_sig.signer)
        self.assertTrue(isinstance(multi_sig.fields[0], TransactionAuthField.Signature))
        self.assertTrue(multi_sig.verify(b"*HelloWorldHelloWorldHelloWorld*"))

    def test_multi_sig_2_of_2(self):
        private_key0, public_key0 = generate_private_and_public_keys()
        private_key1, public_key1 = generate_private_and_public_keys()
        multi_sig = TransactionSpendingCondition.Multisig()
        multi_sig.hash_mode = HashMode.Multisig.P2SH()
        multi_sig.fields = [
            TransactionAuthField.PublicKey(False, public_key0),
            TransactionAuthField.PublicKey(False, public_key1),
        ]
        multi_sig.signatures_required = 2
        multi_sig.tx_fee = 200
        multi_sig.nonce = 10000
        multi_sig.sign(
            b"*HelloWorldHelloWorldHelloWorld*",
            private_key0,
        )
        multi_sig.sign(
            b"*HelloWorldHelloWorldHelloWorld*",
            private_key1,
        )
        self.assertIsNotNone(multi_sig.signer)
        self.assertTrue(isinstance(multi_sig.fields[0], TransactionAuthField.Signature))
        self.assertTrue(isinstance(multi_sig.fields[1], TransactionAuthField.Signature))
        self.assertTrue(multi_sig.verify(b"*HelloWorldHelloWorldHelloWorld*"))

    def test_multi_sig_1_of_2(self):
        private_key0, public_key0 = generate_private_and_public_keys()
        private_key1, public_key1 = generate_private_and_public_keys()
        multi_sig = TransactionSpendingCondition.Multisig()
        multi_sig.hash_mode = HashMode.Multisig.P2SH()
        multi_sig.fields = [
            TransactionAuthField.PublicKey(False, public_key0),
            TransactionAuthField.PublicKey(False, public_key1),
        ]
        multi_sig.signatures_required = 1
        multi_sig.tx_fee = 200
        multi_sig.nonce = 10000
        multi_sig.sign(
            b"*HelloWorldHelloWorldHelloWorld*",
            private_key1,
        )
        self.assertIsNotNone(multi_sig.signer)
        self.assertTrue(isinstance(multi_sig.fields[0], TransactionAuthField.PublicKey))
        self.assertTrue(isinstance(multi_sig.fields[1], TransactionAuthField.Signature))
        self.assertTrue(multi_sig.verify(b"*HelloWorldHelloWorldHelloWorld*"))

    def test_multi_sig_3_of_3(self):
        private_key0, public_key0 = generate_private_and_public_keys()
        private_key1, public_key1 = generate_private_and_public_keys()
        private_key2, public_key2 = generate_private_and_public_keys(compressed=True)
        multi_sig = TransactionSpendingCondition.Multisig()
        multi_sig.hash_mode = HashMode.Multisig.P2SH()
        multi_sig.fields = [
            TransactionAuthField.PublicKey(False, public_key0),
            TransactionAuthField.PublicKey(False, public_key1),
            TransactionAuthField.PublicKey(True, public_key2),
        ]
        multi_sig.signatures_required = 3
        multi_sig.tx_fee = 200
        multi_sig.nonce = 10000
        multi_sig.sign(
            b"*HelloWorldHelloWorldHelloWorld*",
            private_key0,
        )
        multi_sig.sign(
            b"*HelloWorldHelloWorldHelloWorld*",
            private_key1,
        )
        multi_sig.sign(
            b"*HelloWorldHelloWorldHelloWorld*",
            private_key2,
        )
        self.assertIsNotNone(multi_sig.signer)
        self.assertTrue(isinstance(multi_sig.fields[0], TransactionAuthField.Signature))
        self.assertTrue(isinstance(multi_sig.fields[1], TransactionAuthField.Signature))
        self.assertTrue(isinstance(multi_sig.fields[2], TransactionAuthField.Signature))
        self.assertTrue(multi_sig.verify(b"*HelloWorldHelloWorldHelloWorld*"))

    def test_multi_sig_3_of_3_unordered(self):
        private_key0, public_key0 = generate_private_and_public_keys()
        private_key1, public_key1 = generate_private_and_public_keys()
        private_key2, public_key2 = generate_private_and_public_keys(compressed=True)
        multi_sig = TransactionSpendingCondition.Multisig()
        multi_sig.hash_mode = HashMode.Multisig.P2SH()
        multi_sig.fields = [
            TransactionAuthField.PublicKey(False, public_key0),
            TransactionAuthField.PublicKey(False, public_key1),
            TransactionAuthField.PublicKey(True, public_key2),
        ]
        multi_sig.signatures_required = 3
        multi_sig.tx_fee = 300
        multi_sig.nonce = 10
        multi_sig.sign(
            b"*HelloWorldHelloWorldHelloWorld*",
            private_key1,
        )
        multi_sig.sign(
            b"*HelloWorldHelloWorldHelloWorld*",
            private_key2,
        )
        multi_sig.sign(
            b"*HelloWorldHelloWorldHelloWorld*",
            private_key0,
        )
        self.assertIsNotNone(multi_sig.signer)
        self.assertTrue(isinstance(multi_sig.fields[0], TransactionAuthField.Signature))
        self.assertTrue(isinstance(multi_sig.fields[1], TransactionAuthField.Signature))
        self.assertTrue(isinstance(multi_sig.fields[2], TransactionAuthField.Signature))
        self.assertTrue(multi_sig.verify(b"*HelloWorldHelloWorldHelloWorld*"))
