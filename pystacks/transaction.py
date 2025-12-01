import hashlib
from io import BytesIO
import struct
from .utils import (
    read_vector_class_from_stream,
    read_string_from_stream,
    read_vector_u8_from_stream,
    read_u8_from_stream,
    read_u32_from_stream,
    read_u64_from_stream,
    write_u8_to_stream,
    write_u32_to_stream,
    write_u64_to_stream,
    write_vector_class_to_stream,
    write_string_to_stream,
    write_vector_u8_to_stream,
    serialize,
    recover_pubkey_from_signature,
    ByteType,
    verify,
    hash160,
    compressed_pubkey,
    sha512_256,
    sign,
    get_public_key,
)

from typing import Union


class HashMode(ByteType):

    class Singlesig:

        @serialize(0x00)
        class P2PKH:
            pass

        @serialize(0x02)
        class P2WPKH:
            pass

    class Multisig:

        @serialize(0x01)
        class P2SH:
            pass

        @serialize(0x03)
        class P2WSH:
            pass

    class OrderIndependentMultisig:

        @serialize(0x05)
        class P2SH:
            pass

        @serialize(0x07)
        class P2WSH:
            pass


class ClarityVersion(ByteType):
    @serialize(0x01)
    class Clarity1:
        pass

    @serialize(0x02)
    class Clarity2:
        pass

    @serialize(0x03)
    class Clarity3:
        pass

    @serialize(0x04)
    class Clarity4:
        pass


class TransactionSmartContract:
    def __init__(self, name=None, code_body=None):
        self.name = name
        self.code_body = code_body

    @staticmethod
    def from_stream(stream):
        smart_contract = TransactionSmartContract()
        smart_contract.name = read_string_from_stream(stream)
        smart_contract.code_body = read_vector_u8_from_stream(stream)
        return smart_contract

    def to_stream(self, stream):
        write_string_to_stream(stream, self.name)
        write_vector_u8_to_stream(stream, self.code_body)


class TransactionPayload:
    class TokenTransfer:
        pass

    class ContractCall:
        pass

    class SmartContract:
        @staticmethod
        def from_stream(stream):
            raise Exception("Unsupported SmartContract")

    class PoisonMicroblock:
        pass

    class Coinbase:
        pass

    class CoinbaseToAltRecipient:
        pass

    class VersionedSmartContract:
        def __init__(self):
            self.version = None
            self.smart_contract = None

        @staticmethod
        def from_stream(stream):
            versioned_smart_contract = TransactionPayload.VersionedSmartContract()
            versioned_smart_contract.version = ClarityVersion.from_stream(stream)
            versioned_smart_contract.smart_contract = (
                TransactionSmartContract.from_stream(stream)
            )

            return versioned_smart_contract

        def to_stream(self, stream):
            write_u8_to_stream(stream, 0x06)
            self.version.to_stream(stream)
            self.smart_contract.to_stream(stream)

    class TenureChange:
        pass

    class NakamotoCoinbase:
        pass

    @staticmethod
    def from_stream(stream):
        payload_id = read_u8_from_stream(stream)
        if payload_id == 0x00:
            return TransactionPayload.TokenTransfer.from_stream(stream)
        elif payload_id == 0x01:
            return TransactionPayload.SmartContract.from_stream(stream)
        elif payload_id == 0x02:
            return TransactionPayload.ContractCall.from_stream(stream)
        elif payload_id == 0x03:
            return TransactionPayload.PoisonMicroblock.from_stream(stream)
        elif payload_id == 0x04:
            return TransactionPayload.Coinbase.from_stream(stream)
        elif payload_id == 0x05:
            return TransactionPayload.CoinbaseToAltRecipient.from_stream(stream)
        elif payload_id == 0x06:
            return TransactionPayload.VersionedSmartContract.from_stream(stream)
        elif payload_id == 0x07:
            return TransactionPayload.TenureChange.from_stream(stream)
        elif payload_id == 0x08:
            return TransactionPayload.NakamotoCoinbase.from_stream(stream)
        raise Exception("Unsupported TransactionPayload")


class TransactionPostCondition:
    class STX:
        pass

    class Fungible:
        pass

    class Nonfungible:
        pass

    @staticmethod
    def from_stream(stream):
        asset_info_id = read_u8_from_stream(stream)
        if asset_info_id == 0x00:
            return TransactionPostCondition.STX.from_stream(stream)
        elif asset_info_id == 0x01:
            return TransactionPostCondition.Fungible.from_stream(stream)
        elif asset_info_id == 0x02:
            return TransactionPostCondition.Nonfungible.from_stream(stream)
        raise Exception("Unsupported TransactionPostCondition")


class TransactionPostConditionMode(ByteType):
    @serialize(0x01)
    class Allow:
        pass

    @serialize(0x02)
    class Deny:
        pass


class TransactionAnchorMode(ByteType):
    @serialize(0x01)
    class OnChainOnly:
        pass

    @serialize(0x02)
    class OffChainOnly:
        pass

    @serialize(0x03)
    class Any:
        pass


class TransactionPublicKeyEncoding(ByteType):
    @serialize(0x00)
    class Compressed:
        pass

    @serialize(0x01)
    class Uncompressed:
        pass


class TransactionSpendingCondition:
    class Singlesig:
        def __init__(self):
            self.hash_mode = None
            self.signer = None
            self.nonce = None
            self.tx_fee = None
            self.key_encoding = None
            self.signature = None

        @staticmethod
        def from_stream(stream):
            condition_singlesig = TransactionSpendingCondition.Singlesig()
            condition_singlesig.hash_mode = HashMode.from_stream(stream)
            condition_singlesig.signer = stream.read(20)
            condition_singlesig.nonce = read_u64_from_stream(stream)
            condition_singlesig.tx_fee = read_u64_from_stream(stream)
            condition_singlesig.key_encoding = TransactionPublicKeyEncoding.from_stream(
                stream
            )
            condition_singlesig.signature = stream.read(65)

            return condition_singlesig

        def to_stream(self, stream):
            self.hash_mode.to_stream(stream)
            stream.write(self.signer)
            write_u64_to_stream(stream, self.nonce)
            write_u64_to_stream(stream, self.tx_fee)
            self.key_encoding.to_stream(stream)
            stream.write(self.signature)

        def get_hash(self, tx):
            tx_copy = tx.copy()
            tx_copy.auth.origin.tx_fee = 0
            tx_copy.auth.origin.nonce = 0
            tx_copy.auth.origin.signature = bytes(65)
            tx_copy_txid = tx_copy.txid()

            return sha512_256(
                tx_copy_txid
                + b"\x04"
                + struct.pack(">QQ", tx.auth.origin.tx_fee, tx.auth.origin.nonce)
            )

        def sign(self, tx, private_key):
            # ensure teh signature is empty before doing any operation
            self.signature = bytes(65)
            # TODO honour self.hash_mode
            if isinstance(self.key_encoding, TransactionPublicKeyEncoding.Uncompressed):
                self.signer = hash160(get_public_key(private_key))
            else:
                self.signer = hash160(get_public_key(private_key, True))

            self.signature = sign(private_key, self.get_hash(tx))

        def verify(self, tx):
            hash = self.get_hash(tx)
            pubkey = recover_pubkey_from_signature(self.signature, hash)

            # TODO honour self.hash_mode
            if isinstance(self.key_encoding, TransactionPublicKeyEncoding.Uncompressed):
                pubkey_hash = hash160(pubkey)
            else:
                pubkey_hash = hash160(compressed_pubkey(pubkey))

            return (
                verify(pubkey, self.signature, hash)
                and hash160(pubkey_hash) == self.signer
            )

    class Multisig:
        pass

    class OrderIndependentMultisig:
        pass

    @staticmethod
    def from_stream(stream):
        hash_mode = HashMode.peek_from_stream(stream)
        if isinstance(hash_mode, (HashMode.Singlesig.P2PKH, HashMode.Singlesig.P2WPKH)):
            return TransactionSpendingCondition.Singlesig.from_stream(stream)
        raise Exception("Unsupported TransactionSpendingCondition")


class TransactionAuth:
    class Standard:
        def __init__(self):
            self.origin: Union[
                TransactionSpendingCondition.Singlesig,
                TransactionSpendingCondition.Multisig,
                TransactionSpendingCondition.OrderIndependentMultisig,
            ] = None

        @staticmethod
        def from_stream(stream):
            auth_standard = TransactionAuth.Standard()
            auth_standard.origin = TransactionSpendingCondition.from_stream(stream)
            return auth_standard

        def to_stream(self, stream):
            write_u8_to_stream(stream, 0x04)
            self.origin.to_stream(stream)

        def sign(self, tx, private_key):
            self.origin.sign(tx, private_key)

        def verify(self, tx):
            return self.origin.verify(tx)

    class Sponsored:
        pass

    @staticmethod
    def from_stream(stream):
        auth_type = read_u8_from_stream(stream)
        if auth_type == 0x04:
            return TransactionAuth.Standard.from_stream(stream)
        elif auth_type == 0x05:
            return TransactionAuth.Sponsored.from_stream(stream)
        raise Exception("Unsupported TransactionAuth")


class Transaction:

    def __init__(self):
        self.version = None
        self.chain_id = None
        self.auth: Union[TransactionAuth.Standard, TransactionAuth.Sponsored] = None
        self.anchor_mode = None
        self.post_condition_mode = None
        self.post_conditions = None
        self.payload = None

    @staticmethod
    def from_stream(stream):
        transaction = Transaction()
        transaction.version = read_u8_from_stream(stream)
        transaction.chain_id = read_u32_from_stream(stream)

        transaction.auth = TransactionAuth.from_stream(stream)
        transaction.anchor_mode = TransactionAnchorMode.from_stream(stream)
        transaction.post_condition_mode = TransactionPostConditionMode.from_stream(
            stream
        )
        transaction.post_conditions = read_vector_class_from_stream(
            stream, TransactionPostCondition
        )

        transaction.payload = TransactionPayload.from_stream(stream)

        return transaction

    @staticmethod
    def from_hex(hex_string):
        return Transaction.from_stream(BytesIO(bytes.fromhex(hex_string)))

    def to_stream(self, stream):
        write_u8_to_stream(stream, self.version)
        write_u32_to_stream(stream, self.chain_id)
        self.auth.to_stream(stream)
        self.anchor_mode.to_stream(stream)
        self.post_condition_mode.to_stream(stream)
        write_vector_class_to_stream(stream, self.post_conditions)
        self.payload.to_stream(stream)

    def to_bytes(self):
        stream = BytesIO()
        self.to_stream(stream)
        stream.seek(0)
        return stream.read()

    def to_hex(self):
        return self.to_bytes().hex()

    def txid(self):
        return sha512_256(self.to_bytes())

    def copy(self):
        stream = BytesIO()
        self.to_stream(stream)
        stream.seek(0)
        return Transaction.from_stream(stream)

    def verify(self):
        return self.auth.verify(self)

    def sign(self, private_key):
        self.auth.sign(self, private_key)
