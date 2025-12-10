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
    C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
    C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
)
from .clarity import Value, TypePrefix

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


class TenureChangeCause(ByteType):

    @serialize(0)
    class BlockFound:
        pass

    @serialize(1)
    class Extended:
        pass

    @serialize(2)
    class ExtendedRuntime:
        pass

    @serialize(3)
    class ExtendedReadCount:
        pass

    @serialize(4)
    class ExtendedReadLength:
        pass

    @serialize(5)
    class ExtendedWriteCount:
        pass

    @serialize(6)
    class ExtendedWriteLength:
        pass


class PrincipalData:

    class Standard:
        def __init__(self):
            self.version = None
            self.data = None

        @staticmethod
        def from_stream(stream):
            standard = PrincipalData.Standard()
            standard.version = read_u8_from_stream(stream)
            standard.data = stream.read(20)
            return standard

    class Contract:
        def __init__(self):
            self.issuer = None
            self.name = None

        @staticmethod
        def from_stream(stream):
            contract = PrincipalData.Contract()
            contract.issuer = PrincipalData.Standard.from_stream(stream)
            contract.name = read_string_from_stream(stream)

    @staticmethod
    def from_stream(stream):
        principal_data_type = TypePrefix.from_stream(stream)
        if isinstance(principal_data_type, TypePrefix.PrincipalStandard):
            return PrincipalData.Standard.from_stream(stream)
        elif isinstance(principal_data_type, TypePrefix.PrincipalContract):
            return PrincipalData.Contract.from_stream(stream)
        raise Exception("Unsupported PrincipalData")


class TransactionVersion(ByteType):

    @serialize(C32_ADDRESS_VERSION_MAINNET_SINGLESIG)
    class Mainnet:
        pass

    @serialize(C32_ADDRESS_VERSION_TESTNET_SINGLESIG)
    class Testnet:
        pass


class StacksAddress:

    def __init__(self, version=None, _bytes=None):
        self.version = version
        self._bytes = _bytes

    @staticmethod
    def from_stream(stream):
        stacks_address = StacksAddress()
        stacks_address.version = TransactionVersion.from_stream(stream)
        stacks_address._bytes = stream.read(20)
        return stacks_address

    def to_stream(self, stream):
        self.version.to_stream(stream)
        stream.write(self._bytes)


class TransactionPayload:
    class TokenTransfer:
        def __init__(self):
            self.principal_data = None
            self.amount = None
            self.memo = None

        @staticmethod
        def from_stream(stream):
            token_transfer = TransactionPayload.TokenTransfer()
            token_transfer.principal_data = PrincipalData.from_stream(stream)
            token_transfer.amount = read_u64_from_stream(stream)
            token_transfer.memo = stream.read(34)
            return token_transfer

    class ContractCall:
        def __init__(
            self,
            address=None,
            contract_name=None,
            function_name=None,
            function_args=None,
        ):
            self.address = address
            self.contract_name = contract_name
            self.function_name = function_name
            self.function_args = function_args

        @staticmethod
        def from_stream(stream):
            contract_call = TransactionPayload.ContractCall()
            contract_call.address = StacksAddress.from_stream(stream)
            contract_call.contract_name = read_string_from_stream(stream)
            contract_call.function_name = read_string_from_stream(stream)
            contract_call.function_args = read_vector_class_from_stream(stream, Value)
            return contract_call

        def to_stream(self, stream):
            write_u8_to_stream(stream, 0x02)
            self.address.to_stream(stream)
            write_string_to_stream(stream, self.contract_name)
            write_string_to_stream(stream, self.function_name)
            write_vector_class_to_stream(stream, self.function_args)

    class SmartContract:
        @staticmethod
        def from_stream(stream):
            raise Exception("Unsupported SmartContract")

    class PoisonMicroblock:
        pass

    class Coinbase:
        def __init__(self):
            self.coinbase_payload = None

        @staticmethod
        def from_stream(stream):
            coinbase = TransactionPayload.NakamotoCoinbase()
            coinbase.coinbase_payload = stream.read(32)
            return coinbase

    class CoinbaseToAltRecipient:
        pass

    class VersionedSmartContract:
        def __init__(self, version=None, smart_contract=None):
            self.version = version
            self.smart_contract = smart_contract

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
        def __init__(self):
            self.tenure_consensus_hash = None
            self.prev_tenure_consensus_hash = None
            self.burn_view_consensus_hash = None
            self.previous_tenure_end = None
            self.previous_tenure_blocks = None
            self.cause = None
            self.pubkey_hash = None

        @staticmethod
        def from_stream(stream):
            tenure_change = TransactionPayload.TenureChange()
            tenure_change.tenure_consensus_hash = stream.read(20)
            tenure_change.prev_tenure_consensus_hash = stream.read(20)
            tenure_change.burn_view_consensus_hash = stream.read(20)
            tenure_change.previous_tenure_end = stream.read(32)
            tenure_change.previous_tenure_blocks = read_u32_from_stream(stream)
            tenure_change.cause = TenureChangeCause.from_stream(stream)
            tenure_change.pubkey_hash = stream.read(20)
            return tenure_change

    class NakamotoCoinbase:
        def __init__(self):
            self.coinbase_payload = None
            self.recipient = None
            self.vrf_proof = None

        @staticmethod
        def from_stream(stream):
            nakamoto_coinbase = TransactionPayload.NakamotoCoinbase()
            nakamoto_coinbase.coinbase_payload = stream.read(32)
            nakamoto_coinbase.recipient = Value.from_stream(stream)
            nakamoto_coinbase.vrf_proof = stream.read(80)
            return nakamoto_coinbase

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
        raise Exception("Unsupported TransactionPayload 0x{:02x}".format(payload_id))


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
        raise Exception("Unsupported TransactionAuth {}".format(auth_type))


class Transaction:

    def __init__(self):
        self.version = None
        self.chain_id = None
        self.auth: Union[TransactionAuth.Standard, TransactionAuth.Sponsored] = None
        self.anchor_mode = None
        self.post_condition_mode = None
        self.post_conditions = None
        self.payload: Union[
            TransactionPayload.NakamotoCoinbase,
            TransactionPayload.Coinbase,
            TransactionPayload.CoinbaseToAltRecipient,
            TransactionPayload.ContractCall,
            TransactionPayload.SmartContract,
            TransactionPayload.TenureChange,
            TransactionPayload.VersionedSmartContract,
            TransactionPayload.PoisonMicroblock,
            TransactionPayload.TokenTransfer,
        ] = None

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
