import hashlib
from io import BytesIO
import struct
from .utils import (
    read_vector_class_from_stream,
    read_string_from_stream,
    read_vector_u8_from_stream,
    read_u8_from_stream,
    read_u16_from_stream,
    read_u32_from_stream,
    read_u64_from_stream,
    write_u8_to_stream,
    write_u16_to_stream,
    write_u32_to_stream,
    write_u64_to_stream,
    write_vector_class_to_stream,
    write_string_to_stream,
    write_vector_u8_to_stream,
    serialize,
    recover_public_key_from_signature,
    ByteType,
    verify,
    hash160,
    get_compressed_public_key,
    sha512_256,
    sign,
    get_public_key,
    c32_address,
    C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
    C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
    C32_ADDRESS_VERSION_MAINNET_MULTISIG,
    C32_ADDRESS_VERSION_TESTNET_MULTISIG,
    is_public_key_compressed,
    RaiseOnUnsupported,
)
from .clarity import ClarityVersion, Value
from .auth import HashMode, PrincipalData, StacksAddress

from typing import Union
from collections.abc import Iterable


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


class TransactionVersion(ByteType):

    @serialize(C32_ADDRESS_VERSION_MAINNET_SINGLESIG)
    class Mainnet:
        pass

    @serialize(C32_ADDRESS_VERSION_TESTNET_SINGLESIG)
    class Testnet:
        pass


class TransactionPayload(RaiseOnUnsupported):
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
        raise TransactionPayload.Unsupported(TransactionPayload, payload_id)


class AssetInfoID(ByteType):

    @serialize(0)
    class STX:
        pass

    @serialize(1)
    class FungibleAsset:
        pass

    @serialize(2)
    class NonfungibleAsset:
        pass


class PostConditionPrincipalID(ByteType):

    @serialize(0x01)
    class Origin:
        pass

    @serialize(0x02)
    class Standard:
        pass

    @serialize(0x03)
    class Contract:
        pass


class FungibleConditionCode(ByteType):

    @serialize(0x01)
    class SentEq:
        pass

    @serialize(0x02)
    class SentGt:
        pass

    @serialize(0x03)
    class SentGe:
        pass

    @serialize(0x04)
    class SentLt:
        pass

    @serialize(0x05)
    class SentLe:
        pass


class AssetInfo:

    def __init__(self, address, contract_name, asset_name):
        self.address = address
        self.contract_name = contract_name
        self.asset_name = asset_name

    @staticmethod
    def from_stream(stream):
        address = StacksAddress.from_stream(stream)
        contract_name = read_string_from_stream(stream)
        asset_name = read_string_from_stream(stream)
        return AssetInfo(address, contract_name, asset_name)


class PostConditionPrincipal:

    class Origin:
        pass

    class Standard:

        def __init__(self, address):
            self.address = address

        @staticmethod
        def from_stream(stream):
            return PostConditionPrincipal.Standard(StacksAddress.from_stream(stream))

    class Contract:
        def __init__(self, address, contract_name):
            self.address = address
            self.contract_name = contract_name

        @staticmethod
        def from_stream(stream):
            return PostConditionPrincipal.Contract(
                StacksAddress.from_stream(stream), read_string_from_stream(stream)
            )

    @staticmethod
    def from_stream(stream):
        post_condition_principal_id = PostConditionPrincipalID.from_stream(stream)
        if isinstance(post_condition_principal_id, PostConditionPrincipalID.Origin):
            return PostConditionPrincipal.Origin()
        elif isinstance(post_condition_principal_id, PostConditionPrincipalID.Standard):
            return PostConditionPrincipal.Standard.from_stream(stream)
        elif isinstance(post_condition_principal_id, PostConditionPrincipalID.Contract):
            return PostConditionPrincipal.Contract.from_stream(stream)


class TransactionPostCondition(RaiseOnUnsupported):
    class STX:
        def __init__(self, principal, fungible_condition_code, amount):
            self.principal = principal
            self.fungible_condition_code = fungible_condition_code
            self.amount = amount

        @staticmethod
        def from_stream(stream):
            principal = PostConditionPrincipal.from_stream(stream)
            fungible_condition_code = FungibleConditionCode.from_stream(stream)
            amount = read_u64_from_stream(stream)
            return TransactionPostCondition.STX(
                principal, fungible_condition_code, amount
            )

    class Fungible:
        def __init__(self, principal, asset_info, fungible_condition_code, amount):
            self.principal = principal
            self.asset_info = asset_info
            self.fungible_condition_code = fungible_condition_code
            self.amount = amount

        @staticmethod
        def from_stream(stream):
            principal = PostConditionPrincipal.from_stream(stream)
            asset_info = AssetInfo.from_stream(stream)
            fungible_condition_code = FungibleConditionCode.from_stream(stream)
            amount = read_u64_from_stream(stream)
            return TransactionPostCondition.Fungible(
                principal, asset_info, fungible_condition_code, amount
            )

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
        raise TransactionPostCondition.Unsupported(
            TransactionPostCondition, asset_info_id
        )


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


class TransactionAuthFlags(ByteType):
    @serialize(0x04)
    class AuthStandard:
        pass

    @serialize(0x05)
    class AuthSponsored:
        pass


class TransactionAuthFieldID(ByteType):

    @serialize(0x00)
    class PublicKeyCompressed:
        pass

    @serialize(0x01)
    class PublicKeyUncompressed:
        pass

    @serialize(0x02)
    class SignatureCompressed:
        pass

    @serialize(0x03)
    class SignatureUncompressed:
        pass


class TransactionAuthField(RaiseOnUnsupported):
    class PublicKey(RaiseOnUnsupported):
        def __init__(self, compressed=None, data=None):
            self.compressed = compressed
            self.data = data

        @staticmethod
        def from_stream(stream):
            auth_field_id = TransactionAuthFieldID.from_stream(stream)
            if isinstance(auth_field_id, TransactionAuthFieldID.PublicKeyCompressed):
                return TransactionAuthField.PublicKey(True, stream.read(33))
            elif isinstance(
                auth_field_id, TransactionAuthFieldID.PublicKeyUncompressed
            ):
                return TransactionAuthField.PublicKey(False, stream.read(33))
            else:
                raise TransactionAuthField.PublicKey.Unsupported(
                    TransactionAuthFieldID, auth_field_id
                )

    class Signature:
        def __init__(self, compressed=None, data=None):
            self.compressed = compressed
            self.data = data

        @staticmethod
        def from_stream(stream):
            auth_field_id = TransactionAuthFieldID.from_stream(stream)
            if isinstance(auth_field_id, TransactionAuthFieldID.SignatureCompressed):
                return TransactionAuthField.Signature(True, stream.read(65))
            elif isinstance(
                auth_field_id, TransactionAuthFieldID.SignatureUncompressed
            ):
                return TransactionAuthField.Signature(False, stream.read(65))
            else:
                raise TransactionAuthField.Signature.Unsupported(
                    TransactionAuthFieldID, auth_field_id
                )

    @staticmethod
    def from_stream(stream):
        auth_field_id = TransactionAuthFieldID.peek_from_stream(stream)
        if isinstance(auth_field_id, TransactionAuthFieldID.PublicKeyCompressed):
            return TransactionAuthField.PublicKey.from_stream(stream)
        elif isinstance(auth_field_id, TransactionAuthFieldID.PublicKeyUncompressed):
            return TransactionAuthField.PublicKey.from_stream(stream)
        elif isinstance(auth_field_id, TransactionAuthFieldID.SignatureCompressed):
            return TransactionAuthField.Signature.from_stream(stream)
        elif isinstance(auth_field_id, TransactionAuthFieldID.SignatureUncompressed):
            return TransactionAuthField.Signature.from_stream(stream)
        raise TransactionAuthField.Unsupported(TransactionAuthFieldID, auth_field_id)


class TransactionSpendingCondition:
    class Singlesig(RaiseOnUnsupported):
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

        def get_hash_tx(self, tx, cond_code):
            tx_copy = tx.copy()
            tx_copy.auth.origin.tx_fee = 0
            tx_copy.auth.origin.nonce = 0
            tx_copy.auth.origin.signature = bytes(65)
            tx_copy_txid = tx_copy.txid()

            return sha512_256(
                tx_copy_txid
                + struct.pack(
                    ">BQQ", cond_code, tx.auth.origin.tx_fee, tx.auth.origin.nonce
                )
            )

        def validate_hash_mode(self):
            if not isinstance(
                self.hash_mode, (HashMode.Singlesig.P2PKH, HashMode.Singlesig.P2WPKH)
            ):
                raise TransactionSpendingCondition.Singlesig.Unsupported(
                    self, self.hash_mode
                )

        def sign(self, data, private_key):
            self.validate_hash_mode()
            # ensure the signature is empty before doing any operation
            self.signature = bytes(65)
            self.signer = self.hash_mode.get_public_key_hash(
                get_public_key(private_key), self.key_encoding
            )
            self.signature = sign(private_key, data)

        def verify(self, data):
            self.validate_hash_mode()
            public_key = recover_public_key_from_signature(self.signature, data)
            public_key_hash = self.hash_mode.get_public_key_hash(
                public_key, self.key_encoding
            )
            return (
                verify(public_key, self.signature, data)
                and public_key_hash == self.signer
            )

    class Multisig:
        def __init__(self):
            self.hash_mode = None
            self.signer = None
            self.nonce = None
            self.tx_fee = None
            self.fields: Iterable[TransactionAuthField] = None
            self.signatures_required = None
            self.sighash = None

        @staticmethod
        def from_stream(stream):
            condition_multisig = TransactionSpendingCondition.Multisig()
            condition_multisig.hash_mode = HashMode.from_stream(stream)
            condition_multisig.signer = stream.read(20)
            condition_multisig.nonce = read_u64_from_stream(stream)
            condition_multisig.tx_fee = read_u64_from_stream(stream)
            condition_multisig.fields = read_vector_class_from_stream(
                stream, TransactionAuthField
            )
            condition_multisig.signatures_required = read_u16_from_stream(stream)

            return condition_multisig

        def to_stream(self, stream):
            self.hash_mode.to_stream(stream)
            stream.write(self.signer)
            write_u64_to_stream(stream, self.nonce)
            write_u64_to_stream(stream, self.tx_fee)
            write_vector_class_to_stream(stream, self.fields)
            write_u16_to_stream(stream, self.signatures_required)

        def get_hash_tx(self, tx, cond_code):
            if self.sighash is None:
                self.sighash
                tx_copy = tx.copy()
                tx_copy.auth.origin.tx_fee = 0
                tx_copy.auth.origin.nonce = 0
                tx_copy.auth.origin.fields = []
                tx_copy_txid = tx_copy.txid()

                self.sighash = sha512_256(
                    tx_copy_txid
                    + struct.pack(
                        ">BQQ", cond_code, tx.auth.origin.tx_fee, tx.auth.origin.nonce
                    )
                )

            return (
                self.sighash,
                cond_code,
                tx.auth.origin.tx_fee,
                tx.auth.origin.nonce,
            )

        def validate_hash_mode(self):
            if not isinstance(
                self.hash_mode, (HashMode.Multisig.P2SH, HashMode.Multisig.P2WSH)
            ):
                raise Exception("Invalid HashMode {}".format(self.hash_mode))

        def sign(self, data, private_key):
            self.validate_hash_mode()

            if self.sighash is None:
                self.sighash = data

            if self.signer is None:
                # num_sigs + self.fields + len(self.fields) + OP_CHECKMULTISIG = 0xae
                # TODO check for P2WSH
                self.signer = hash160(
                    struct.pack("B", self.signatures_required)
                    + b"".join(
                        [
                            struct.pack("B", len(field.data)) + field.data
                            for field in self.fields
                        ]
                    )
                    + struct.pack("B", len(self.fields))
                    + b"\xae"
                )

            if self.signatures_required is None or self.signatures_required < 1:
                raise Exception(
                    "Invalid number of required signatures: {}".format(
                        self.signatures_required
                    )
                )

            # check the number of fields over signatures_required
            if self.fields is None or len(self.fields) < self.signatures_required:
                raise Exception(
                    "Invalid number of fields: {} (expected {})".format(
                        len(self.fields) if self.fields else 0, self.signatures_required
                    )
                )

            # find the slot we are signing
            compressed_signing_public_key = get_public_key(private_key, compressed=True)
            uncompressed_signing_public_key = get_public_key(
                private_key, compressed=False
            )
            found_slot = None
            key_encoding = None
            for slot, field in enumerate(self.fields):
                if (
                    field.compressed and field.data == compressed_signing_public_key
                ) or (
                    not field.compressed
                    and field.data == uncompressed_signing_public_key
                ):
                    key_encoding = (
                        TransactionPublicKeyEncoding.Compressed()
                        if field.compressed
                        else TransactionPublicKeyEncoding.Uncompressed()
                    )
                    found_slot = slot
                    break

            if found_slot is None:
                raise Exception("Unable to find the signing slot for the specified key")

            data_to_sign = sha512_256(
                self.sighash
                + struct.pack(
                    ">BQQ", TransactionAuthFlags.AuthStandard(), self.tx_fee, self.nonce
                )
            )
            signature = sign(private_key, data_to_sign)
            self.fields[found_slot] = TransactionAuthField.Signature(
                compressed=self.fields[found_slot].compressed, data=signature
            )
            self.sighash = sha512_256(
                data_to_sign + struct.pack("B", key_encoding) + signature
            )

        def verify(self, data):
            self.validate_hash_mode()

            cur_sighash = sha512_256(
                data
                + struct.pack(
                    ">BQQ", TransactionAuthFlags.AuthStandard(), self.tx_fee, self.nonce
                )
            )

            valid_signatures = 0
            for field in self.fields:
                if isinstance(field, TransactionAuthField.Signature):
                    public_key = recover_public_key_from_signature(
                        field.data, cur_sighash, field.compressed
                    )
                    if not verify(public_key, field.data, cur_sighash):
                        raise Exception("Validation failed")
                    valid_signatures += 1
                    cur_sighash = sha512_256(
                        cur_sighash
                        + struct.pack(
                            "B",
                            (
                                TransactionPublicKeyEncoding.Compressed()
                                if field.compressed
                                else TransactionPublicKeyEncoding.Uncompressed()
                            ),
                        )
                        + field.data
                    )
                elif isinstance(field, TransactionAuthField.PublicKey):
                    continue
                else:
                    raise Exception("Invalid TransactionAuthField")

            # TODO check self.signer
            if valid_signatures < self.signatures_required:
                raise Exception("Not enough signatures")

            return True

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
            TransactionAuthFlags.AuthStandard().to_stream(stream)
            self.origin.to_stream(stream)

        def sign(self, tx, private_key):
            data = self.origin.get_hash_tx(tx)
            self.origin.sign(data, private_key)

        def verify(self, tx):
            data = self.origin.get_hash_tx(tx)
            return self.origin.verify(data, TransactionAuthFlags.AuthStandard())

    class Sponsored:
        pass

    @staticmethod
    def from_stream(stream):
        auth_type = TransactionAuthFlags.from_stream(stream)
        if isinstance(auth_type, TransactionAuthFlags.AuthStandard):
            return TransactionAuth.Standard.from_stream(stream)
        elif isinstance(auth_type, TransactionAuthFlags.AuthSponsored):
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
