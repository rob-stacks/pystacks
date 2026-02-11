from .utils import (
    ByteType,
    read_u8_from_stream,
    read_string_from_stream,
    serialize,
    hash160,
    c32_address,
)
from .curves import get_compressed_public_key, is_public_key_compressed
from .clarity import TypePrefix
import struct


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


class HashMode(ByteType):

    class Singlesig:

        @serialize(0x00)
        class P2PKH:
            def get_public_key_hash(self, public_key, compressed):
                if compressed:
                    return hash160(get_compressed_public_key(public_key))
                else:
                    return hash160(public_key)

            def public_key_to_address(self, version, public_key):
                public_key_hash = self.get_public_key_hash(
                    public_key, is_public_key_compressed(public_key)
                )
                return c32_address(version, public_key_hash)

        @serialize(0x02)
        class P2WPKH:
            def get_public_key_hash(self, public_key, compressed):
                if compressed:
                    public_key_hash = hash160(get_compressed_public_key(public_key))
                else:
                    public_key_hash = hash160(public_key)
                # OP_FALSE + len(key_hash) + key_hash
                return (
                    b"\x00"
                    + struct.pack("BB", 0, len(public_key_hash))
                    + public_key_hash
                )

            def public_key_to_address(self, version, public_key):
                public_key_hash = self.get_public_key_hash(
                    public_key, is_public_key_compressed(public_key)
                )
                return c32_address(version, public_key_hash)

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


class StacksAddress:

    def __init__(self, version=None, _bytes=None):
        self.version = version
        self._bytes = _bytes

    @staticmethod
    def from_stream(stream):
        stacks_address = StacksAddress()
        stacks_address.version = read_u8_from_stream(stream)
        stacks_address._bytes = stream.read(20)
        return stacks_address

    def to_stream(self, stream):
        self.version.to_stream(stream)
        stream.write(self._bytes)

    def __repr__(self):
        return c32_address(self.version, self._bytes)
