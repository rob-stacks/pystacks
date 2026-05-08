import struct
import hashlib
from .curves import get_public_key

C32_CHARACTERS = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ"
C32_ADDRESS_VERSION_MAINNET_SINGLESIG = 22
C32_ADDRESS_VERSION_TESTNET_SINGLESIG = 26
C32_ADDRESS_VERSION_MAINNET_MULTISIG = 20
C32_ADDRESS_VERSION_TESTNET_MULTISIG = 21


def c32_encode(input_bytes):
    result = b""
    carry = 0
    carry_bits = 0

    for current_value in reversed(input_bytes):
        low_bits_to_take = 5 - carry_bits
        low_bits = current_value & ((1 << low_bits_to_take) - 1)
        c32_value = (low_bits << carry_bits) + carry
        result += bytes((C32_CHARACTERS[c32_value],))
        carry_bits = (8 + carry_bits) - 5
        carry = current_value >> (8 - carry_bits)

        if carry_bits >= 5:
            c32_value = carry & ((1 << 5) - 1)
            result += bytes((C32_CHARACTERS[c32_value],))
            carry_bits -= 5
            carry >>= 5

    if carry_bits > 0:
        result += bytes((C32_CHARACTERS[carry],))

    # remove leading zeros from c32 encoding
    result = result.rstrip(b"0")

    # add leading zeros from input.
    for current_value in input_bytes:
        if current_value == 0:
            result += b"0"
        else:
            break

    return bytes(reversed(result))


def c32_decode(input_bytes):
    decoded = []
    result = []
    for current_value in reversed(input_bytes):
        decoded.append(C32_CHARACTERS.index(current_value))

    if len(decoded) != len(input_bytes):
        raise Exception("Invalid c32 sequence")

    carry = 0
    carry_bits = 0

    for current_5bit in decoded:
        carry += current_5bit << carry_bits
        carry_bits += 5

        if carry_bits >= 8:
            result.append(carry & ((1 << 8) - 1))
            carry_bits -= 8
            carry >>= 8

    if carry_bits > 0:
        result.append(carry)

    for _ in range(0, len(result)):
        v = result.pop()
        if v != 0:
            result.append(v)
            break

    for current_value in reversed(decoded):
        if current_value == 0:
            result.append(0)
        else:
            break

    return bytes(reversed(result))


def c32_address(version, data):
    checksum = sha256(sha256(bytes((version,)) + data))[:4]
    final_data = c32_encode(data + checksum)
    return (b"S" + bytes((C32_CHARACTERS[version],)) + final_data).decode("utf8")


def read_vector_class_from_stream(stream, _class):
    vector_len = read_u32_from_stream(stream)
    vector = []
    for _ in range(0, vector_len):
        vector.append(_class.from_stream(stream))
    return vector


def write_vector_class_to_stream(stream, items):
    if items is None:
        items = []
    write_u32_to_stream(stream, len(items))
    for item in items:
        item.to_stream(stream)


def read_string_from_stream(stream):
    string_len = read_u8_from_stream(stream)
    data = stream.read(string_len)
    return data.decode("utf8")


def read_ascii_string_from_stream(stream):
    string_len = read_u8_from_stream(stream)
    data = stream.read(string_len)
    return data.decode("ascii")


def read_vector_u8_from_stream(stream):
    vector_len = read_u32_from_stream(stream)
    return stream.read(vector_len)


def read_u8_from_stream(stream):
    return stream.read(1)[0]


def read_u16_from_stream(stream):
    return struct.unpack(">H", stream.read(2))[0]


def read_u32_from_stream(stream):
    return struct.unpack(">I", stream.read(4))[0]


def read_u64_from_stream(stream):
    return struct.unpack(">Q", stream.read(8))[0]


def read_u128_from_stream(stream):
    high, low = struct.unpack(">QQ", stream.read(8 * 2))
    return high << 64 | low


def read_i128_from_stream(stream):
    high, low = struct.unpack(">qQ", stream.read(8 * 2))
    return high << 64 | low


def write_u8_to_stream(stream, value):
    stream.write(struct.pack("B", value))


def write_u16_to_stream(stream, value):
    stream.write(struct.pack(">H", value))


def write_u32_to_stream(stream, value):
    stream.write(struct.pack(">I", value))


def write_u64_to_stream(stream, value):
    stream.write(struct.pack(">Q", value))


def write_u128_to_stream(stream, value):
    high = value >> 64
    low = value & 0xFFFFFFFFFFFFFFFF
    stream.write(struct.pack(">QQ", high, low))


def write_i128_to_stream(stream, value):
    high = value >> 64
    low = value & 0xFFFFFFFFFFFFFFFF
    stream.write(struct.pack(">qQ", high, low))


def write_vector_u8_to_stream(stream, data):
    write_u32_to_stream(stream, len(data))
    stream.write(data)


def write_string_to_stream(stream, string):
    data = string.encode("utf8")
    write_u8_to_stream(stream, len(data))
    stream.write(data)


def serialize(value):
    def wrapper(cls):
        cls._pystacks_byte_type = value
        cls.to_stream = lambda self, stream: write_u8_to_stream(
            stream, self._pystacks_byte_type
        )
        cls.__index__ = lambda self: value
        return cls

    return wrapper


def sha256(data):
    return hashlib.new("sha256", data).digest()


def hash160(data):
    return hashlib.new("ripemd160", sha256(data)).digest()


def sha512_256(data):
    return hashlib.new(
        "sha512_256",
        data,
    ).digest()


def stx_mainnet_address_from_private_key(private_key):
    return c32_address(
        C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
        hash160(get_public_key(private_key, compressed=True)),
    )


def stx_testnet_address_from_private_key(private_key):
    return c32_address(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        hash160(get_public_key(private_key, compressed=True)),
    )


def stx_address_to_principal_data(stx_address):
    if "." in stx_address:
        return {"Contract": []}
    else:
        stx_address_bytes = stx_address.encode("ascii")
        version, data = stx_address_bytes[1], stx_address_bytes[2:]
        return {
            "Standard": [
                C32_CHARACTERS.index(version),
                list(c32_decode(data)[:-4]),
            ]
        }


class ByteType:
    @classmethod
    def from_stream(cls, stream):
        _type = stream.read(1)[0]

        def traverse(_cls):
            if not isinstance(_cls, type):
                return None
            if hasattr(_cls, "_pystacks_byte_type"):
                if _cls._pystacks_byte_type == _type:
                    return _cls
            for child in _cls.__dict__.values():
                found_class = traverse(child)
                if found_class:
                    return found_class

        found_class = traverse(cls)
        if not found_class:
            raise Exception("Unsupported {}: {}".format(cls, _type))
        return found_class()

    @classmethod
    def peek_from_stream(cls, stream):
        current_pos = stream.tell()
        value = cls.from_stream(stream)
        stream.seek(current_pos)
        # ensure to call to_stream on the actual value
        value.to_stream(stream)
        stream.seek(current_pos)
        return value


class RaiseOnUnsupported:
    class Unsupported(Exception):
        def __init__(self, subject, value):
            super().__init__(
                "Unsupported {}: {}".format(
                    (
                        subject.__class__.__qualname__
                        if not isinstance(subject, type)
                        else subject.__qualname__
                    ),
                    value,
                )
            )
