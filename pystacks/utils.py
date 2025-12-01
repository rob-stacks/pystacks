from coincurve import PublicKey, PrivateKey
from coincurve.ecdsa import deserialize_recoverable, recoverable_convert, cdata_to_der
from coincurve.utils import verify_signature
import struct
import hashlib


def generate_key(compressed=False):
    pk = PrivateKey()
    return pk.secret, pk.public_key.format(compressed=compressed)


def compressed_pubkey(pubkey):
    return PublicKey(pubkey).format(compressed=True)


def recover_pubkey_from_signature(signature, message, compressed=False):
    r_s = signature[1:]
    v = signature[:1]
    pub = PublicKey.from_signature_and_message(r_s + v, message, hasher=None)
    return pub.format(compressed=compressed)


def get_public_key(privkey, compressed=False):
    return PrivateKey(privkey).public_key.format(compressed=compressed)


def verify(pubkey, signature, message):
    signature_der = cdata_to_der(
        recoverable_convert(deserialize_recoverable(signature[1:] + signature[:1]))
    )
    return verify_signature(
        signature_der,
        message,
        pubkey,
        hasher=None,
    )


def sign(privkey, message):
    pk = PrivateKey(privkey)
    signature = pk.sign_recoverable(message, hasher=None)
    return signature[64:] + signature[:64]


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


def read_vector_u8_from_stream(stream):
    vector_len = read_u32_from_stream(stream)
    return stream.read(vector_len)


def read_u8_from_stream(stream):
    return stream.read(1)[0]


def read_u32_from_stream(stream):
    return struct.unpack(">I", stream.read(4))[0]


def read_u64_from_stream(stream):
    return struct.unpack(">Q", stream.read(8))[0]


def write_u8_to_stream(stream, value):
    stream.write(struct.pack("B", value))


def write_u32_to_stream(stream, value):
    stream.write(struct.pack(">I", value))


def write_u64_to_stream(stream, value):
    stream.write(struct.pack(">Q", value))


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
            raise Exception("Unsupported {}".format(cls))
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
