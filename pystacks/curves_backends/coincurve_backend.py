from coincurve import PublicKey, PrivateKey
from coincurve.ecdsa import deserialize_recoverable, recoverable_convert, cdata_to_der
from coincurve.utils import verify_signature


def generate_private_key():
    pk = PrivateKey()
    return pk.secret


def get_compressed_public_key(public_key):
    return PublicKey(public_key).format(compressed=True)


def get_uncompressed_public_key(public_key):
    return PublicKey(public_key).format(compressed=False)


def recover_public_key_from_signature(signature, message, compressed=False):
    r_s = signature[1:]
    v = signature[:1]
    pub = PublicKey.from_signature_and_message(r_s + v, message, hasher=None)
    return pub.format(compressed=compressed)


def get_public_key(private_key, compressed=False):
    return PrivateKey(private_key).public_key.format(compressed=compressed)


def sign(private_key, message):
    pk = PrivateKey(private_key)
    signature = pk.sign_recoverable(message, hasher=None)
    return signature[64:] + signature[:64]
