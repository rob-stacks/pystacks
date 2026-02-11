from ecdsa import SigningKey, VerifyingKey, SECP256k1
from ecdsa.util import sigencode_string, sigdecode_string
from ecdsa.keys import MalformedPointError


def generate_private_key():
    return SigningKey.generate(curve=SECP256k1).to_string()


def get_compressed_public_key(public_key):
    return VerifyingKey.from_string(public_key, curve=SECP256k1).to_string(
        encoding="compressed"
    )


def get_uncompressed_public_key(public_key):
    return VerifyingKey.from_string(public_key, curve=SECP256k1).to_string(
        encoding="uncompressed"
    )


def recover_public_key_from_signature(signature, message, compressed=False):
    r_s = signature[1:]
    v = signature[0]
    return VerifyingKey.from_public_key_recovery_with_digest(
        r_s, message, SECP256k1, sigdecode=sigdecode_string
    )[v].to_string(encoding="compressed" if compressed else "uncompressed")


def get_public_key(private_key, compressed=False):
    return SigningKey.from_string(private_key, curve=SECP256k1).verifying_key.to_string(
        encoding="compressed" if compressed else "uncompressed"
    )


def sign(private_key, message):
    pk = SigningKey.from_string(private_key, curve=SECP256k1)
    public_key_bytes = pk.verifying_key.to_string()
    signature = pk.sign_digest(message, sigencode=sigencode_string)
    recovered_keys = VerifyingKey.from_public_key_recovery_with_digest(
        signature, message, SECP256k1, sigdecode=sigdecode_string
    )
    v = None
    for i, recovered_vk in enumerate(recovered_keys):
        try:
            if recovered_vk.to_string() == public_key_bytes:
                v = i
                break
        except MalformedPointError:
            continue
    return bytes((v,)) + signature
