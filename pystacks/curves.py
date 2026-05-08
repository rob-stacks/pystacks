try:
    from .curves_backends.coincurve_backend import (
        generate_private_key,
        recover_public_key_from_signature,
        get_compressed_public_key,
        get_uncompressed_public_key,
        get_public_key,
        sign,
    )
except ImportError:
    from .curves_backends.ecdsa_backend import (
        generate_private_key,
        recover_public_key_from_signature,
        get_compressed_public_key,
        get_uncompressed_public_key,
        get_public_key,
        sign,
    )


def generate_private_and_public_keys(compressed=False):
    pk = generate_private_key()
    return pk, get_public_key(pk, compressed)


def is_public_key_compressed(public_key):
    public_key_len = len(public_key)
    if public_key_len == 33:
        return True
    elif public_key_len == 65:
        return False
    raise Exception("Invalid public key")


def verify(public_key, signature, message):
    recovered_public_key = recover_public_key_from_signature(signature, message)
    if is_public_key_compressed(public_key):
        public_key = get_uncompressed_public_key(public_key)
    return recovered_public_key == public_key
