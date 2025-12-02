# pystacks

Stacks blockchain python module

```py
from pystacks.transaction import (
    Transaction,
    TransactionAnchorMode,
    TransactionAuth,
    TransactionSpendingCondition,
    HashMode,
    ClarityVersion,
    TransactionPublicKeyEncoding,
    TransactionPostConditionMode,
    TransactionPayload,
    TransactionSmartContract,
)

from pystacks.utils import generate_key
from pystacks.api import block_simulate
from pprint import pprint

private_key, public_key = generate_key()

tx = Transaction()
tx.version = 0x80
tx.chain_id = 0x80000000
tx.anchor_mode = TransactionAnchorMode.Any()
tx.auth = TransactionAuth.Standard()
tx.auth.origin = TransactionSpendingCondition.Singlesig()
tx.auth.origin.hash_mode = HashMode.Singlesig.P2PKH()
tx.auth.origin.key_encoding = TransactionPublicKeyEncoding.Compressed()
tx.auth.origin.nonce = 0
tx.auth.origin.tx_fee = 100
tx.post_condition_mode = TransactionPostConditionMode.Allow()
tx.payload = TransactionPayload.VersionedSmartContract(
    ClarityVersion.Clarity2(),
    TransactionSmartContract(
        "hello_world",
        b'(print 17)(print 30)(define-public (dummy) (begin (print "ciao") (ok true) ) ) (dummy)',
    ),
)

tx.sign(private_key)

pprint(
    block_simulate(
        "ffc3e13aa7102289a48db62da6558709d9b8c1452d6d4fc7fe4f3ce53a7e6cc5",
        "hello",
        [tx.to_hex()],
    )
)
```
