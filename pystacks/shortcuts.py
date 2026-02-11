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


def contract_deploy_on_mainnet_with_p2pkh(
    private_key,
    nonce,
    fee,
    contract_name,
    contract_code,
    clarity_version=ClarityVersion.Clarity4,
):
    tx = Transaction()
    tx.version = 0x00
    tx.chain_id = 1
    tx.anchor_mode = TransactionAnchorMode.Any()
    tx.auth = TransactionAuth.Standard()
    tx.auth.origin = TransactionSpendingCondition.Singlesig()
    tx.auth.origin.hash_mode = HashMode.Singlesig.P2PKH()
    tx.auth.origin.key_encoding = TransactionPublicKeyEncoding.Compressed()
    tx.auth.origin.nonce = nonce
    tx.auth.origin.tx_fee = fee
    tx.post_condition_mode = TransactionPostConditionMode.Allow()
    tx.payload = TransactionPayload.VersionedSmartContract(
        clarity_version(),
        TransactionSmartContract(
            contract_name,
            contract_code.encode("utf8"),
        ),
    )

    tx.sign(private_key)

    return tx
