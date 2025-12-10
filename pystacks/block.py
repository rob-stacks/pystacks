import struct
from .utils import (
    sha512_256,
    read_u8_from_stream,
    read_u64_from_stream,
    read_u32_from_stream,
    read_u16_from_stream,
    read_vector_class_from_stream,
)
from .transaction import Transaction
from io import BytesIO
from typing import List


class NakamotoBlockHeader:
    def __init__(self):
        self.version = None
        self.height = None
        self.burn_spent = None
        self.consensus_hash = None
        self.parent_block_id = None
        self.tx_merkle_root = None
        self.state_index_root = None
        self.timestamp = None
        self.miner_signature = None
        self.signer_signature = None
        self.pox_treatment_bit_vec_size = None
        self.pox_treatment = None

    @staticmethod
    def from_stream(stream):
        header = NakamotoBlockHeader()
        header.version = read_u8_from_stream(stream)
        header.height = read_u64_from_stream(stream)
        header.burn_spent = read_u64_from_stream(stream)
        header.consensus_hash = stream.read(20)
        header.parent_block_id = stream.read(32)
        header.tx_merkle_root = stream.read(32)
        header.state_index_root = stream.read(32)
        header.timestamp = read_u64_from_stream(stream)
        header.miner_signature = stream.read(65)
        header.signer_signature = []
        for _ in range(0, read_u32_from_stream(stream)):
            header.signer_signature.append(stream.read(65))
        header.pox_treatment_bit_vec_size = read_u16_from_stream(stream)
        header.pox_treatment = stream.read(read_u32_from_stream(stream))
        return header


class NakamotoBlock:

    def __init__(self, header=None, transactions=None):
        self.header: NakamotoBlockHeader = header
        self.transactions: List[Transaction] = transactions

    @staticmethod
    def from_stream(stream):
        block = NakamotoBlock()
        block.header = NakamotoBlockHeader.from_stream(stream)
        block.transactions = read_vector_class_from_stream(stream, Transaction)
        return block

    @staticmethod
    def from_hex(hex_string):
        return NakamotoBlock.from_stream(BytesIO(bytes.fromhex(hex_string)))

    def block_hash(self):
        data = (
            struct.pack(
                ">BQQ", self.header.version, self.header.height, self.header.burn_spent
            )
            + self.header.consensus_hash
            + self.header.parent_block_id
            + self.header.tx_merkle_root
            + self.header.state_index_root
            + struct.pack(">Q", self.header.timestamp)
            + self.header.miner_signature
            + struct.pack(
                ">HI",
                self.header.pox_treatment_bit_vec_size,
                len(self.header.pox_treatment),
            )
            + self.header.pox_treatment
        )
        return sha512_256(data)

    def block_id(self):
        return sha512_256(self.block_hash() + self.header.consensus_hash)
