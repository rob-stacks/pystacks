import struct
import hashlib
from coincurve import PublicKey


class NakamotoBlock:

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
        self.signer_signature = []
        self.pox_treatment_bit_vec_size = None
        self.pox_treatment = None

    @staticmethod
    def from_blob(blob):
        block = NakamotoBlock()
        offset = 0
        block.version, block.height, block.burn_spent = struct.unpack(
            ">BQQ", blob[offset : offset + 1 + 8 + 8]
        )
        offset += 1 + 8 + 8
        block.consensus_hash = blob[offset : offset + 20]
        offset += 20
        block.parent_block_id = blob[offset : offset + 32]
        offset += 32
        block.tx_merkle_root = blob[offset : offset + 32]
        offset += 32
        block.state_index_root = blob[offset : offset + 32]
        offset += 32
        block.timestamp = struct.unpack(">Q", blob[offset : offset + 8])[0]
        offset += 8
        block.miner_signature = blob[offset : offset + 65]
        offset += 65
        number_of_signer_signature = struct.unpack(">I", blob[offset : offset + 4])[0]
        offset += 4
        for _ in range(0, number_of_signer_signature):
            block.signer_signature.append(blob[offset : offset + 65])
            offset += 65
        block.pox_treatment_bit_vec_size = struct.unpack(
            ">H", blob[offset : offset + 2]
        )[0]
        offset += 2
        pox_treatment_bit_vec_size_in_bytes = struct.unpack(
            ">I", blob[offset : offset + 4]
        )[0]
        offset += 4
        block.pox_treatment = blob[
            offset : offset + pox_treatment_bit_vec_size_in_bytes
        ]
        return block

    def block_hash(self):
        data = (
            struct.pack(">BQQ", self.version, self.height, self.burn_spent)
            + self.consensus_hash
            + self.parent_block_id
            + self.tx_merkle_root
            + self.state_index_root
            + struct.pack(">Q", self.timestamp)
            + self.miner_signature
            + struct.pack(
                ">HI", self.pox_treatment_bit_vec_size, len(self.pox_treatment)
            )
            + self.pox_treatment
        )
        return hashlib.new("sha512_256", data).digest()

    def block_id(self):
        return hashlib.new(
            "sha512_256", self.block_hash() + self.consensus_hash
        ).digest()
