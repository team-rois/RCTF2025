import os
import secrets
from Crypto.Cipher import AES


class SuanHash:
    state_bits = 128
    rate_bits = 64
    cap_bits = state_bits - rate_bits
    digest_size = state_bits // 8
    block_size = state_bits // 8
    _rate_mask = (1 << rate_bits) - 1
    _cap_mask = (1 << cap_bits) - 1

    def __init__(self, data: bytes = b""):
        self._perm_seed = os.urandom(16)
        self._cipher = AES.new(self._perm_seed, AES.MODE_ECB)
        self._cfg_hi = secrets.randbits(self.rate_bits)
        self._cfg_lo = secrets.randbits(self.cap_bits)
        self._buf = bytearray()
        self._done = False
        self._value = None
        if data:
            self.update(data)

    def _permute(self, x: int) -> int:
        return int.from_bytes(self._cipher.encrypt(x.to_bytes(16, "big")), "big")

    def _pad_to_blocks(self, msg: bytes) -> list[int]:
        n = self.block_size
        if not msg:
            data = b"\x80" + b"\x00" * (n - 1)
        else:
            data = msg + b"\x80"
            data += b"\x00" * (-len(data) % n)
        return [int.from_bytes(data[i : i + n], "big") for i in range(0, len(data), n)]

    def _core(self, blocks: list[int], out_bits: int | None = None) -> int:
        if out_bits is None:
            out_bits = self.state_bits
        b, r, c = self.state_bits, self.rate_bits, self.cap_bits
        rm, cm = self._rate_mask, self._cap_mask
        s0 = self._permute(((self._cfg_hi & rm) << c) | (self._cfg_lo & cm))
        upper, lower, last_low = s0 >> c, s0 & cm, 0
        for blk in blocks:
            mixed = ((upper << c) | lower) ^ blk
            s = self._permute(mixed)
            upper, lower = s >> c, s & cm
            last_low = mixed & cm
        need = (out_bits + b - 1) // b
        acc_hi = acc_lo = used_hi = used_lo = 0
        cur_hi, cur_lo, cur_w = upper, lower, last_low
        for i in range(need):
            acc_hi = (acc_hi << r) | (cur_hi & rm)
            used_hi += r
            acc_lo = (acc_lo << c) | ((cur_w ^ cur_lo) & cm)
            used_lo += c
            if i < need - 1:
                nxt_in = ((cur_hi & rm) << c) | (cur_lo & cm)
                nxt = self._permute(nxt_in)
                cur_hi, cur_lo, cur_w = nxt >> c, nxt & cm, nxt_in & cm
        full = (acc_hi << used_lo) | acc_lo
        return (full >> (used_hi + used_lo - out_bits)) & ((1 << out_bits) - 1)

    def update(self, data: bytes):
        if self._done:
            raise ValueError("hash object already finalized")
        self._buf.extend(data)
        return self

    def _compute(self) -> int:
        return self._core(self._pad_to_blocks(bytes(self._buf)), self.state_bits)

    def digest(self) -> bytes:
        if not self._done:
            self._value = self._compute()
            self._done = True
        return self._value.to_bytes(self.digest_size, "big")

    def hexdigest(self) -> str:
        return self.digest().hex()

    def copy(self):
        other = self.__class__.__new__(self.__class__)
        other._perm_seed = self._perm_seed
        other._cipher = AES.new(self._perm_seed, AES.MODE_ECB)
        other._cfg_hi = self._cfg_hi
        other._cfg_lo = self._cfg_lo
        other._buf = bytearray(self._buf)
        other._done = False  # reset finalized flag
        other._value = None  # clear cached digest
        return other

    @classmethod
    def new(cls, data: bytes = b""):
        h = cls()
        if data:
            h.update(data)
        return h
