#!/usr/bin/env python3
"""Cross-check vanity-gpu's CPU reference (`vanity-gpu derive`) against an
independent implementation: the `cryptography` package for the curves, plus a
pure-Python Keccak-256, base58 and TON cell hashing written here.

usage: python3 -I tests/crosscheck.py build/vanity-gpu [N]
"""
import base64
import binascii
import hashlib
import os
import subprocess
import sys

from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives import serialization

RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
      0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
      0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
      0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
      0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
      0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
       [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
M64 = (1 << 64) - 1


def rol(x, n):
    return ((x << n) | (x >> (64 - n))) & M64 if n else x


def keccak_f(A):
    for rc in RC:
        C = [A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4] for x in range(5)]
        D = [C[(x - 1) % 5] ^ rol(C[(x + 1) % 5], 1) for x in range(5)]
        A = [[A[x][y] ^ D[x] for y in range(5)] for x in range(5)]
        B = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                B[y][(2 * x + 3 * y) % 5] = rol(A[x][y], ROT[x][y])
        A = [[B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
        A[0][0] ^= rc
    return A


def keccak256(data):
    rate = 136
    data = bytearray(data) + b"\x01"
    data += b"\x00" * (-len(data) % rate)
    data[-1] |= 0x80
    A = [[0] * 5 for _ in range(5)]
    for off in range(0, len(data), rate):
        for i in range(rate // 8):
            A[i % 5][i // 5] ^= int.from_bytes(data[off + 8 * i:off + 8 * i + 8], "little")
        A = keccak_f(A)
    return b"".join(A[i % 5][i // 5].to_bytes(8, "little") for i in range(4))


ALPH = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58(b):
    n = int.from_bytes(b, "big")
    s = ""
    while n:
        n, r = divmod(n, 58)
        s = ALPH[r] + s
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + s


def eip55(addr):
    h = keccak256(addr.encode()).hex()
    return "0x" + "".join(c.upper() if c.isalpha() and int(h[i], 16) >= 8 else c for i, c in enumerate(addr))


TON_W5_CODE = bytes.fromhex("20834b7b72b112147e1b2fb457b84e74d1a30f04f737d4f62a668e9552d2b72f")


def cell_hash(bits, refs=()):
    """Representation hash of an ordinary level-0 cell; refs = [(hash, depth)]."""
    n = len(bits)
    padded = bits + ("1" + "0" * ((7 - n % 8) % 8) if n % 8 else "")
    data = int(padded, 2).to_bytes(len(padded) // 8, "big") if padded else b""
    rep = bytes([len(refs), n // 8 + (n + 7) // 8]) + data
    rep += b"".join(d.to_bytes(2, "big") for _, d in refs) + b"".join(h for h, _ in refs)
    return hashlib.sha256(rep).digest()


def ton_w5_address(pub, wallet_id=2147483409):
    bits = "1" + "0" * 32 + format(wallet_id, "032b") + "".join(format(x, "08b") for x in pub) + "0"
    acct = cell_hash("00110", [(TON_W5_CODE, 6), (cell_hash(bits), 0)])
    raw = b"\x51\x00" + acct
    raw += binascii.crc_hqx(raw, 0).to_bytes(2, "big")
    return base64.urlsafe_b64encode(raw).decode()


BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def bech32_p2wpkh(prog):
    """BIP-173 encoding of a version-0 witness program with hrp 'bc'."""
    def polymod(values):
        gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
        chk = 1
        for v in values:
            b = chk >> 25
            chk = (chk & 0x1FFFFFF) << 5 ^ v
            for i in range(5):
                chk ^= gen[i] if (b >> i) & 1 else 0
        return chk
    bits = "".join(format(x, "08b") for x in prog)
    data = [0] + [int(bits[i:i + 5].ljust(5, "0"), 2) for i in range(0, len(bits), 5)]
    hrp = [ord(c) >> 5 for c in "bc"] + [0] + [ord(c) & 31 for c in "bc"]
    pm = polymod(hrp + data + [0] * 6) ^ 1
    return "bc1" + "".join(BECH32[d] for d in data + [(pm >> 5 * (5 - i)) & 31 for i in range(6)])


def b58check(payload):
    return b58(payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4])


def hash160(b):
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()


def derive(binary, chain, key):
    out = subprocess.run([binary, "derive", chain, key], capture_output=True, text=True, check=True)
    return out.stdout.split()


def main():
    binary = sys.argv[1]
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 20
    assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    bad = 0
    for _ in range(n):
        k = int.from_bytes(os.urandom(32), "big") % (2**256 - 2**129) + 1
        priv = ec.derive_private_key(k, ec.SECP256K1())
        pub = priv.public_key().public_bytes(serialization.Encoding.X962,
                                             serialization.PublicFormat.UncompressedPoint)[1:]
        a20 = keccak256(pub)[12:]
        want_evm = eip55(a20.hex())
        payload = b"\x41" + a20
        want_tron = b58(payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4])
        got_evm, got_pub = derive(binary, "evm", "%064x" % k)
        got_tron, _ = derive(binary, "tron", "%064x" % k)
        if (got_evm, got_pub, got_tron) != (want_evm, pub.hex(), want_tron):
            bad += 1
            print("secp256k1 MISMATCH for key", "%064x" % k)

        comp = priv.public_key().public_bytes(serialization.Encoding.X962,
                                              serialization.PublicFormat.CompressedPoint)
        h = hash160(comp)
        want_btc = {"btc": bech32_p2wpkh(h), "btc-legacy": b58check(b"\x00" + h),
                    "btc-p2sh": b58check(b"\x05" + hash160(b"\x00\x14" + h))}
        want_wif = b58check(b"\x80" + k.to_bytes(32, "big") + b"\x01")
        for chain, want in want_btc.items():
            got_addr, _, got_wif = derive(binary, chain, "%064x" % k)
            if (got_addr, got_wif) != (want, want_wif):
                bad += 1
                print("bitcoin MISMATCH (%s) for key %064x" % (chain, k))

        seed = os.urandom(32)
        spub = ed25519.Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        got_sol, got_spub = derive(binary, "sol", seed.hex())
        got_ton, _ = derive(binary, "ton", seed.hex())
        if (got_sol, got_spub, got_ton) != (b58(spub), spub.hex(), ton_w5_address(spub)):
            bad += 1
            print("ed25519 MISMATCH for seed", seed.hex())
    # a live mainnet W5 wallet (public key from its on-chain data cell)
    real = ton_w5_address(bytes.fromhex("3b26e906af38b3aa45aacbecc4bee94169aa9becc9d8aeb94e9b97519d2088b0"))
    if real != "UQA-OSGVswlJOJzD6ijqpDtNS5J8VnNtnx4QOzWomN0vNoT1":
        bad += 1
        print("TON reference implementation does not reproduce the mainnet wallet")
    print(f"{n} secp256k1 keys (EVM + TRON + 3 Bitcoin types) and {n} ed25519 seeds (SOL + TON) checked, "
          f"{bad} mismatches")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
