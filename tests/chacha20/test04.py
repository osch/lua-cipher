#!/usr/bin/env python3
#
# Helper of test04.lua: runs ChaCha20, ChaCha20-Poly1305 and Poly1305 jobs with the Python
# package "cryptography" or "pycryptodome" (Crypto or Cryptodome). Usage:
#
#   python3 test04.py <backend> <jobfile>      backend: cryptography | pycryptodome
#
# Each line of the job file is one job, fields separated by spaces, "-" for empty values,
# binary values in hex:
#
#   op key iv counter aad tag data
#
#   op       crypt (ChaCha20) | enc | dec (ChaCha20-Poly1305) | poly (Poly1305)
#   counter  crypt: the initial block counter (decimal)
#   tag      dec: the expected tag
#
# For each job one line is written to stdout: "<output> <tag>" (hex, "-" if empty; enc:
# the ciphertext and the tag, crypt and dec: the output and "-", poly: the tag and "-"),
# "ERR" if the backend raised an error (e.g. authentication failed) or "SKIP" if the
# backend does not support the job. If the backend is not installed, the only line is
# "UNAVAILABLE".

import sys


def unhex(s):
    return b"" if s == "-" else bytes.fromhex(s)


def tohex(b):
    return b.hex() if b else "-"


SKIP = object()


def backend_cryptography():
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.poly1305 import Poly1305

    def run(op, key, iv, counter, aad, tag, data):
        if op == "crypt":
            # the 16 byte nonce of OpenSSL: the counter and the nonce (with an 8 byte nonce
            # a 64 bit counter, as OpenSSL carries into the second word)
            if len(iv) == 12:
                nonce = counter.to_bytes(4, "little") + iv
            elif len(iv) == 8:
                nonce = counter.to_bytes(8, "little") + iv
            else:
                return SKIP
            # (some builds of cryptography refuse a block counter that passes 2^32,
            # which the 64 bit counter of the 8 byte nonce variant allows: a backend
            # limit, skipped; every other failure still counts as a difference)
            wraps = len(iv) == 8 and counter + (len(data) + 63) // 64 > 2 ** 32
            try:
                c = Cipher(algorithms.ChaCha20(key, nonce), mode=None).encryptor()
                return c.update(data) + c.finalize(), b""
            except Exception:
                if wraps:
                    return SKIP
                raise
        if op == "poly":
            return Poly1305.generate_tag(key, data), b""
        if len(iv) != 12:
            return SKIP
        a = ChaCha20Poly1305(key)
        if op == "enc":
            r = a.encrypt(iv, data, aad or None)
            return r[:-16], r[-16:]
        return a.decrypt(iv, data + tag, aad or None), b""

    return run


def backend_pycryptodome():
    try:
        from Crypto.Cipher import ChaCha20, ChaCha20_Poly1305
    except ImportError:
        from Cryptodome.Cipher import ChaCha20, ChaCha20_Poly1305

    def run(op, key, iv, counter, aad, tag, data):
        if op == "crypt":
            c = ChaCha20.new(key=key, nonce=iv)
            if counter:
                c.seek(64 * counter)
            return c.encrypt(data), b""
        if op == "poly":
            # Crypto.Hash.Poly1305 derives the key with a cipher, no raw key
            return SKIP
        c = ChaCha20_Poly1305.new(key=key, nonce=iv)
        c.update(aad)
        if op == "enc":
            return c.encrypt_and_digest(data)
        return c.decrypt_and_verify(data, tag), b""

    return run


def main():
    name, jobfile = sys.argv[1], sys.argv[2]
    try:
        run = {"cryptography": backend_cryptography, "pycryptodome": backend_pycryptodome}[name]()
    except ImportError:
        print("UNAVAILABLE")
        return
    out = []
    with open(jobfile) as f:
        for line in f:
            fields = line.split()
            if not fields:
                continue
            op, key, iv, counter, aad, tag, data = fields
            try:
                r = run(op, unhex(key), unhex(iv), int(counter), unhex(aad), unhex(tag), unhex(data))
                if r is SKIP:
                    out.append("SKIP")
                else:
                    out.append(tohex(r[0]) + " " + tohex(r[1]))
            except Exception:
                out.append("ERR")
    sys.stdout.write("\n".join(out) + "\n")


main()
