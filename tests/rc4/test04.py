#!/usr/bin/env python3
#
# Helper of test04.lua: runs RC4 jobs with the Python package "cryptography" (ARC4) or
# "pycryptodome" (Crypto.Cipher.ARC4). Usage:
#
#   python3 test04.py <backend> <jobfile>      backend: cryptography | pycryptodome
#
# Each line of the job file is one job: "key drop data" (key and data in hex, "-" for
# empty data, drop: the number of keystream bytes to discard). For each job one line with
# the output in hex ("-" if empty) is written to stdout, "SKIP" if the backend does not
# support the key length, "ERR" if the backend raised an error; if the backend is not
# installed, the only line is "UNAVAILABLE".

import sys


def unhex(s):
    return b"" if s == "-" else bytes.fromhex(s)


def backend_cryptography():
    try:
        from cryptography.hazmat.decrepit.ciphers.algorithms import ARC4
    except ImportError:
        from cryptography.hazmat.primitives.ciphers.algorithms import ARC4
    from cryptography.hazmat.primitives.ciphers import Cipher

    def run(key, drop, data):
        if len(key) * 8 not in ARC4.key_sizes:
            return None
        c = Cipher(ARC4(key), mode=None).encryptor()
        c.update(bytes(drop))
        return c.update(data) + c.finalize()

    return run


def backend_pycryptodome():
    try:
        from Crypto.Cipher import ARC4
    except ImportError:
        from Cryptodome.Cipher import ARC4

    def run(key, drop, data):
        if len(key) < ARC4.key_size[0]:
            return None
        return ARC4.new(key, drop=drop).encrypt(data)

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
            key, drop, data = fields
            try:
                r = run(unhex(key), int(drop), unhex(data))
                out.append("SKIP" if r is None else r.hex() if r else "-")
            except Exception:
                out.append("ERR")
    sys.stdout.write("\n".join(out) + "\n")


main()
