#!/usr/bin/env python3
#
# Helper of test04.lua: runs DES and Triple DES jobs with the Python package
# "cryptography" (TripleDES) or "pycryptodome" (DES, DES3; Crypto or Cryptodome). Usage:
#
#   python3 test04.py <backend> <jobfile>      backend: cryptography | pycryptodome
#
# Each line of the job file is one job, fields separated by spaces, "-" for empty values,
# binary values in hex:
#
#   op mode key iv padding data
#
#   op       enc | dec
#   mode     ecb | cbc | cfb | cfb8 | ofb | ctr
#   key      8 bytes (DES), 16 or 24 bytes (Triple DES)
#   padding  pkcs7 | none
#
# For each job one line is written to stdout: the output in hex ("-" if empty), "ERR" if
# the backend raised an error or "SKIP" if the backend does not support the job. If the
# backend is not installed, the only line is "UNAVAILABLE".

import sys
import warnings


def unhex(s):
    return b"" if s == "-" else bytes.fromhex(s)


def tohex(b):
    return b.hex() if b else "-"


SKIP = object()


def backend_cryptography():
    from cryptography.hazmat.primitives.ciphers import Cipher, modes
    from cryptography.hazmat.primitives import padding as cpadding
    try:
        from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
    except ImportError:
        from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
    try:
        from cryptography.hazmat.decrepit.ciphers import modes as dmodes
    except ImportError:
        dmodes = modes
    legacy = dmodes if hasattr(dmodes, "CFB") else modes
    # single DES keys (TripleDES with an 8 byte key) are deprecated, but still supported
    warnings.simplefilter("ignore")

    def mode_of(mode, iv):
        return {"ecb": lambda: modes.ECB(), "cbc": lambda: modes.CBC(iv), "cfb": lambda: legacy.CFB(iv),
                "cfb8": lambda: legacy.CFB8(iv), "ofb": lambda: legacy.OFB(iv)}[mode]()

    def run(op, mode, key, iv, pad, data):
        if mode == "ctr":
            return SKIP   # not supported for TripleDES
        c = Cipher(TripleDES(key), mode_of(mode, iv))
        if op == "enc":
            if pad == "pkcs7":
                p = cpadding.PKCS7(64).padder()
                data = p.update(data) + p.finalize()
            e = c.encryptor()
            return e.update(data) + e.finalize()
        d = c.decryptor()
        out = d.update(data) + d.finalize()
        if pad == "pkcs7":
            u = cpadding.PKCS7(64).unpadder()
            out = u.update(out) + u.finalize()
        return out

    return run


def backend_pycryptodome():
    try:
        from Crypto.Cipher import DES, DES3
        from Crypto.Util.Padding import pad as cpad, unpad as cunpad
    except ImportError:
        from Cryptodome.Cipher import DES, DES3
        from Cryptodome.Util.Padding import pad as cpad, unpad as cunpad

    def cipher(mode, key, iv):
        M = DES if len(key) == 8 else DES3
        if mode == "ecb":
            return M.new(key, M.MODE_ECB)
        if mode == "cbc":
            return M.new(key, M.MODE_CBC, iv=iv)
        if mode == "cfb":
            return M.new(key, M.MODE_CFB, iv=iv, segment_size=64)
        if mode == "cfb8":
            return M.new(key, M.MODE_CFB, iv=iv, segment_size=8)
        if mode == "ofb":
            return M.new(key, M.MODE_OFB, iv=iv)
        if mode == "ctr":
            # the whole block as counter
            return M.new(key, M.MODE_CTR, nonce=b"", initial_value=iv)
        raise ValueError(mode)

    def run(op, mode, key, iv, pad, data):
        c = cipher(mode, key, iv)
        if op == "enc":
            if pad == "pkcs7":
                data = cpad(data, 8)
            return c.encrypt(data)
        out = c.decrypt(data)
        if pad == "pkcs7":
            out = cunpad(out, 8)
        return out

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
            op, mode, key, iv, pad, data = fields
            try:
                r = run(op, mode, unhex(key), unhex(iv), pad, unhex(data))
                out.append("SKIP" if r is SKIP else tohex(r))
            except Exception:
                out.append("ERR")
    sys.stdout.write("\n".join(out) + "\n")


main()
