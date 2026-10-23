#!/usr/bin/env python3
#
# Helper of test04.lua: runs AES jobs with the Python package "cryptography" or
# "pycryptodome" (Crypto or Cryptodome). Usage:
#
#   python3 test04.py <backend> <jobfile>      backend: cryptography | pycryptodome
#
# Each line of the job file is one job, fields separated by spaces, "-" for empty values,
# binary values in hex:
#
#   op mode key iv padding aad tag data
#
#   op       enc | dec
#   mode     ecb | cbc | cfb | cfb8 | ofb | ctr | gcm
#   padding  pkcs7 | none
#   tag      enc: the tag length (gcm), dec: the expected tag (gcm)
#
# For each job one line is written to stdout: "<output> <tag>" (hex, "-" if empty), "ERR"
# if the backend raised an error (e.g. invalid padding, authentication failed) or "SKIP"
# if the backend does not support the job. If the backend is not installed, the only
# line is "UNAVAILABLE".

import sys


def unhex(s):
    return b"" if s == "-" else bytes.fromhex(s)


def tohex(b):
    return b.hex() if b else "-"


def backend_cryptography():
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding as cpadding
    try:
        # newer versions: the legacy modes in the "decrepit" package
        from cryptography.hazmat.decrepit.ciphers import modes as dmodes
    except ImportError:
        dmodes = modes
    legacy = dmodes if hasattr(dmodes, "CFB") else modes

    def mode_of(mode, iv, tag):
        if mode == "ecb":
            return modes.ECB()
        if mode == "cbc":
            return modes.CBC(iv)
        if mode == "cfb":
            return legacy.CFB(iv)
        if mode == "cfb8":
            return legacy.CFB8(iv)
        if mode == "ofb":
            return legacy.OFB(iv)
        if mode == "ctr":
            return modes.CTR(iv)
        if mode == "gcm":
            if tag is None:
                return modes.GCM(iv)
            return modes.GCM(iv, tag, min_tag_length=len(tag))
        raise ValueError(mode)

    def run(op, mode, key, iv, pad, aad, tag, data):
        if op == "enc":
            if pad == "pkcs7":
                p = cpadding.PKCS7(128).padder()
                data = p.update(data) + p.finalize()
            c = Cipher(algorithms.AES(key), mode_of(mode, iv, None)).encryptor()
            if mode == "gcm" and aad:
                c.authenticate_additional_data(aad)
            out = c.update(data) + c.finalize()
            t = c.tag[:int(tag)] if mode == "gcm" else b""
            return out, t
        c = Cipher(algorithms.AES(key), mode_of(mode, iv, tag if mode == "gcm" else None)).decryptor()
        if mode == "gcm" and aad:
            c.authenticate_additional_data(aad)
        out = c.update(data) + c.finalize()
        if pad == "pkcs7":
            u = cpadding.PKCS7(128).unpadder()
            out = u.update(out) + u.finalize()
        return out, b""

    return run


def backend_pycryptodome():
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad as cpad, unpad as cunpad
    except ImportError:
        from Cryptodome.Cipher import AES
        from Cryptodome.Util.Padding import pad as cpad, unpad as cunpad

    def cipher(mode, key, iv, taglen):
        if mode == "ecb":
            return AES.new(key, AES.MODE_ECB)
        if mode == "cbc":
            return AES.new(key, AES.MODE_CBC, iv=iv)
        if mode == "cfb":
            return AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128)
        if mode == "cfb8":
            return AES.new(key, AES.MODE_CFB, iv=iv, segment_size=8)
        if mode == "ofb":
            return AES.new(key, AES.MODE_OFB, iv=iv)
        if mode == "ctr":
            # the whole block as counter
            return AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=iv)
        if mode == "gcm":
            return AES.new(key, AES.MODE_GCM, nonce=iv, mac_len=taglen)
        raise ValueError(mode)

    def run(op, mode, key, iv, pad, aad, tag, data):
        if op == "enc":
            c = cipher(mode, key, iv, int(tag) if mode == "gcm" else 16)
            if pad == "pkcs7":
                data = cpad(data, 16)
            if mode == "gcm":
                c.update(aad)
                out, t = c.encrypt_and_digest(data)
                return out, t
            return c.encrypt(data), b""
        c = cipher(mode, key, iv, len(tag) if mode == "gcm" else 16)
        if mode == "gcm":
            c.update(aad)
            return c.decrypt_and_verify(data, tag), b""
        out = c.decrypt(data)
        if pad == "pkcs7":
            out = cunpad(out, 16)
        return out, b""

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
            op, mode, key, iv, pad, aad, tag, data = fields
            t = tag if op == "enc" else unhex(tag)
            try:
                r, rt = run(op, mode, unhex(key), unhex(iv), pad, unhex(aad), t, unhex(data))
                out.append(tohex(r) + " " + tohex(rt))
            except Exception:
                out.append("ERR")
    sys.stdout.write("\n".join(out) + "\n")


main()
