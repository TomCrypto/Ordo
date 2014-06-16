#!/usr/bin/env python
# -*- coding: utf-8 -*-

''' The purpose of this script is to extract struct definitions
    for primitives from source files that are being built (this
    is provided via command-line arguments) and write them into
    a header file so they can be made public to the user.
    
    This will be moved into the CMake script eventually but due
    to the nontrivial nature of the operation it is much easier
    to prototype in Python for the moment.                      '''

import sys

class Primitive:
    def __init__(self, name, prefix, ptype, block_len = 0, digest_len = 0):
        self.name = name
        self.prefix = prefix
        self.ptype = ptype
        self.block_len = block_len
        self.digest_len = digest_len

primitives = [Primitive("rc4.c", "RC4", "STREAM"),
              Primitive("md5.c", "MD5", "HASH", block_len = 64, digest_len = 16),
              Primitive("sha256.c", "SHA256", "HASH", block_len = 64, digest_len = 32),
              Primitive("skein256.c", "SKEIN256", "HASH", block_len = 32, digest_len = 32),
              Primitive("aes.c", "AES", "BLOCK", block_len = 16),
              Primitive("threefish256.c", "THREEFISH256", "BLOCK", block_len = 32),
              Primitive("nullcipher.c", "NULLCIPHER", "BLOCK", block_len = 16),
              Primitive("ecb.c", "ECB", "BLOCK_MODE"),
              Primitive("cbc.c", "CBC", "BLOCK_MODE"),
              Primitive("cfb.c", "CFB", "BLOCK_MODE"),
              Primitive("ofb.c", "OFB", "BLOCK_MODE"),
              Primitive("ctr.c", "CTR", "BLOCK_MODE"),
              ]

def extract_struct(path, prim):
    with open(path, "r") as f:
        content = f.readlines()
    
    for i, line in enumerate(content):
        if line == "#if annotation\n":
            p1 = i
            break
    
    for i, line in enumerate(content):
        if (line == "#endif /* annotation */\n") and (i > p1):
            p2 = i
            break

    buf = "#define USING_" + prim.prefix + "\n"
    
    for i in range(p1 + 1, p2):
        buf += content[i]
    
    return buf

def gen_polymorphic_struct(prims, ptype):
    count = 0
    for (arg, prim) in prims:
        if prim.ptype == ptype:
            count += 1

    buf =  "struct {0}_STATE\n".format(ptype)
    buf += "{\n"

    buf += "    prim_t primitive;\n"

    if count > 0:
        buf += "\n    union\n"
        buf += "    {\n"
        
        for (arg, prim) in prims:
            if prim.ptype == ptype:
                buf += "        struct {0}_STATE {1};\n".format(prim.prefix, prim.prefix.lower())
        
        buf += "    } jmp;\n"

    buf += "};\n"
    
    return buf

def calc_block_len(prims, ptype):
    maxval = 0

    for (arg, prim) in prims:
        if prim.ptype == ptype:
            maxval = max(maxval, prim.block_len)
    
    return 1 if maxval == 0 else maxval

def calc_digest_len(prims, ptype):
    maxval = 0

    for (arg, prim) in prims:
        if prim.ptype == ptype:
            maxval = max(maxval, prim.digest_len)
    
    return 1 if maxval == 0 else maxval

if __name__ == "__main__":
    in_use = []
    
    for arg in sys.argv:
        for prim in primitives:
            if prim.name in arg:
                in_use.append((arg, prim))
    
    platform  = "/* AUTOGENERATED - DO NOT EDIT */\n\n"
    platform += "#ifndef ORDO_DEFINITIONS_H\n"
    platform += "#define ORDO_DEFINITIONS_H\n"
    platform += "\n"
    platform += "#include \"ordo/common/identification.h\"\n"
    
    platform += "\n"
    platform += "#define HASH_BLOCK_LEN {0}\n".format(calc_block_len(in_use, "HASH"))
    platform += "#define HASH_DIGEST_LEN {0}\n".format(calc_digest_len(in_use, "HASH"))
    platform += "#define BLOCK_BLOCK_LEN {0}\n".format(calc_block_len(in_use, "BLOCK"))
    
    for (path, prim) in in_use:
        print prim.name
        platform += "\n" + extract_struct(path, prim)
    
    platform += "\n" + gen_polymorphic_struct(in_use, "BLOCK")
    platform += "\n" + gen_polymorphic_struct(in_use, "HASH")
    platform += "\n" + gen_polymorphic_struct(in_use, "STREAM")
    platform += "\n" + gen_polymorphic_struct(in_use, "BLOCK_MODE")
    
    platform += "\n#endif\n"
    
    with open('include/ordo/definitions.h', 'w') as f:
        f.write(platform)
    
    # done!
