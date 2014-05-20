#!/usr/bin/env python

''' The purpose of this script is to extract struct definitions
    for primitives from source files that are being built (this
    is provided via command-line arguments) and write them into
    a header file so they can be made public to the user.
    
    This will be moved into the CMake script eventually but due
    to the nontrivial nature of the operation it is much easier
    to prototype in Python for the moment.                      '''

from sys import argv

class Primitive:
    def __init__(self, name, prefix, ptype, block_len, digest_len):
        self.name = name
        self.prefix = prefix
        self.ptype = ptype
        self.block_len = block_len
        self.digest_len = digest_len

primitives = [Primitive("rc4.c", "RC4", "STREAM", block_len = 0, digest_len = 0),
              Primitive("md5.c", "MD5", "HASH", block_len = 64, digest_len = 16),
              Primitive("sha256.c", "SHA256", "HASH", block_len = 64, digest_len = 32),
              Primitive("skein256.c", "SKEIN256", "HASH", block_len = 32, digest_len = 32)]

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
    buf =  "struct {0}_STATE\n".format(ptype)
    buf += "{\n"
    
    if ptype == "HASH":
        buf += "    enum HASH_FUNCTION primitive;\n"
    elif ptype == "STREAM":
        buf += "    enum STREAM_CIPHER primitive;\n"
    # elif...
    
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
    
    return maxval

def calc_digest_len(prims, ptype):
    maxval = 0

    for (arg, prim) in prims:
        if prim.ptype == ptype:
            maxval = max(maxval, prim.digest_len)
    
    return maxval

if __name__ == "__main__":
    in_use = []
    
    for arg in argv:
        for prim in primitives:
            if prim.name in arg:
                in_use.append((arg, prim))
    
    platform  = "/* AUTOGENERATED - DO NOT EDIT */\n\n"
    platform += "#ifndef ORDO_PLATFORM_H\n"
    platform += "#define ORDO_PLATFORM_H\n"
    
    platform += "\n"
    platform += "#define HASH_BLOCK_LEN {0}\n".format(calc_block_len(in_use, "HASH"))
    platform += "#define HASH_DIGEST_LEN {0}\n".format(calc_digest_len(in_use, "HASH"))
    
    for (path, prim) in in_use:
        platform += "\n" + extract_struct(path, prim)
    
    platform += "\n" + gen_polymorphic_struct(in_use, "HASH")
    platform += "\n" + gen_polymorphic_struct(in_use, "STREAM")
    
    platform += "\n#endif"
    
    with open('include/ordo/platform.h', 'w') as f:
        f.write(platform)
    
    # done!
