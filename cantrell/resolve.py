from __future__ import print_function, division

from os import path


class Primitive:
    """ Holds a library primitive with limit information. """
    def __init__(self, name, prim_type, block_len=0, digest_len=0):
        self.name = name
        self.prim_type = prim_type
        self.block_len = block_len
        self.digest_len = digest_len


primitives = [
    Primitive('rc4',               'STREAM'),
    Primitive('md5',               'HASH',             block_len=64, digest_len=16),
    Primitive('sha1',              'HASH',             block_len=64, digest_len=20),
    Primitive('sha256',            'HASH',             block_len=64, digest_len=32),
    Primitive('skein256',          'HASH',             block_len=32, digest_len=32),
    Primitive('aes',               'BLOCK',            block_len=16),
    Primitive('threefish256',      'BLOCK',            block_len=32),
    Primitive('nullcipher',        'BLOCK',            block_len=16),
    Primitive('ecb',               'BLOCK_MODE'),
    Primitive('cbc',               'BLOCK_MODE'),
    Primitive('cfb',               'BLOCK_MODE'),
    Primitive('ofb',               'BLOCK_MODE'),
    Primitive('ctr',               'BLOCK_MODE')
]


def extract_opaque_struct(fd):
    """ Extracts a list of opaque structures from a file. """
    source = fd.readlines()
    structs = []

    while len(source) != 0:
        line = source[0]
        if line == '#ifdef OPAQUE\n':
            end = source.index("#endif\n")
            structs.append("\n")
            structs += source[1:end]
            del source[:end + 1]
        else:
            del source[0]

    return structs


def gen_polymorphic_struct(built_prims, prim_type):
    """ Generates the polymorphic structure (union) for a primitive type. """
    prim_count = sum(1 for p in built_prims if p[1].prim_type == prim_type)

    src = 'struct {0}_STATE\n'.format(prim_type)
    src += '{\n'
    src += '    prim_t primitive;\n'

    if prim_count > 0:
        src += '\n'
        src += '    union\n'
        src += '    {\n'

        for (_, prim) in built_prims:
            if prim.prim_type == prim_type:
                src += '        struct {0}_STATE {1};\n'.format(prim.name.upper(), prim.name)

        src += '    } jmp;\n'

    src += '};\n'
    return src


def get_block_len(built_prims, prim_type):
    """ Calculates the maximum block length for a given primitive type """
    retval = 0

    for _, p in built_prims:
        if p.prim_type == prim_type:
            retval = max(retval, p.block_len)

    return retval


def get_digest_len(built_prims, prim_type):
    """ Calculates the maximum digest length for a given primitive type """
    retval = 0

    for _, p in built_prims:
        if p.prim_type == prim_type:
            retval = max(retval, p.digest_len)

    return retval


# List of source files along with their resolution order, a lower number means
# the source file contains opaque structs which should be resolved first. Here
# the numbers are assigned according to dependencies and are not all needed.

src_priority = {
    'alg': 0, 'utils': 0, 'features': 0, 'error': 0,
    'version': 0, 'endianness': 0, 'identification': 0,
    'os_random': 1, 'curve25519': 1, 'sha1': 2, 'curve25519': 1,
    'sha256': 2, 'md5': 2, 'skein256': 2,
    'rc4': 2, 'aes': 2, 'threefish256': 2, 'threefish256': 2,
    'nullcipher': 2, 'ecb': 2, 'cbc': 2, 'ctr': 2, 'rc4': 2,
    'cfb': 2, 'ofb': 2,
    'block_ciphers': 3, 'block_modes': 3, 'stream_ciphers': 3,
    'hash_functions': 4,
    'enc_block': 5, 'enc_stream': 5, 'digest': 5,
    'hmac': 6, 'hkdf': 6, 'pbkdf2': 7,
    'ordo': 8
}


def source_sort(name):
    return src_priority[path.splitext(path.basename(name))[0]]


def resolve(definitions_path, built_files):
    """Analyze a list of built source files and output a definition header."""
    built_files = sorted(built_files, key=source_sort)

    built_prims = []
    other_files = []

    for path in built_files:
        added = False
        for prim in primitives:
            if prim.name + '.c' in path:
                built_prims.append((path, prim))
                added = True

        if not added:
            other_files.append(path)

    definitions = '/* AUTOGENERATED - DO NOT EDIT */\n\n'
    definitions += '#ifndef ORDO_DEFINITIONS_H\n'
    definitions += '#define ORDO_DEFINITIONS_H\n'
    definitions += '\n'
    definitions += '#include "ordo/common/identification.h"\n'
    definitions += '#include "ordo/common/limits.h"\n'

    definitions += '\n'
    definitions += '#define HASH_BLOCK_LEN  {0}\n'.format(get_block_len(built_prims,  'HASH'))
    definitions += '#define HASH_DIGEST_LEN {0}\n'.format(get_digest_len(built_prims, 'HASH'))
    definitions += '#define BLOCK_BLOCK_LEN {0}\n'.format(get_block_len(built_prims,  'BLOCK'))

    for (path, prim) in built_prims:
        with open(path, 'r') as fd:
            structs = extract_opaque_struct(fd)
            for line in structs:
                definitions += line

    for prim_type in ['BLOCK', 'HASH', 'STREAM', 'BLOCK_MODE']:
        definitions += '\n' + gen_polymorphic_struct(built_prims, prim_type)

    for path in other_files:
        with open(path, 'r') as fd:
            structs = extract_opaque_struct(fd)
            for line in structs:
                definitions += line

    definitions += '\n'
    definitions += '#endif\n'

    with open(definitions_path, 'w') as fd:
        fd.write(definitions)