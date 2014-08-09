from __future__ import with_statement
from os import path, walk, listdir
from cantrell.detection import *


def prefix_search(dirpath):
    """Search for all files in a folder recursively."""
    return [path.join(root, filename)
            for root, dirnames, filenames in walk(dirpath)
            for filename in filenames
    ]


class SourceTree:
    def __init__(self, prefix):
        """Collect all source and header files into a searchable tree."""
        self.src = {}
        self.src_dir = {}
        self.inc_dir = {}
        self.headers = {}
        self.prefix = prefix

        self.src_dir['lib'] = path.join(prefix, 'src')
        self.inc_dir['lib'] = path.join(prefix, 'include')
        self.src_dir['test'] = path.join(prefix, 'test/src')
        self.inc_dir['test'] = path.join(prefix, 'test/include')
        self.src_dir['util'] = path.join(prefix, 'samples/util/src')
        self.inc_dir['util'] = path.join(prefix, 'samples/util/include')
        self.src_dir['sample'] = path.join(prefix, 'samples/src')

        # Collect all the library files, including definition header
        # (note the files are all given as full paths from the root)

        self.def_header = path.join(prefix, 'include/ordo/definitions.h')

        self.headers['lib'] = list(set(
            prefix_search(self.inc_dir['lib']) + [self.def_header]
        ))

        self.src['lib'] = self.search_src_lib(self.src_dir['lib'], self.prefix)

        self.src['test'] = prefix_search(self.src_dir['test'])
        self.src['util'] = prefix_search(self.src_dir['util'])
        self.headers['test'] = prefix_search(self.inc_dir['test'])
        self.headers['util'] = prefix_search(self.inc_dir['util'])

        self.src['hashsum'] = [path.join(self.src_dir['sample'], 'hashsum.c')]
        self.src['version'] = [path.join(self.src_dir['sample'], 'version.c')]
        self.src['info'] = [path.join(self.src_dir['sample'], 'info.c')]
        self.src['benchmark'] = [path.join(self.src_dir['sample'], 'benchmark.c')]

        self.headers['hashsum'] = []
        self.headers['version'] = []
        self.headers['info'] = []
        self.headers['benchmark'] = []

    def search_src_lib(self, pR, prefix):
        out = {}

        for plat in platform_list:
            for arch in arch_list:
                for feat in feature_list:
                    pP = path.join(pR, plat) if plat != 'generic' else pR
                    pA = path.join(pP, arch) if arch != 'generic' else pP
                    pF = path.join(pA, feat) if feat != 'generic' else pA

                    if not path.isdir(pF):
                        out[(plat, arch, feat)] = []
                        continue

                    out[(plat, arch, feat)] = [
                        path.join(pF, f) for f in listdir(pF)
                        if path.isfile(path.join(pF, f))
                    ]

        return out

    def same_module(self, file1, file2):
        """Return if two files are (the same part of) the same module."""
        return path.basename(file1) == path.basename(file2)

    def process(self, source_files, category):
        for f in self.src['lib'][category]:
            if not any(self.same_module(f, f2) for f2 in source_files):
                source_files.append(f)
        return source_files

    def select(self, plat, arch, features):
        """Select the source files to build from platform/arch/features."""
        source_files = []

        for f in set(features + ['generic']):
            tup = (plat, arch, f)
            source_files = self.process(source_files, tup)
        for a in set([arch] + ['generic']):
            tup = (plat, a, 'generic')
            source_files = self.process(source_files, tup)
        for p in set([plat] + ['generic']):
            tup = (p, 'generic', 'generic')
            source_files = self.process(source_files, tup)

        return source_files


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

    src = 'struct %s_STATE\n' % prim_type
    src += '{\n'
    src += '    prim_t primitive;\n'

    if prim_count > 0:
        src += '\n'
        src += '    union\n'
        src += '    {\n'

        for (_, prim) in built_prims:
            if prim.prim_type == prim_type:
                src += '        struct %s_STATE %s;\n' % (prim.name.upper(), prim.name)

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
    definitions += '#define HASH_BLOCK_LEN  %d\n' % get_block_len(built_prims,  'HASH')
    definitions += '#define HASH_DIGEST_LEN %d\n' % get_digest_len(built_prims, 'HASH')
    definitions += '#define BLOCK_BLOCK_LEN %d\n' % get_block_len(built_prims,  'BLOCK')

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
