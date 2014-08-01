#!/usr/bin/env python
#-*- coding:utf-8 -*-

from __future__ import print_function

#===============================================================================
#======================= OUTPUT, LOGGING, AND UTILITIES ========================
#===============================================================================

from os import path, mkdir

verbose   = False
build_dir = 'build'
build_ctx = '.context'

class BuildError(Exception):
    pass

def regenerate_build_folder():
    if not path.isdir(build_dir):
        os.mkdir(build_dir)

    with open(path.join(build_dir, '.gitignore'), 'w') as f:
        f.write('*\n!.gitignore\n')  # Recreate a .gitignore

def log(level, fmt, *args, **kwargs):
    if verbose:
        if level == 'info':
            print(fmt.format(*args, **kwargs))
        elif level == 'warn':
            print('Warning: ' + fmt.format(*args, **kwargs))
        elif level == 'fail':
            print('Error: ' + fmt.format(*args, **kwargs))
        else:
            raise ValueError("Unrecognized logging level")

class chdir:
    """Context manager for changing the current working directory"""
    def __init__(self, newPath):
        self.newPath = newPath

    def __enter__(self):
        self.savedPath = os.getcwd()
        os.chdir(self.newPath)

    def __exit__(self, etype, value, traceback):
        os.chdir(self.savedPath)

#===============================================================================
#======================= PLATFORM ANALYSIS AND CHECKING ========================
#===============================================================================

import subprocess
import platform
import os, sys
import shutil

os_list = ['generic', 'linux', 'win32', 'darwin', 'freebsd', 'openbsd', 'netbsd']

arch_list = ['generic', 'amd64']

def get_os():
    """Returns the current OS as a library platform string, or "generic"."""
    if platform.system() == 'Linux':
        return 'linux'
    elif platform.system() == 'Windows':
        return 'win32'
    elif platform.system() == 'Darwin':
        return 'darwin'
    elif platform.system() == 'FreeBSD':
        return 'freebsd'
    elif platform.system() == 'OpenBSD':
        return 'openbsd'
    elif platform.system() == 'NetBSD':
        return 'netbsd'
    else:
        return "generic"

def program_exists(name):
    try:
        run_cmd(name, [])
        return True
    except IOError:
        return False

def get_c_compiler():
    """Returns the name of the default C compiler on the system."""
    if ("CC" in os.environ) and program_exists(os.environ['CC']):
        return os.environ['CC']

    if program_exists('cc'):
        return 'cc'

    # On Windows, maybe check for MSVC in one of the popular paths here

    return None

def get_compiler_id(compiler):
    if not program_exists(compiler):
        return (None, None)

    output = run_cmd(compiler, ['--version']).decode('utf-8')
    header = output.split('\n')[0]

    if 'GCC' in output:
        return ('gcc', header)
    if 'clang' in output:
        return ('clang', header)
    if 'Intel' in output:
        return ('intel', header)
    if 'MSVC' in output:
        return ('msvc', header)

    return (None, None)

def run_cmd(cmd, args, stream=False):
    process = subprocess.Popen([cmd] + args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    if stream:
        while process.poll() is None:
            print(process.stdout.readline().rstrip())
        print(process.stdout.readline().rstrip())
    else:
        return process.communicate()[0].rstrip()

#===============================================================================
#============================= LIBRARY RESOURCES ===============================
#===============================================================================

source_files = [
    'alg.c',
    'utils.c',
    'block_ciphers.c',
    'block_modes.c',
    'digest.c',
    'enc_block.c',
    'enc_stream.c',
    'endianness.c',
    'error.c',
    'identification.c',
    'hash_functions.c',
    'hmac.c',
    'ordo.c',
    'os_random.c',
    'pbkdf2.c',
    'hkdf.c',
    'stream_ciphers.c',
    'version.c',
    'curve25519.c',
    'features.c',
    'sha1.c',
    'sha256.c',
    'md5.c',
    'skein256.c',
    'rc4.c',
    'aes.c',
    'threefish256.c',
    'nullcipher.c',
    'ecb.c',
    'cbc.c',
    'ctr.c',
    'cfb.c',
    'ofb.c'
]

headers = [
    '../include/ordo.h',
    '../include/ordo/auth/hmac.h',
    '../include/ordo/common/error.h',
    '../include/ordo/common/identification.h',
    '../include/ordo/common/interface.h',
    '../include/ordo/common/limits.h',
    '../include/ordo/common/version.h',
    '../include/ordo/digest/digest.h',
    '../include/ordo/enc/enc_block.h',
    '../include/ordo/enc/enc_stream.h',
    '../include/ordo/internal/alg.h',
    '../include/ordo/internal/implementation.h',
    '../include/ordo/internal/sys.h',
    '../include/ordo/kdf/pbkdf2.h',
    '../include/ordo/kdf/hkdf.h',
    '../include/ordo/misc/curve25519.h',
    '../include/ordo/misc/endianness.h',
    '../include/ordo/misc/os_random.h',
    '../include/ordo/misc/utils.h',
    '../include/ordo/primitives/block_ciphers.h',
    '../include/ordo/primitives/block_ciphers/aes.h',
    '../include/ordo/primitives/block_ciphers/block_params.h',
    '../include/ordo/primitives/block_ciphers/nullcipher.h',
    '../include/ordo/primitives/block_ciphers/threefish256.h',
    '../include/ordo/primitives/block_modes.h',
    '../include/ordo/primitives/block_modes/cbc.h',
    '../include/ordo/primitives/block_modes/cfb.h',
    '../include/ordo/primitives/block_modes/ctr.h',
    '../include/ordo/primitives/block_modes/ecb.h',
    '../include/ordo/primitives/block_modes/mode_params.h',
    '../include/ordo/primitives/block_modes/ofb.h',
    '../include/ordo/primitives/hash_functions.h',
    '../include/ordo/primitives/hash_functions/hash_params.h',
    '../include/ordo/primitives/hash_functions/md5.h',
    '../include/ordo/primitives/hash_functions/sha256.h',
    '../include/ordo/primitives/hash_functions/skein256.h',
    '../include/ordo/primitives/hash_functions/sha1.h',
    '../include/ordo/primitives/stream_ciphers.h',
    '../include/ordo/primitives/stream_ciphers/rc4.h',
    '../include/ordo/primitives/stream_ciphers/stream_params.h',
    '../include/ordo/definitions.h'
]

test_srcdir = '../extra/test/src/'

test_source = [
    'main.c',
    'test_vectors/md5.c',
    'test_vectors/sha1.c',
    'test_vectors/sha256.c',
    'test_vectors/skein256.c',
    'test_vectors/hmac.c',
    'test_vectors/hkdf.c',
    'test_vectors/pbkdf2.c',
    'test_vectors/rc4.c',
    'test_vectors/aes.c',
    'test_vectors/threefish256.c',
    'test_vectors/ecb.c',
    'test_vectors/cbc.c',
    'test_vectors/ctr.c',
    'test_vectors/cfb.c',
    'test_vectors/ofb.c',
    'test_vectors/curve25519.c',
    'unit_tests/pbkdf2.c',
    'unit_tests/hkdf.c',
    'unit_tests/misc.c',
    'unit_tests/internal.c',
    'unit_tests/os_random.c'
]

test_headers = [
    '../extra/test/include/testenv.h'
]

#===============================================================================
#======================== DEFINITION RESOLUTION SCRIPT =========================
#===============================================================================

class Primitive:
    """ Holds a library primitive with limit information. """
    def __init__(self, name, prim_type, block_len = 0, digest_len = 0):
        self.name = name
        self.prim_type = prim_type
        self.block_len = block_len
        self.digest_len = digest_len

primitives = [
    Primitive('rc4',               'STREAM'                                           ),
    Primitive('md5',               'HASH',             block_len = 64, digest_len = 16),
    Primitive('sha1',              'HASH',             block_len = 64, digest_len = 20),
    Primitive('sha256',            'HASH',             block_len = 64, digest_len = 32),
    Primitive('skein256',          'HASH',             block_len = 32, digest_len = 32),
    Primitive('aes',               'BLOCK',            block_len = 16                 ),
    Primitive('threefish256',      'BLOCK',            block_len = 32                 ),
    Primitive('nullcipher',        'BLOCK',            block_len = 16                 ),
    Primitive('ecb',               'BLOCK_MODE'                                       ),
    Primitive('cbc',               'BLOCK_MODE'                                       ),
    Primitive('cfb',               'BLOCK_MODE'                                       ),
    Primitive('ofb',               'BLOCK_MODE'                                       ),
    Primitive('ctr',               'BLOCK_MODE'                                       ),
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

    src =  'struct {0}_STATE\n'.format(prim_type)
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

def resolve(definitions_path, built_files):
    """Analyze a list of built source files and output a definition header."""
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

    definitions  = '/* AUTOGENERATED - DO NOT EDIT */\n\n'
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

#===============================================================================
#========================= TARGET-SPECIFIC GENERATION ==========================
#===============================================================================

def gen_makefile(ctx):
    if ctx.compiler in ['gcc', 'clang']:
        cflags = ['-O3', '-Wall', '-Wextra', '-std=c89', '-pedantic',
                  '-fvisibility=hidden', '-Wno-unused-parameter',
                  '-Wno-long-long', '-Wno-missing-braces',
                  '-Wno-missing-field-initializers']
        if ctx.lto:
            if ctx.compiler in ['gcc']:
                cflags += ['-flto -ffat-lto-objects']
            else:
                cflags += ['-flto']
        if not ctx.compat:
            cflags += ['-march=native']
    elif (ctx.compiler == 'icc'):
        pass  # TODO (icc)
    elif (ctx.compiler == 'msvc'):
        pass  # TODO (windows)

    defines = ['-DORDO_STATIC_LIB', '-DBUILDING_ORDO',
               '-DORDO_SYSTEM=\\\"{0}\\\"'.format(ctx.platform),
               '-DORDO_ARCH=\\\"{0}\\\"'.format(ctx.arch)]

    if ctx.platform == 'generic':
        defines += ['-DORDO_LITTLE_ENDIAN' if ctx.endian == 'little' else
                    '-DORDO_BIG_ENDIAN']

    # TODO: implement selection logic here?

    defines += ['-DWITH_AES=1', '-DWITH_THREEFISH256=1', '-DWITH_NULLCIPHER=1',
                '-DWITH_RC4=1', '-DWITH_MD5=1', '-DWITH_SHA1=1',
                '-DWITH_SHA256=1', '-DWITH_SKEIN256=1', '-DWITH_ECB=1',
                '-DWITH_CBC=1', '-DWITH_CTR=1', '-DWITH_CFB=1',
                '-DWITH_OFB=1']

    with open(path.join(build_dir, 'Makefile'), 'w') as f:
        f.write('HEADERS = {0}\n'.format(' '.join(headers)))
        f.write('TEST_HEADERS = {0}\n'.format(' '.join(test_headers)))
        f.write('CFLAGS = {0}\n'.format(' '.join(cflags + defines)))
        f.write('TEST_CFLAGS = -O3 -Wall -Wextra -std=c89 -pedantic -Wno-unused-parameter -Wno-long-long -Wno-missing-field-initializers -DORDO_STATIC_LIB\n')
        f.write('\n')
        f.write('all: static test\n\n')
        f.write('static: libordo_s.a\n\n')
        f.write('obj:\n\tmkdir obj\n\n')

        objfiles = []
        for srcfile in source_files:
            objfile = 'obj/' + srcfile.replace('.c', '.o')
            objfiles.append(objfile)
            f.write('{0}: {1} $(HEADERS) | obj\n'.format(objfile, '../src/' + srcfile))
            f.write('\t{0} $(CFLAGS) -I../include -c $< -o $@\n\n'.format(ctx.compiler))

        f.write('libordo_s.a: {0}\n'.format(' '.join(objfiles)))
        f.write('\tar rcs libordo_s.a {0}\n'.format(' '.join(objfiles)))

        test_objfiles = []
        for srcfile in test_source:
            objfile = 'obj/' + srcfile.replace('.c', '.o').replace('/', '_')
            test_objfiles.append(objfile)
            f.write('{0}: {1} $(HEADERS) $(TEST_HEADERS) | obj\n'.format(objfile, path.join(test_srcdir, srcfile)))
            f.write('\t{0} $(TEST_CFLAGS) -I../include -I../extra/test/include -c $< -o $@\n\n'.format(ctx.compiler))

        f.write('test: libordo_s.a {0}\n'.format(' '.join(test_objfiles)))
        f.write('\t{0} {1} -o $@ libordo_s.a\n'.format(ctx.compiler, ' '.join(test_objfiles)))

    resolve('include/ordo/definitions.h', ['src/' + src for src in source_files])

def bld_makefile(ctx, targets):
    with chdir(build_dir):
        run_cmd('make', targets)

def ins_makefile(ctx):
    with chdir(build_dir):
        run_cmd('make', ['install'])  # Must handle dependencies!

def tst_makefile(ctx):
    bld_makefile(ctx, ['test'])
    run_cmd(path.join(build_dir, 'test'), [])  # Must build tests before!

# VS/etc.

generate    = {'makefile': gen_makefile}
run_build   = {'makefile': bld_makefile}
run_install = {'makefile': ins_makefile}
run_tests   = {'makefile': tst_makefile}

#===============================================================================
#========================== HIGH-LEVEL BUILD PROCESS ===========================
#===============================================================================

import pickle

class BuildContext:
    def __init__(self, args):
        """This function simply copies the arguments into a build context."""
        self.lto = args.lto
        self.compat = args.compat
        self.shared = args.shared

        cc = get_c_compiler() if args.compiler is None else args.compiler[0]
        self.compiler, self.compiler_info = get_compiler_id(cc)

        self.platform = args.platform[0]
        self.arch = args.arch[0]

def configure(args):
    """Generates (and returns) a build context from the arguments."""
    ctx = BuildContext(args)

    if ctx.lto and ctx.compat:
        raise BuildError("Link-time optimization and compatibility mode are mutually exclusive")

    if ctx.platform == 'generic':
        print("Note: compiling for generic platform")
        print("      (external utilities will not be available)")

        if args.endian is None:
            raise BuildError("Error: please specify target endianness for generic platform")

        ctx.endian = args.endian[0]

    if ctx.compiler is None:
        print(".. FAILED to detect C compiler.")
        print(".. please configure with --compiler")
        raise BuildError("An error occurred during configuration")
    else:
        print(".. C compiler is: {0}".format(ctx.compiler_info))

    print("Your platform is ", ctx.platform)

    ctx.output = 'makefile'

    with open(path.join(build_dir, build_ctx), mode='wb') as f:
        pickle.dump(ctx, f)

    return ctx

def make_doc(args):
    """Attempts to generate documentation by calling doxygen."""

    # Try and locate doxygen
    doxygen_path = 'doxygen'

    run_cmd('doxygen', [])

def clean_build():
    """Deletes the build folder and recreates an empty one."""
    shutil.rmtree(build_dir)
    regenerate_build_folder()

def get_targets(ctx, targets):
    """Parses a target list and filters out unknown targets."""
    out = []

    for target in targets:
        if target == 'static':
            out.append('static')
        elif (target == 'shared') and ctx.shared:
            out.append('shared')
        elif target == 'test':
            out.append('test')
        elif target == 'samples':
            out.append('samples')
        else:
            log('warn', "Target '{0}' will not be built.", target)

    return ['all'] if len(out) == 0 else out

from argparse import ArgumentParser
import argparse

def main():
    global verbose

    master = ArgumentParser(description="Build script for the Ordo library.")
    parsers = master.add_subparsers(dest='command')  # One for each command
    master.add_argument('-v', '--verbose', action='store_true',
                        help="display additional information")

    cfg = parsers.add_parser('configure', help="configure the library")
    bld = parsers.add_parser('build',     help="build one or more targets")
    ins = parsers.add_parser('install',   help="install library on system")
    tst = parsers.add_parser('test',      help="run the Ordo test driver")
    cln = parsers.add_parser('clean',     help="remove all build files")
    doc = parsers.add_parser('doc',       help="generate documentation")

    cfg.add_argument('-c', '--compiler', nargs=1, type=str, metavar='',
                     help="path to C compiler to use for building")

    cfg.add_argument('-p', '--platform', nargs=1, type=str, metavar='',
                     help="operating system/platform to configure for",
                     default=[get_os()], choices=os_list)

    cfg.add_argument('-e', '--endian', nargs=1, type=str, metavar='',
                     help="target endianness (for generic platform)",
                     default=None, choices=['little', 'big'])

    cfg.add_argument('-a', '--arch', nargs=1, type=str, metavar='',
                     help="architecture to configure for",
                     default=['generic'], choices=arch_list)

    cfg.add_argument('-u', '--compat', action='store_true',
                     help="for (very) old compilers",
                     default=False)

    cfg.add_argument('-l', '--lto', action='store_true',
                     help="use link-time optimization",
                     default=True)

    cfg.add_argument('--aes-ni', action='store_true',
                     help="use the AES-NI hardware instructions",
                     default=False)

    cfg.add_argument('--shared', action='store_true',
                     help="also build as a shared library",
                     default=False)

    bld.add_argument('targets', nargs=argparse.REMAINDER,
                     help="set of targets to build")

    args = master.parse_args()
    regenerate_build_folder()
    verbose = args.verbose
    cmd = args.command

    # TODO: then implement the source file selection algorithm and
    #       assembly support, to achieve feature parity with the
    #       cmake version with makefiles, before doing Windows

    try:
        if cmd in ['configure']:  # Erase previous config
            if path.exists(path.join(build_dir, build_ctx)):
                log('info', 'Already configured, cleaning')
                clean_build()
            ctx = configure(args)
            generate[ctx.output](ctx)
        elif cmd in ['build', 'install', 'test']:  # Need config
            if not path.exists(path.join(build_dir, build_ctx)):
                raise BuildError("Please configure before '{0}'.".format(cmd))
            else:
                with open(path.join(build_dir, build_ctx), 'rb') as f:
                    log('info', "Parsing build info in '{0}'.", f.name)
                    ctx = pickle.load(f)
            if cmd == 'build':
                run_build[ctx.output](ctx, get_targets(ctx, args.targets))
            elif cmd == 'install':
                run_install[ctx.output](ctx)  # Install libraries
            elif cmd == 'test':
                run_tests[ctx.output](ctx)  # Build & run tests
        elif cmd in ['doc']:
            make_doc(args)
        elif cmd in ['clean']:
            clean_build()
    except BuildError as e:
        print(e)

if __name__ == '__main__':
    main()
