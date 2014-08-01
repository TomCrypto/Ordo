#!/usr/bin/env python
#-*- coding:utf-8 -*-

from __future__ import print_function

# =============================================================================
# ====================== OUTPUT, LOGGING, AND UTILITIES =======================
# =============================================================================

from os import path, mkdir

verbose = False
build_dir = 'build'
build_ctx = '.context'


class BuildError(Exception):
    pass


def regenerate_build_folder():
    if not path.isdir(build_dir):
        os.mkdir(build_dir)

    with open(path.join(build_dir, '.gitignore'), 'w') as f:
        f.write('*\n!.gitignore\n')  # Recreate a .gitignore


def safe_path(s):
    """Converts a filesystem path to a safe (first-level) file name."""
    return s.replace('/', '_')


def multiline_pad(header, msg, width):
    indent = len(header) + 2
    pad = width - indent  # Effective width
    lines = [msg[t:t + pad] for t in range(0, len(msg), pad)]
    return '{0}: {1}'.format(header, ('\n' + ' ' * indent).join(lines))


def log(level, fmt, *args, **kwargs):
    tt = fmt.format(*args, **kwargs)

    if level == 'fail':
        print(multiline_pad('Error', tt, 78))
    elif level == 'warn':
        print(multiline_pad('Warning', tt, 78))
    elif (level == 'info'):
        if verbose:
            print(multiline_pad('Info', tt, 78))
    elif (level == 'debug') and verbose:
        if verbose:
            print(multiline_pad('Debug', tt, 78))
    else:
        raise ValueError("Unrecognized logging level!")


class chdir:
    """Context manager for changing the current working directory"""
    def __init__(self, newPath):
        self.newPath = newPath

    def __enter__(self):
        self.savedPath = os.getcwd()
        os.chdir(self.newPath)

    def __exit__(self, etype, value, traceback):
        os.chdir(self.savedPath)


# =============================================================================
# ====================== PLATFORM ANALYSIS AND CHECKING =======================
# =============================================================================


import subprocess
import platform
import os, sys
import shutil


platform_list = ['generic', 'linux', 'win32', 'darwin', 'freebsd', 'openbsd', 'netbsd']

arch_list = ['generic', 'amd64']


def get_platform():
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

    out = run_cmd(compiler, ['--version'])[1]
    header = out.split('\n')[0]

    if 'gcc' in out.lower():
        return ('gcc', header)
    if 'clang' in out.lower():
        return ('clang', header)
    if 'intel' in out.lower():
        return ('intel', header)
    if 'msvc' in out.lower():
        return ('msvc', header)

    return (None, None)


def stream(line):
    """Utility function for run_cmd which streams its input to stdout."""
    print(line, end='')


def run_cmd(cmd, args=[], stdout_func=None):
    """Executes a shell command and returns its output (and errors)."""
    process = subprocess.Popen([cmd] + args,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT)

    stdout = ''

    for buf in iter(process.stdout.readline, ''):
        line = buf.decode('utf-8')

        if (not line) or ((stdout_func is not None) and stdout_func(line)):
            break

        stdout += line

    stdout_buf = process.communicate()[0]
    final_line = stdout_buf.decode('utf-8')
    if final_line:
        if (stdout_func is not None):
            stdout_func(final_line)

        stdout += final_line

    return (process.returncode, stdout)


# =============================================================================
# ============================ LIBRARY RESOURCES ==============================
# =============================================================================


class SourceTree:
    def __init__(self):
        self.srcdir = 'src'

        self.src = {}

        self.src['all'] = set()

        for platform in platform_list:
            if platform == 'generic':
                pth = self.srcdir
            else:
                pth = path.join(self.srcdir, platform)

            self.src[(platform, 'generic')] = [path.join(pth, f) for f in os.listdir(pth) if path.isfile(path.join(pth, f))]

            for f in [f for f in os.listdir(pth) if path.isfile(path.join(pth, f))]:
                self.src['all'].add(f)

            for arch in arch_list:
                apth = path.join(pth, arch)
                if not path.isdir(apth):
                    continue

                self.src[(platform, arch)] = [path.join(apth, f) for f in os.listdir(apth) if path.isfile(path.join(apth, f))]

                for f in [path.join(apth, f) for f in os.listdir(apth) if path.isfile(path.join(apth, f))]:
                    self.src['all'].add(f)

                print("Files for {0}/{1} = {2}\n".format(platform, arch, self.src[(platform, arch)]))

        # All source files, in order of dependency

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


# =============================================================================
# ======================= DEFINITION RESOLUTION SCRIPT ========================
# =============================================================================


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


# =============================================================================
# ======================== TARGET-SPECIFIC GENERATION =========================
# =============================================================================


def gen_makefile(ctx):
    tree = SourceTree()

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
               '-DORDO_PLATFORM=\\\"{0}\\\"'.format(ctx.platform),
               '-DORDO_ARCH=\\\"{0}\\\"'.format(ctx.arch)]

    if ctx.platform == 'generic':
        defines += ['-DORDO_LITTLE_ENDIAN' if ctx.endian == 'little' else
                    '-DORDO_BIG_ENDIAN']

    # TODO: implement selection logic here?

    print("All files = {0}".format(tree.src['all']))

    to_build = set()

    for srcfile in tree.src['all']:
        found = False
        if ctx.arch != 'generic':
            for afile in tree.src[(ctx.platform, ctx.arch)]:
                if path.basename(srcfile) == path.basename(afile):
                    to_build.add(afile)
                    found = True
        if found:
            continue
        for afile in tree.src[(ctx.platform, 'generic')]:
            if path.basename(srcfile) == path.basename(afile):
                to_build.add(afile)
                found = True
        if found:
            continue
        for afile in tree.src[('generic', 'generic')]:
            if path.basename(srcfile) == path.basename(afile):
                to_build.add(afile)

    print("to_build = {0}".format(to_build))

    defines += ['-DWITH_AES=1', '-DWITH_THREEFISH256=1', '-DWITH_NULLCIPHER=1',
                '-DWITH_RC4=1', '-DWITH_MD5=1', '-DWITH_SHA1=1',
                '-DWITH_SHA256=1', '-DWITH_SKEIN256=1', '-DWITH_ECB=1',
                '-DWITH_CBC=1', '-DWITH_CTR=1', '-DWITH_CFB=1',
                '-DWITH_OFB=1']

    with open(path.join(build_dir, 'Makefile'), 'w') as f:
        f.write('HEADERS = {0}\n'.format(' '.join(headers)))
        f.write('TEST_HEADERS = {0}\n'.format(' '.join(test_headers)))
        f.write('CFLAGS = {0}\n'.format(' '.join(cflags + defines)))
        f.write('TEST_CFLAGS = {0} -DORDO_STATIC_LIB\n'.format(' '.join(cflags)))
        f.write('\n')
        f.write('all: static test\n\n')
        f.write('static: libordo_s.a\n\n')
        f.write('obj:\n\tmkdir obj\n\n')

        objfiles = []
        for srcfile in to_build:
            if '.c' in srcfile:
                objfile = 'obj/' + safe_path(srcfile.replace('.c', '.o'))
                objfiles.append(objfile)
                f.write('{0}: {1} $(HEADERS) | obj\n'.format(objfile, path.join('../', srcfile)))
                f.write('\t{0} $(CFLAGS) -I../include -c $< -o $@\n\n'.format(ctx.compiler))
            elif '.asm' in srcfile:
                objfile = 'obj/' + safe_path(srcfile.replace('.asm', '.asm.o'))
                objfiles.append(objfile)
                f.write('{0}: {1} | obj\n'.format(objfile, path.join('../', srcfile)))
                f.write('\t{0} -f {1} $< -o $@\n\n'.format(ctx.assembler, ctx.obj_format))

        f.write('libordo_s.a: {0}\n'.format(' '.join(objfiles)))
        f.write('\tar rcs libordo_s.a {0}\n'.format(' '.join(objfiles)))

        test_objfiles = []
        for srcfile in test_source:
            objfile = 'obj/' + safe_path(srcfile.replace('.c', '.o'))
            test_objfiles.append(objfile)
            f.write('{0}: {1} $(HEADERS) $(TEST_HEADERS) | obj\n'.format(objfile, path.join(test_srcdir, srcfile)))
            f.write('\t{0} $(TEST_CFLAGS) -I../include -I../extra/test/include -c $< -o $@\n\n'.format(ctx.compiler))

        f.write('test: libordo_s.a {0}\n'.format(' '.join(test_objfiles)))
        f.write('\t{0} {1} -o $@ libordo_s.a\n'.format(ctx.compiler, ' '.join(test_objfiles)))

    resolve('include/ordo/definitions.h', to_build)


def bld_makefile(ctx, targets):
    with chdir(build_dir):
        run_cmd('make', targets, stdout_func=stream)


def ins_makefile(ctx):
    with chdir(build_dir):
        run_cmd('make', ['install'], stdout_func=stream)  # Must handle dependencies!


def tst_makefile(ctx):
    bld_makefile(ctx, ['test'])
    run_cmd(path.join(build_dir, 'test'), [], stdout_func=stream)  # Must build tests before!


# VS/etc.


generate    = {'makefile': gen_makefile}
run_build   = {'makefile': bld_makefile}
run_install = {'makefile': ins_makefile}
run_tests   = {'makefile': tst_makefile}


# =============================================================================
# ========================= HIGH-LEVEL BUILD PROCESS ==========================
# =============================================================================


from argparse import ArgumentParser
import argparse, pickle


class BuildContext:
    def __init__(self, args):
        """This function simply copies the arguments into a build context."""
        self.lto = args.lto
        self.compat = args.compat

        cc = get_c_compiler() if args.compiler is None else args.compiler[0]
        self.compiler, self.compiler_info = get_compiler_id(cc)

        self.platform = args.platform[0]
        self.arch = args.arch[0]

        self.assembler = 'nasm'
        self.obj_format = 'elf64'


def configure(args):
    """Generates and returns a build context from the arguments."""
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

    ctx.out = 'makefile'

    with open(path.join(build_dir, build_ctx), mode='wb') as f:
        pickle.dump(ctx, f)

    return ctx


def make_doc(args):
    """Attempts to generate documentation by calling doxygen."""
    if not program_exists('doxygen'):
        raise BuildError("Doxygen is required to build the documentation")
    else:
        run_cmd('doxygen', stdout_func=stream)


def clean_build():
    """Deletes the build folder and recreates an empty one."""
    shutil.rmtree(build_dir)
    regenerate_build_folder()

def main():
    global verbose

    master = ArgumentParser(description="Build script for the Ordo library.")
    parsers = master.add_subparsers(dest='command')  # One for each command

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
                     default=[get_platform()], choices=platform_list)

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
                     default=False)

    cfg.add_argument('--aes-ni', action='store_true',
                     help="use the AES-NI hardware instructions",
                     default=False)

    bld.add_argument('targets', nargs=argparse.REMAINDER,
                     help="set of targets to build",
                     choices=['static', 'shared', 'test', 'samples'])

    master.add_argument('-v', '--verbose', action='store_true',
                        help="display additional information")

    args = master.parse_args()
    regenerate_build_folder()
    verbose = args.verbose
    cmd = args.command

    # TODO: handle CPU features and fill in versioning information like
    #       ORDO_FEATURE_ARRAY and so on, and tidy up code/improve the
    #       makefile generation and other misc. things
    #
    #       Then, add all of the special parameters, implement the
    #       sample targets, and verify the script works everywhere on
    #       linux/bsd/mac with gcc. E.g. ctx.obj_format on 32-bit/mac.
    #
    #       Then, implement the flags for clang and icc, and delete the
    #       CMakeLists and check if it passes on CI, and improve the
    #       function to find programs on the filesystem.
    #
    #       Debug the script (using makefiles/mingw) on Windows.
    #
    #       Implement VS solution generation on Windows.

    try:
        if cmd in ['configure']:
            if path.exists(path.join(build_dir, build_ctx)):
                log('info', 'Already configured, cleaning')
                clean_build()

            ctx = configure(args)
            generate[ctx.out](ctx)
        elif cmd in ['build', 'install', 'test']:
            if not path.exists(path.join(build_dir, build_ctx)):
                raise BuildError("Please configure before '{0}'.".format(cmd))
            else:
                with open(path.join(build_dir, build_ctx), 'rb') as f:
                    log('info', "Parsing build info in '{0}'.", f.name)
                    ctx = pickle.load(f)

            if cmd == 'build':
                run_build[ctx.out](ctx, args.targets)
            elif cmd == 'install':
                run_install[ctx.out](ctx)
            elif cmd == 'test':
                run_tests[ctx.out](ctx)
        elif cmd in ['doc']:
            make_doc(args)
        elif cmd in ['clean']:
            clean_build()
    except BuildError as e:
        print(e)


if __name__ == '__main__':
    main()