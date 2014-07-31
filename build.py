#!/usr/bin/env python
#*-* coding: utf8 *-*

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
        f.write('*\n!.gitignore\n')

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
import sys, os
import shutil

os_list = ['linux', 'win32', 'darwin', 'freebsd', 'openbsd', 'netbsd', 'generic']

arch_list = ['generic', 'amd64']

def get_os():
    """ Returns the current OS as a library platform string, or None. """
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
        return None

def get_cc():
    """ Returns the default C compiler using the CC environment variable.
        If the environment variable does not exist, returns None, or "msvc"
        on windows. """
    return os.environ['CC']

def run_cmd(cmd, args, stream=False):
    process = subprocess.Popen([cmd] + args, stdout=subprocess.PIPE)

    if stream:
        while process.poll() is None:
            print(process.stdout.readline().rstrip())
        print(process.stdout.readline().rstrip())
    else:
        return process.communicate()[0].rstrip()

#===============================================================================
#========================= TARGET-SPECIFIC GENERATION ==========================
#===============================================================================

def gen_makefile(ctx):
    pass

def bld_makefile(ctx, targets):
    with chdir(build_dir):
        run_cmd('make', targets)

def ins_makefile(ctx):
    with chdir(build_dir):
        run_cmd('make', ['install'])

def tst_makefile(ctx):
    run_cmd(path.join(build_dir, 'test/test'), [])

# VS/etc.

gen_output = {'makefile': gen_makefile}
bld_output = {'makefile': bld_makefile}
ins_output = {'makefile': ins_makefile}
tst_output = {'makefile': tst_makefile}

#===============================================================================
#========================== HIGH-LEVEL BUILD PROCESS ===========================
#===============================================================================

import pickle

class BuildContext:
    def __init__(self):
        pass

def configure(args):
    if path.exists(path.join(build_dir, build_ctx)):
        log('info', "Already configured, cleaning.")
        clean(args)

    ctx = BuildContext()

    if args.platform == None:
        ctx.system = get_os()
    else:
        ctx.system = args.platform[0]

    ctx.cc = get_cc()

    print("Your system is ", ctx.system)

    print("The compiler is ", ctx.cc)

    print(run_cmd(ctx.cc, ['--version']))

    ctx.output = 'makefile'

    gen_output[ctx.output](ctx)

    with open(path.join(build_dir, build_ctx), mode='wb') as f:
        pickle.dump(ctx, f)

def build(args):
    if not path.exists(path.join(build_dir, build_ctx)):
        raise BuildError("Please configure first before building.")

    with open(path.join(build_dir, build_ctx), 'rb') as f:
        log('info', "Parsing build info in '{0}'.", f.name)
        ctx = pickle.load(f)

    # Remember to filter and validate targets (lib shared/static, tests/etc.)

    bld_output[ctx.output](ctx, args.targets)

def install(args):
    if not path.exists(path.join(build_dir, build_ctx)):
        raise BuildError("Please configure first before installing.")

    with open(path.join(build_dir, build_ctx), 'rb') as f:
        log('info', "Parsing build info in '{0}'.", f.name)
        ctx = pickle.load(f)

    ins_output[ctx.output](ctx)

def test(args):
    if not path.exists(path.join(build_dir, build_ctx)):
        raise BuildError("Please configure first before testing.")

    with open(path.join(build_dir, build_ctx), 'rb') as f:
        log('info', "Parsing build info in '{0}'.", f.name)
        ctx = pickle.load(f)

    # Should amount to running a binary, but location may be system dependent
    # Also check that we have built (really, run the build each time, it should
    # update itself automatically and only rebuild what is needed)
    # (keep a flag in the build context indicating whether we built at least once)
    tst_output[ctx.output](ctx)

def make_doc(args):
    # Try and locate doxygen
    doxygen_path = 'doxygen'

    shutil.copyfile('Doxyfile', path.join(build_dir, 'Doxyfile'))

    with chdir(build_dir):
        run_cmd('doxygen', [])

def clean(args):
    shutil.rmtree(build_dir)
    regenerate_build_folder()

from argparse import ArgumentParser
import argparse

def main():
    global verbose

    master = ArgumentParser(description="Build script for the Ordo library.")
    parsers = master.add_subparsers(dest='command')  # List of all commands
    master.add_argument('-v', '--verbose', action='store_true',
                        help="display additional information")

    cfg = parsers.add_parser('configure',
                             help="configure the library before building it")
    bld = parsers.add_parser('build',
                             help="build one or more targets automatically")
    ins = parsers.add_parser('install',
                             help="install library headers and binaries")
    tst = parsers.add_parser('test',
                             help="run the library's test driver")
    cln = parsers.add_parser('clean',
                             help="remove all generated build files")
    doc = parsers.add_parser('doc',
                             help="generate the documentation")

    cfg.add_argument('-p', '--platform', nargs=1, type=str, metavar='',
                     help="operating system to configure for ({0})".\
                     format(', '.join(os_list)))

    cfg.add_argument('-a', '--arch', nargs=1, type=str, metavar='',
                     help="architecture to configure for ({0})".\
                     format(', '.join(arch_list)))

    cfg.add_argument('-n', '--native', action='store_true',
                     help="optimize for this system")

    cfg.add_argument('-c', '--compat', action='store_true',
                     help="for (very) old compilers")

    cfg.add_argument('-l', '--lto', action='store_true',
                     help="use link-time optimization")

    cfg.add_argument('--aes-ni', action='store_true',
                     help="use the AES-NI hardware instructions")

    bld.add_argument('targets', nargs=argparse.REMAINDER,
                     help="set of targets to build")

    args = master.parse_args()
    regenerate_build_folder()
    verbose = args.verbose

    operation = {'configure': configure,
                 'build':     build,
                 'install':   install,
                 'test':      test,
                 'clean':     clean,
                 'doc':       make_doc}

    try:
        operation[args.command](args)
    except BuildError as e:
        print(e)

if __name__ == '__main__':
    main()
