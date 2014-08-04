from __future__ import print_function, division
from argparse import ArgumentParser
import argparse, pickle

from cantrell.utilities import *
from cantrell.detection import *

import cantrell.makefile as makefile

generate    = {'makefile': makefile.gen_makefile}
run_build   = {'makefile': makefile.bld_makefile}
run_install = {'makefile': makefile.ins_makefile}
run_tests   = {'makefile': makefile.tst_makefile}

class BuildContext:
    def __init__(self, args):
        """This function simply copies the arguments into a build context."""
        self.lto = args.lto
        self.compat = args.compat

        cc = get_c_compiler() if args.compiler is None else args.compiler[0]
        self.compiler, self.compiler_info = get_compiler_id(cc)

        self.platform = args.platform[0]
        self.arch = args.arch[0]

        if self.arch == 'generic':  # We won't need an assembler here
            if args.assembler is not None:
                log('info', "Assembler not required for generic arch.")
        else:
            if args.assembler is not None:
                if is_program(args.assembler[0], 'nasm'):
                    self.assembler = args.assembler[0]
                else:
                    log('warn', "Assembler {0} does not appear to be NASM.",
                        args.assembler[0])
            else:
                self.assembler = find_nasm()
                
                if self.assembler is None:
                    raise BuildError("Failed to find assembler!")

            if self.assembler is not None:
                self.obj_format = get_obj_format(self.platform, self.arch)

        self.features = []
        if args.aes_ni:
            self.features.append('aes_ni')

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
    
    if ctx.arch != 'generic':
        print("Assembler is: {0}.".format(get_version(ctx.assembler)))

    ctx.out = 'makefile'

    with open(path.join(build_dir, build_ctx), mode='wb') as f:
        pickle.dump(ctx, f)

    return ctx


def make_doc(args):
    """Attempts to generate documentation by calling doxygen."""
    if not program_exists('doxygen'):
        raise BuildError("Doxygen is required to build the documentation")
    else:
        with chdir('doc'):
            run_cmd('doxygen', stdout_func=stream)


def clean_build():
    """Deletes the build folder and recreates an empty one."""
    shutil.rmtree(build_dir)
    regenerate_build_folder()

def run_builder():
    global verbose

    master = ArgumentParser(description="Build script for the Ordo library.")
    parsers = master.add_subparsers(dest='command')  # One for each command

    cfg = parsers.add_parser('configure', help="configure the library")
    bld = parsers.add_parser('build',     help="build one or more targets")
    ins = parsers.add_parser('install',   help="install library on system")
    tst = parsers.add_parser('test',      help="run the Ordo test driver")
    cln = parsers.add_parser('clean',     help="remove all build files")
    doc = parsers.add_parser('doc',       help="generate documentation")

    cfg.add_argument('--prefix', nargs=1, type=str, metavar='',
                     help="path into which to install files",
                     default=get_default_prefix())

    cfg.add_argument('-c', '--compiler', nargs=1, type=str, metavar='',
                     help="path to C compiler to use for building")

    cfg.add_argument('-q', '--assembler', nargs=1, type=str, metavar='',
                     help="path to assembler to use for building")

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
                     help="set of targets to build")

    master.add_argument('-v', '--verbose', action='store_true',
                        help="display additional information")

    args = master.parse_args()
    regenerate_build_folder()
    verbose = args.verbose
    cmd = args.command

    # TODO: Add all of the special parameters, and verify the script
    #       works everywhere on linux/bsd/mac with gcc. E.g.
    #       ctx.obj_format on mac.
    #
    #       Then, improve the function to find programs on the filesystem.
    #
    #       Debug the script (using makefiles/mingw) on Windows.
    #
    #       Implement VS solution generation on Windows.

    if cmd in ['configure']:
        if path.exists(path.join(build_dir, build_ctx)):
            log('info', 'Already configured, cleaning')
            clean_build()

        ctx = configure(args)
        with chdir(build_dir):
            generate[ctx.out](ctx)
    elif cmd in ['build', 'install', 'test']:
        if not path.exists(path.join(build_dir, build_ctx)):
            raise BuildError("Please configure before '{0}'.".format(cmd))
        else:
            with open(path.join(build_dir, build_ctx), 'rb') as f:
                ctx = pickle.load(f)

        if cmd == 'build':
            for target in args.targets:
                if not target in ['static', 'shared', 'test', 'samples']:
                    raise BuildError("Bad target '{0}'.".format(target))
        
            with chdir(build_dir):
                run_build[ctx.out](ctx, args.targets)
        elif cmd == 'install':
            with chdir(build_dir):
                run_install[ctx.out](ctx)
        elif cmd == 'test':
            with chdir(build_dir):
                run_tests[ctx.out](ctx)
    elif cmd in ['doc']:
        make_doc(args)
    elif cmd in ['clean']:
        clean_build()
