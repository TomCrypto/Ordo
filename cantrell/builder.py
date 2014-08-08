from __future__ import print_function, division

import cantrell.makefile as makefile
from cantrell.utilities import *
from cantrell.detection import *
import argparse, pickle, shutil

# Global configuration below, do not edit!
build_dir, build_ctx = 'build', '.context'
doc_dir = 'doc'

generate    = {'makefile': makefile.gen_makefile}
run_build   = {'makefile': makefile.bld_makefile}
run_install = {'makefile': makefile.ins_makefile}
run_tests   = {'makefile': makefile.tst_makefile}

output_list = [
    'makefile'
]


class BuildError(Exception):
    pass


class BuildContext:
    def __init__(self, args):
        """Parse the provided arguments into a new build context."""
        self.output = args.output[0]
        self.prefix = args.prefix
        self.shared = args.shared
        self.compat = args.compat
        self.lto    = args.lto

        # Special argument handling

        if self.lto and self.compat:
            raise BuildError("Link-time optimization and compatibility mode "
                             "are mutually exclusive, please pick one only!")

        report_info("Build output format", self.output)

        # Locate and identify the compiler

        if args.compiler is None:
            info("Looking for a C compiler...")
            self.cc = get_c_compiler()
            if not self.cc:
                info("Failed to find a C compiler, try with --compiler.")
                raise BuildError("Configuration error.")
        else:
            self.cc = args.compiler[0]


        found, self.compiler, self.compiler_info = identify_compiler(self.cc)

        if not found:
            info("Could not identify compiler, is it supported?")
            raise BuildError("Configuration error.")
        else:
            report_info("C compiler", "{0} ({1})", self.compiler, self.compiler_info)

        self.platform = args.platform[0]
        self.arch = args.arch[0]

        if self.arch == 'generic':  # We won't need an assembler here
            if args.assembler is not None:
                info("Assembler not required for generic arch.")
            self.assembler = None
            self.obj_format = None
        else:
            # Locate and identify the assembler

            if args.assembler is not None:
                if is_program(args.assembler[0], 'nasm'):
                    self.assembler = args.assembler[0]
                else:
                    info("Assembler {0} does not appear to be NASM.",
                         args.assembler[0])
            else:
                self.assembler = find_nasm()

            if self.assembler is not None:
                self.obj_format = get_obj_format(self.platform, self.arch)
                self.assembler_info = get_version(self.assembler)

        # Platform configuration

        report_info("Platform", "{0}", self.platform)
        report_info("Architecture", "{0}", self.arch)

        self.features = []
        if args.aes_ni:
            self.features.append('aes_ni')

        if len(self.features) > 0:
            report_info("Features", "{0}", ', '.join(self.features))
        else:
            report_info("Features", "(none)")

        # Assembler stuff (move this elsewhere)

        if (self.arch is not 'generic') and (self.assembler is not None):
            report_info("Assembler", "{0} ({1})", self.assembler, self.assembler_info)
        elif (self.arch is not 'generic') and (self.assembler is None):
            info("Assembler not found, build may fail (try with --assembler)")

        if self.platform in ['generic']:
            info("Compiling for generic platform, os_random/etc. unavailable")
            info("(platform autodetection might have failed, try --platform)")

            if args.endian is None:
                info("Please specify target endianness for generic platform")
                raise BuildError("Configuration error.")
            else:
                ctx.endian = args.endian[0]


def configure(args):
    """Generate and return a build context from the arguments."""
    ctx = BuildContext(args)

    with open(path.join(build_dir, build_ctx), mode='wb') as f:
        pickle.dump(ctx, f)

    return ctx


def make_doc(args):
    """Attempt to generate documentation by calling doxygen."""
    if not program_exists('doxygen'):
        raise BuildError("Doxygen is required to build the documentation")
    else:
        run_cmd('doxygen', stdout_func=stream)


def clean_build():
    """Delete the build folder and then recreate an empty one."""
    shutil.rmtree(build_dir), regenerate_build_folder(build_dir)


def run_builder():
    master = argparse.ArgumentParser(description="Ordo build script.")
    parsers = master.add_subparsers(dest='command')  # One per command

    cfg = parsers.add_parser('configure', help="configure the library")
    bld = parsers.add_parser('build',     help="build one or more targets")
    ins = parsers.add_parser('install',   help="install library on system")
    tst = parsers.add_parser('test',      help="run the Ordo test driver")
    cln = parsers.add_parser('clean',     help="remove all build files")
    doc = parsers.add_parser('doc',       help="generate documentation")

    cfg.add_argument('--prefix', nargs=1, metavar='',
                     help="path into which to install files",
                     default=get_default_prefix())

    cfg.add_argument('--compiler', nargs=1, metavar='',
                     help="path to C compiler to use for building")

    cfg.add_argument('--assembler', nargs=1, metavar='',
                     help="path to assembler to use for building")

    cfg.add_argument('--platform', nargs=1, metavar='',
                     help="operating system/platform to configure for",
                     default=[get_platform()], choices=platform_list)

    cfg.add_argument('--arch', nargs=1, metavar='',
                     help="architecture to configure for",
                     default=['generic'], choices=arch_list)

    cfg.add_argument('--endian', nargs=1, metavar='',
                     help="target endianness (for generic platform)",
                     default=None, choices=['little', 'big'])

    cfg.add_argument('-c', '--compat', action='store_true',
                     help="for (very) old compilers",
                     default=False)

    cfg.add_argument('-o', '--output', metavar='',
                     help="build output format to generate",
                     default=['makefile'], choices=output_list)

    cfg.add_argument('-l', '--lto', action='store_true',
                     help="use link-time optimization",
                     default=False)

    cfg.add_argument('-s', '--shared', action='store_true',
                     help="build a shared library",
                     default=False)

    cfg.add_argument('--aes-ni', action='store_true',
                     help="use the AES-NI hardware instructions",
                     default=False)

    bld.add_argument('targets', nargs=argparse.REMAINDER,
                     help="set of targets to build")

    master.add_argument('-v', '--verbose', action='store_true',
                        help="display additional information")

    regenerate_build_folder(build_dir)
    args = master.parse_args()
    set_verbose(args.verbose)
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
            debug('Already configured, cleaning')
            clean_build()

        ctx = configure(args)
        with chdir(build_dir):
            generate[ctx.output](ctx)
    elif cmd in ['build', 'install', 'test']:
        if not path.exists(path.join(build_dir, build_ctx)):
            raise BuildError("Please configure before '{0}'.".format(cmd))
        else:
            with open(path.join(build_dir, build_ctx), 'rb') as f:
                ctx = pickle.load(f)

        if cmd == 'build':
            for target in args.targets:
                if target not in ['static', 'shared', 'test', 'samples']:
                    raise BuildError("Bad target '{0}'.".format(target))

            with chdir(build_dir):
                run_build[ctx.output](ctx, args.targets)
        elif cmd == 'install':
            with chdir(build_dir):
                run_install[ctx.output](ctx)
        elif cmd == 'test':
            with chdir(build_dir):
                run_tests[ctx.output](ctx)
    elif cmd in ['doc']:
        with chdir(doc_dir):
            make_doc(args)
    elif cmd in ['clean']:
        clean_build()
