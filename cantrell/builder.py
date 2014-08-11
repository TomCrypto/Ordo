from __future__ import with_statement
import cantrell.makefile as makefile
import cantrell.solution as solution
import os, argparse, pickle, shutil
from cantrell.detection import *

# Global configuration below, do not edit!
build_dir, build_ctx = 'build', '.context'
build_inv, gitignore = '..', '.gitignore'
doc_dir = 'doc'

generate    = {'makefile': makefile.gen_makefile,
               'solution': solution.gen_solution}
run_build   = {'makefile': makefile.bld_makefile,
               'solution': solution.bld_solution}
run_install = {'makefile': makefile.ins_makefile,
               'solution': solution.ins_solution}
run_tests   = {'makefile': makefile.tst_makefile,
               'solution': solution.tst_solution}

output_list = [
    'makefile',
    'solution'
]

class BuildError(Exception):
    pass


class chdir:
    """Context manager for changing the current working directory"""
    def __init__(self, new_path):
        self.new_path = new_path

    def __enter__(self):
        self.saved_path = os.getcwd()
        os.chdir(self.new_path)

    def __exit__(self, etype, value, traceback):
        os.chdir(self.saved_path)


def info(msg):
    sys.stdout.write("> %s\n" % (msg))


def report_info(prompt, msg):
    sys.stdout.write("> %s: %s\n" % (prompt, msg))


class BuildContext:
    def __init__(self, args):
        """Parse the provided arguments into a new build context."""
        self.output = args.output
        self.prefix = args.prefix
        self.shared = args.shared
        self.system = args.system
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
            report_info("C compiler", "%s (%s)" % (self.compiler, self.compiler_info))

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
                    info("Assembler %s does not appear to be NASM." % args.assembler[0])
            else:
                self.assembler = find_nasm()

            if self.assembler is not None:
                self.obj_format = get_obj_format(self.platform, self.arch)
                self.assembler_info = get_version(self.assembler)

        # Platform configuration

        report_info("Platform", "%s" % self.platform)
        report_info("Architecture", "%s" % self.arch)

        self.features = []
        if args.aes_ni:
            self.features.append('aes_ni')

        if len(self.features) > 0:
            report_info("Features", "%s" % ', '.join(self.features))
        else:
            report_info("Features", "(none)")

        # Assembler stuff (move this elsewhere)

        if (self.arch is not 'generic') and (self.assembler is not None):
            report_info("Assembler", "%s (%s)" % (self.assembler, self.assembler_info))
        elif (self.arch is not 'generic') and (self.assembler is None):
            info("Assembler not found, build may fail (try with --assembler)")

        if self.platform in ['generic']:
            info("Compiling for generic platform, os_random/etc. unavailable")
            info("(platform autodetection might have failed, try --platform)")

            if args.endian is None:
                info("Please specify target endianness for generic platform")
                raise BuildError("Configuration error.")
            else:
                self.endian = args.endian[0]


def configure(args):
    """Generate and return a build context from the arguments."""
    ctx = BuildContext(args)

    with open(os.path.join(build_dir, build_ctx), mode='wb') as f:
        pickle.dump(ctx, f)

    return ctx


def make_doc(args):
    """Attempt to generate documentation by calling doxygen."""
    if not program_exists('doxygen'):
        raise BuildError("Doxygen is required to build the documentation")
    else:
        run_cmd('doxygen', stdout_func=stream)


def recreate_build_folder():
    """Create an empty build folder with a gitignore file."""
    if not os.path.isdir(build_dir):
        os.mkdir(build_dir)

    with open(os.path.join(build_dir, gitignore), 'w') as f:
        f.write('*\n!%s\n' % gitignore)  # Write .gitignore.


def clean_build():
    """Delete the build folder and then recreate an empty one."""
    shutil.rmtree(build_dir)
    recreate_build_folder()


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

    cfg.add_argument('--system', nargs=1, metavar='',
                     help="operating system/platform to build on",
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
                     default='makefile', choices=output_list)

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

    args = master.parse_args()
    recreate_build_folder()
    cmd = args.command

    # TODO: Improve the functions to find programs on the filesystem.
    #
    #       Debug the script (using makefiles/mingw) on Windows.
    #
    #       Implement VS solution generation on Windows.

    if cmd in ['configure']:
        if os.path.exists(os.path.join(build_dir, build_ctx)):
            clean_build()

        ctx = configure(args)
        with chdir(build_dir):
            generate[ctx.output](ctx, build_inv)
    elif cmd in ['build', 'install', 'test']:
        if not os.path.exists(os.path.join(build_dir, build_ctx)):
            raise BuildError("Please configure before '%s'." % cmd)
        else:
            with open(os.path.join(build_dir, build_ctx), 'rb') as f:
                ctx = pickle.load(f)

        if cmd == 'build':
            for target in args.targets:
                if target not in ['static', 'shared', 'test', 'samples']:
                    raise BuildError("Bad target '%s'." % target)

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
