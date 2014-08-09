from __future__ import with_statement, division

import subprocess
import platform
import tempfile
import os, sys

platform_list = ['generic', 'linux', 'win32', 'darwin', 'freebsd', 'openbsd', 'netbsd']

arch_list = ['generic', 'amd64']

feature_list = ['generic', 'aes_ni']

compiler_list = ['intel', 'clang', 'msvc', 'gcc']


def cond(cnd, s, other=''):
    return s if cnd else other


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


def get_default_prefix():
    if get_platform() in ['linux', 'darwin', 'freebsd', 'openbsd', 'netbsd']:
        return '/usr/local'
    elif get_platform() in ['win32']:
        return 'C:\\Program Files (x86)\\Ordo'
    elif get_platform() in ['generic']:
        return None


def is_program(path, name):
    """Detect whether the binary at path is the program called name."""
    out1 = run_cmd(path, ['-version'])[1].lower()
    out2 = run_cmd(path, ['-v'])[1].lower()
    if name.lower() in out1:
        return True
    if name.lower() in out2:
        return True
    return False


def get_version(path):
    """Returns the version/identifier string of a given program."""
    return run_cmd(path, ['-v'])[1].lower().split('\n')[0]


def find_program(paths, name):
    """Generalized function to find programs from potential paths."""
    for path in paths:
        if program_exists(path) and is_program(path, name):
            return path
    return None


def find_nasm():
    """Attempt to find the NASM assembler, return None on failure."""
    paths = ['nasm']

    if get_platform() == 'win32':
        paths.append('nasm.exe')
        paths.append('C:\\Program Files\\nasm\\nasm.exe')
        paths.append('C:\\Program Files (x86)\\nasm\\nasm.exe')

    return find_program(paths, 'nasm')


def get_obj_format(platform, arch):
    """Retrieves the correct object file format for the assembler."""
    if arch == 'amd64':
        if platform in ['linux', 'freebsd', 'netbsd', 'openbsd']:
            return 'elf64'
        elif platform in ['darwin']:
            return 'macho64'
        elif platform in ['win32']:
            return 'win64'
    else:  # No other architecture yet (add e.g. i386..)
        raise RuntimeError('No assembler format for %s' % arch)


def program_exists(name):
    try:
        run_cmd(name)
        return True
    except (IOError, OSError):
        return False


def get_c_compiler():
    """Returns the name of the default C compiler on the system."""
    if ("CC" in os.environ) and program_exists(os.environ['CC']):
        return os.environ['CC']

    if program_exists('gcc'):
        return 'gcc'

    if program_exists('cc'):
        return 'cc'

    # On Windows, maybe check for MSVC in one of the popular paths here

    return None


def identify_compiler(path):
    """Identify a compiler and return an (found, id, version) tuple."""
    if (path is None) or not program_exists(path):
        return (False, None, None)

    for version_arg in ['-v', '--version', '-V']:
        version_str =run_cmd(path, [version_arg])[1].split('\n')[0]

        for compiler in compiler_list:
            if compiler.lower() in version_str.lower():
                return (True, compiler, version_str)

    return (False, None, None)


def library_exists(compiler, library):
    fd, name = tempfile.mkstemp(suffix='.c')
    out_name = tempfile.mktemp(suffix='.out')

    with os.fdopen(fd, 'w') as f:
        f.write('int main(void){return 0;}\n')

    success = run_cmd(compiler, [name, '-o', out_name, library])[0] == 0
    if success:
        os.remove(out_name)
    os.remove(name)

    return success


def stream(line):
    """Utility function for run_cmd which streams its input to stdout."""
    sys.stdout.write(line)


def run_cmd(cmd, args=[], stdout_func=None):
    """Executes a shell command and returns its output (and errors)."""
    stdout = ''

    try:
        process = subprocess.Popen([cmd] + args,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT)

        for buf in iter(process.stdout.readline, ''):
            line = buf.decode('utf-8')

            if (not line):
                break
            if (stdout_func is not None) and stdout_func(line):
                break

            stdout += line

        stdout_buf = process.communicate()[0]
        final_line = stdout_buf.decode('utf-8')
        if final_line:
            if (stdout_func is not None):
                stdout_func(final_line)

            stdout += final_line
    except KeyboardInterrupt:
        sys.stdout.write("Interrupt")
        return (-1, stdout)

    return (process.returncode, stdout)
