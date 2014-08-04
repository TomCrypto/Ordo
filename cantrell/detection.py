from __future__ import print_function, division

from cantrell.utilities import *

import subprocess
import platform
import os, sys
import shutil


platform_list = ['generic', 'linux', 'win32', 'darwin', 'freebsd', 'openbsd', 'netbsd']

arch_list = ['generic', 'amd64']

feature_list = ['generic', 'aes_ni']


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
        return '/usr/local/bin'
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
        raise BuildError('No assembler format for {0}'.format(arch))

def program_exists(name):
    try:
        run_cmd(name, [])
        return True
    except (IOError, OSError):
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
    out2 = run_cmd(compiler, ['-v'])[1]
    header = out.split('\n')[0]

    if ('intel' in out.lower()) or ('intel' in out2.lower()):
        return ('intel', header)
    if ('clang' in out.lower()) or ('clang' in out2.lower()):
        return ('clang', header)
    if ('gcc' in out.lower()) or ('gcc' in out2.lower()):
        return ('gcc', header)
    if ('msvc' in out.lower()) or ('msvc' in out2.lower()):
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
