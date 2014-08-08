from __future__ import print_function, division

from os.path import basename
from os import path, mkdir
import os, sys, subprocess

verbose = False
build_dir = 'build'
build_ctx = '.context'


class BuildError(Exception):
    pass


def set_verbose(value):
    global verbose
    verbose = value


def cond(cnd, s, other=''):
    return s if cnd else other


def debug(fmt, *args, **kwargs):
    if verbose:
        print("> {0}".format(fmt.format(*args, **kwargs)))


def info(fmt, *args, **kwargs):
    print("> {0}".format(fmt.format(*args, **kwargs)))


def fail(fmt, *args, **kwargs):
    info(fmt, *args, **kwargs)
    raise BuildError("Build failed.")


def report_debug(prompt, fmt, *args, **kwargs):
    if verbose:
        print("> {0}: {1}".format(prompt, fmt.format(*args, **kwargs)))


def report_info(prompt, fmt, *args, **kwargs):
    print("> {0}: {1}".format(prompt, fmt.format(*args, **kwargs)))


def report_fail(prompt, fmt, *args, **kwargs):
    report_info(prompt, fmt, *args, **kwargs)
    raise BuildError("Build failed.")


def regenerate_build_folder():
    if not path.isdir(build_dir):
        os.mkdir(build_dir)

    with open(path.join(build_dir, '.gitignore'), 'w') as f:
        f.write('*\n!.gitignore\n')  # Recreate a .gitignore


class chdir:
    """Context manager for changing the current working directory"""
    def __init__(self, newPath):
        self.newPath = newPath

    def __enter__(self):
        self.savedPath = os.getcwd()
        os.chdir(self.newPath)

    def __exit__(self, etype, value, traceback):
        os.chdir(self.savedPath)


def stream(line):
    """Utility function for run_cmd which streams its input to stdout."""
    print(line, end='')


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
        print("Interrupt")
        return (-1, stdout)

    return (process.returncode, stdout)
