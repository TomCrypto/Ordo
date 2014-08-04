from __future__ import print_function, division

from os import path, mkdir
from os.path import basename
from hashlib import sha256
import os, sys

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
    """Converts a filesystem path to a safe top-level file name."""
    if sys.hexversion >= 0x03000000:
        return '_'.join([sha256(s.encode('utf-8')).hexdigest()[:8], basename(s)])
    else:
        return '_'.join([sha256(s).hexdigest()[:8], basename(s)])


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
