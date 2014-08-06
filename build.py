#!/usr/bin/env python

from __future__ import print_function

if __name__ == '__main__':
    import sys

    if sys.hexversion < 0x02070000:  # TODO: test it on at least 2.5
        print("Sorry, this build script requires Python 2.7 or later.")
    else:
        try:
            from cantrell.utilities import BuildError
            from cantrell.builder import run_builder

            try:
                run_builder()
            except BuildError:
                print(sys.exc_info()[1])
                exit(1)  # Build failed!
        except ImportError:
            print("Please ensure the following modules are installed:")
            print("\n    argparse    (< 2.7)", end='')
            print("\n    hashlib     (< 2.5)", end='')
            print("\n", end='')
            exit(1)
