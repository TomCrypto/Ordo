#!/usr/bin/env python

from __future__ import print_function

if __name__ == '__main__':
    import sys

    if sys.hexversion < 0x02030000:
        print("Sorry, this build script requires Python 2.3 or later.")
    else:
        try:
            from cantrell.main import BuildError, run

            try:
                run()
            except BuildError:
                print(sys.exc_info()[1])
                exit(1)  # Build failed!
        except ImportError:
            print("Please ensure the following modules are installed:")
            print("\n    argparse    (< 2.7)", end='')
            print("\n    hashlib     (< 2.5)", end='')
            print("\n", end='')
            exit(1)
