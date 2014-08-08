#!/usr/bin/env python

if __name__ == '__main__':
    import sys

    if sys.hexversion < 0x02050000:
        print("Sorry, this build script requires Python 2.5 or later.")
    else:
        try:
            from cantrell.builder import run_builder, BuildError

            try:
                run_builder()
            except BuildError:
                print(sys.exc_info()[1])
                exit(1)  # Build failed!
        except ImportError:
            print("Please ensure the following modules are installed:")
            print("\n    argparse    (< 2.7)")
            print("")
            exit(1)
