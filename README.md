Ordo v2.3.0
===========

Symmetric Cryptography Library
------------------------------

This is the github repository for Ordo, a minimalist cryptography library with an emphasis on symmetric cryptography, which strives to meet high performance, portability, and security standards, while remaining modular in design to facilitate adding new features and maintaining existing ones. The library is written in standard C with system-specific features, but some sections are assembly-optimized for efficiency. Note that while the library is technically usable at this point, it is still very much a work in progress and mustn't be deployed in security-sensitive applications.

Status
------

[![Build Status](https://travis-ci.org/TomCrypto/Ordo.png?branch=master)](https://travis-ci.org/TomCrypto/Ordo)

What's new in 2.3:
 - fully implemented new unified query interface for gathering information from primitives and other modules such as key lengths, IV lengths, cipher block sizes (if needed), and so on, while avoiding having dozens of trivial functions scattered everywhere, and improving code consistency

Todo:
 - wrap stdint.h in a cross-platform header (for future portability concerns)

Feature Map
-----------

This table doesn't include every single feature but gives a high level overview of what is available so far:

 Block Ciphers | Stream Ciphers | Hash Functions | Modes | Authentication | Key Derivation | Misc
 ------------- | -------------- | -------------- | ----- | -------------- | -------------- | ----
 AES           | RC4            | MD5            | ECB   | HMAC           | PBKDF2         | CSPRNG
 Threefish-256 | -              | SHA-256        | CBC   | -              | -              | -
 -             | -              | Skein-256      | OFB   | -              | -              | -
 -             | -              | -              | CFB   | -              | -              | -
 -             | -              | -              | CTR   | -              | -              | -

Documentation
-------------

Ordo is documented for Doxygen, and you can automatically generate all documentation via `make doc`. The HTML documentation will be generated in `doc/html` and the LaTeX documentation will be generated in `doc/latex` (note you need `pdflatex` and a working LaTeX environment for this to work). Symlinks will be automatically created in the `doc` directory for your convenience.

Note that by default, internal headers and functions (which should never be used from outside the library except in very specific cases) *are* documented. To disable them, set `INTERNAL_DOCS` to `NO` in the `Doxyfile`. This will remove all internal code from the documentation.

How To Build
------------

As Ordo is somewhat environment-dependent (it needs to know, among others, the target operating system for some platform-specific API's such as memory locking, and the target processor's endianness and configuration for processor-specific optimizations) we use a custom makefile to facilitate the build process. The makefile is *not* set up for cross-compiling and you will need to set this up yourself if you wish to build for different operating systems. If you are building for the current operating system, then you may tweak the processor architecture and Ordo will optimize accordingly, but unless you know what you are doing you should just build for your current system.

The makefile is used as follows:

    make extra=[arguments to the compiler]

Where the `extra` argument is used to refine processor specification. For instance, if your processor supports the AES-NI instructions, you will want to pass `extra="-maes"`. If you want full optimization for your own system, you should probably use `extra="-march=native"`. Those are passed directly to the compiler so you can provide extra architecture information if you have more information on your target processor, in order to optimize the library further.

If your operating system is supported by Ordo, it *will run* as everything has a standard C code path. However, if specific optimizations are not available for your system and/or processor architecture, performance may not be ideal.

Finally, there are a few additional configuration options possible:

* `make strip=1` will strip symbols from the the built libraries using the `strip` tool, generally making them a bit smaller.
* `make debug=1` will enable the debug build functionality, which will disable all optimizations and assembly code paths, and enable debugging symbols. By default, debug mode is not enabled.
* `make shared=1` will build a shared library (`libordo.so`) instead of a static one (`libordo.a`) by default. Note that you will need to `make clean` if you want to change from a static to a shared library, as the object files are not compatible between both library types (shared libraries require position independent code whereas static ones don't).
* `make nopthread=1` will build the library without linking to `pthread`. Use this when you do not actually need the `pthread` mutex implementation, e.g. under Windows.

To build and run the tests, use `make tests` and run the executable in `tests/bin`. To build the samples, use `make samples`. The samples will be built into the `samples/bin` directory where you can try them out. Note the `shared` and `nopthread` makefile parameters also apply to the tests and samples, and they must be the same for the library and the tests/samples.

If you want to have both a static and a shared library, first do `make` to build the static library, then `make clean_obj` to remove the object files (but not the newly created library) and finally `make shared=1`. You should probably then do another `make clean_obj` to remove the object files for consistency.

For most uses, the build process should go like this:

    make
    make tests
    cd tests
    ./bin/tests # add "-color" if your terminal supports it

Finally, `make clean` will remove all generated files in the repository, leaving behind only original content.

Compatibility
-------------

The library has been tested against the following platforms:

* Linux i386, x86_64
* OpenBSD x86_64
* FreeBSD x86_64
* NetBSD i386
* Windows i386, x86_64

The following compilers are supported:

* gcc
* MinGW (use `msys` for the makefiles to work, and perhaps `CC=gcc` when invoking the makefile)
* Clang (should work out of the box with `-no-integrated-as` since Clang doesn't use the same assembler as gcc. To actually fix this, sanitize the assembly files to conform to the `llvm` assembler used by Clang - note the makefile does this automatically when it detects Clang is being used)

Conclusion
----------

Of course, do not use Ordo for anything other than testing or contributing for now! It can only be used once it has been completed and extensively checked (and even then, there may still be flaws and bugs, as in any other software).
