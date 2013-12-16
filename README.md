Ordo v2.4.0
===========

Symmetric Cryptography Library
------------------------------

This is the github repository for Ordo, a minimalist cryptography library with an emphasis on symmetric cryptography, which strives to meet high performance, portability, and security standards, while remaining modular in design to facilitate adding new features and maintaining existing ones. The library is written in standard C with system-specific features, but some sections are assembly-optimized for efficiency. Note that while the library is technically usable at this point, it is still very much a work in progress and mustn't be deployed in security-sensitive applications.

Status
------

[![Build Status](https://travis-ci.org/TomCrypto/Ordo.png?branch=master)](https://travis-ci.org/TomCrypto/Ordo)

What's new in 2.4.0:
 - new and improved build system, using CMake
 - MSVC semi-compatibility (see build notes)
 - explicit export symbols and calling conventions
 - a couple minor bug fixes (the API is unchanged)

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

Ordo is documented for Doxygen, and you can automatically generate all documentation by using the `doc` build target (if available). The HTML documentation will be generated in `doc/html` and the LaTeX documentation will be generated in `doc/latex` (note you need `pdflatex` and a working LaTeX environment for this to work).

Note that by default, internal headers and functions (which should never be used from outside the library except in very specific cases) *are* documented. To disable them, set `INTERNAL_DOCS` to `NO` in the `Doxyfile.in` file. This will remove all internal code from the documentation.

How To Build
------------

We support recent versions of MSVC, GCC, MinGW, and Clang. Other compilers are not officially supported. The build system used is CMake, which has a few configuration options to tweak the library according to your needs. A `build` folder is provided for you to point CMake to.

- STATIC_LIB: builds the library as a static library, in addition to the standard shared library build. Note the static library is suffixed with `_s`.
- NO_ASM: disables **all** assembly code paths in the library, and does not even include the assembly files in the build process.
- NATIVE_ARCH: tries to get the compiler to tune the library for the current system (e.g. `-march=native` or equivalent).
- NO_POOL: turns off the memory pool, requiring you to provide a custom allocator (experimental, do not use).

### Static Linking

If you wish to link statically to the library, please build it as a static library (this should be done automatically by CMake if you set the right option), and define the `ORDO_STATIC_LIB` preprocessor token in your project so that the Ordo headers can configure themselves accordingly (otherwise, they will assume you are linking to a shared library).

### MSVC and Assembly

The GCC, MinGW, and Clang compilers are able to process assembly source files as though they were ordinary C source files. MSVC does not, and will ignore the .S files completely (therefore only the `NO_ASM` build is technically supported out of the box). To make MSVC understand the assembly files, you will need to write custom build rules to send them to a third party assembler (such as `NASM`), and you will need to preprocess the assembly files to get them into the format expected by said assembler. We are working on a solution to automate this.

### Additional Notes

- On Windows, the tests and samples may require you to move the library's DLL around to make the resulting executables run.

Compatibility
-------------

The library has been tested against the following platforms:

* Linux i386, x86_64, ARMv5
* OpenBSD x86_64
* FreeBSD x86_64
* NetBSD i386
* Windows i386, x86_64
* Debian PowerPC (32-bit)
* Debian ARM (armv5tejl)

Conclusion
----------

Of course, do not use Ordo for anything other than testing or contributing for now! It can only be used once it has been completed and extensively checked (and even then, there may still be flaws and bugs, as in any other software).
