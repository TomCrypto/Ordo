Ordo v3.0.0
===========

Symmetric Cryptography Library
------------------------------

This is the github repository for Ordo, a minimalist cryptography library with an emphasis on symmetric cryptography, which strives to meet high performance, portability, and security standards, while remaining modular in design to facilitate adding new features and maintaining existing ones. The library is written in standard C with system-specific features, but some sections are assembly-optimized for efficiency. Note that while the library is technically usable at this point, it is still very much a work in progress and mustn't be deployed in security-sensitive applications.

Status
------

[![Build Status](https://travis-ci.org/TomCrypto/Ordo.png?branch=master)](https://travis-ci.org/TomCrypto/Ordo)

What's new in 3.0.0:
 - completely new API, now fully static (no dynamic allocation ever happens), less indirection levels, and improved C89 conformance
 - renamed a few functions to reduce verbosity and namespace pollution (e.g. `hash_function_init` becomes `ordo_hash_init`) [WIP]
 - the test driver is being reworked (work in progress)
 - the HMAC module has been slightly changed to apply the hash parameters on the outer hash instance, which allows for variable output length parameters

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

Ordo is documented for Doxygen, and you can automatically generate all documentation by using the `doc` build target, if deemed available on your system (you will need `doxygen`, and `pdflatex` with a working TeX environment for the LaTeX output). The HTML documentation will be generated in `doc/html`, and the LaTeX documentation will be generated in `doc/latex`, which you can then typeset using the generated makefile.

You can also access a recent version of the documentation online through the [project page](http://tomcrypto.github.io/Ordo/).

How To Build
------------

We support recent versions of MSVC, GCC, MinGW, and Clang. Other compilers are not officially supported. The build system used is CMake, which has a few configuration options to tweak the library according to your needs. A `build` folder is provided for you to point CMake to. Python 2.x (probably 2.7+) is also required.

- `LTO`: use link-time optimization, this should be enabled for optimal performance.
- `ARCH`: the architecture to use, pick the one most appropriate for your hardware.
- `NATIVE`: tune the build for the current hardware (e.g. `-march` for GCC).
- `COMPAT`: remove some advanced compiler settings for older compiler versions (for GCC only, if this is enabled `LTO` has no effect)

Note the system is autodetected and automatically included in the build. Additional options, such as the use of special hardware instructions, may become available once an architecture is selected, if they are supported. Link-time optimization may not be available on older compilers (it will let you know).

If you are not using the `cmake-gui` utility, the command-line options to configure the library are:

    cd build && cmake .. [-DARCH=arch] [[-DFEATURE=on] ...] [-DLTO=off] [-DNATIVE=off] [-DCOMPAT=on]

For instance, a typical configuration for x86_64 machines with the AES-NI instructions could be:

    cd build && cmake .. -DARCH=amd64 -DAES_NI=on

The test driver is in the `test` folder, the sample programs are in the `samples` folder.

### Assembly Support

We use the NASM assembler for our assembly files. For Linux and other Unix-based operating systems this should work out of the box after installing the assembler. For MSVC on Windows using the Visual Studio generators, custom build rules have been set up to autodetect NASM and get it to automatically compile assembly files, but they have not been tested (and may not necessarily work) for all versions of Visual Studio.

### Static Linking

If you wish to link statically to the library, please define the `ORDO_STATIC_LIB` preprocessor token in your project so that the Ordo headers can configure themselves accordingly (otherwise, they will assume you are linking to a shared library, which may raise some unwelcome compiler warnings as well as forbidding access to the internal headers).

Compatibility
-------------

The library will run everywhere a near-C89 compiler (i.e. with `stdint.h` and `long long` support) is available, however system-dependent modules will not be available without an implementation for these platforms. For better performance, specialized algorithm implementations may be available for your system and processor architecture, and are easy to integrate once written.

The test driver requires partial C99 support (WIP), the build system requires CMake and Python (WIP)

Conclusion
----------

Of course, do not use Ordo for anything other than testing or contributing for now! It can only be used once it has been completed and extensively checked (and even then, there may still be flaws and bugs, as in any other software).
