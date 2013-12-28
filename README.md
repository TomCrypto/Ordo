Ordo v2.5.0
===========

Symmetric Cryptography Library
------------------------------

This is the github repository for Ordo, a minimalist cryptography library with an emphasis on symmetric cryptography, which strives to meet high performance, portability, and security standards, while remaining modular in design to facilitate adding new features and maintaining existing ones. The library is written in standard C with system-specific features, but some sections are assembly-optimized for efficiency. Note that while the library is technically usable at this point, it is still very much a work in progress and mustn't be deployed in security-sensitive applications.

Status
------

[![Build Status](https://travis-ci.org/TomCrypto/Ordo.png?branch=master)](https://travis-ci.org/TomCrypto/Ordo)

What's new in 2.5.0:
 - better build system
 - got rid of the custom allocator in the generic code path
 - completely revamped and finished public documentation
 - improved header dependencies between headers and source files
 - test driver updated accordingly
 - fixed a few logical errors in the public headers and implementation
 - official MSVC support
 - fixed benchmark sample to only measure throughput, not setup

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

Ordo is documented for Doxygen, and you can automatically generate all documentation by using the `doc` build target (if available). The HTML documentation will be generated in `doc/html` and the LaTeX documentation will be generated in `doc/latex` (note you need `pdflatex` and a working TeX environment for the latter to work).

How To Build
------------

We support recent versions of MSVC, GCC, MinGW, and Clang. Other compilers are not officially supported. The build system used is CMake, which has a few configuration options to tweak the library according to your needs. A `build` folder is provided for you to point CMake to.

- `LTO`: use link-time optimization, this should be enabled for optimal performance.
- `ARCH`: the architecture to use, pick the one most appropriate for your hardware.

Note the system is autodetected and automatically included in the build. Additional options, such as the use of special hardware instructions, may become available once an architecture is selected, if they are supported.

### Assembly Support

We use the NASM assembler for our assembly files. For Linux and other Unix-based operating systems this should work out of the box after installing the assembler. For MSVC on Windows using the Visual Studio generators, custom build rules have been setup to autodetect NASM and get it to automatically compile assembly files, but they may not necessarily work for all versions of Visual Studio.

### Static Linking

If you wish to link statically to the library, please define the `ORDO_STATIC_LIB` preprocessor token in your project so that the Ordo headers can configure themselves accordingly (otherwise, they will assume you are linking to a shared library, which may raise some unwelcome compiler warnings).

Compatibility
-------------

The library will run everywhere a C99 compiler (with `stdint.h` and a couple other C99 features) is available, however system-dependent modules will not be available without an implementation for these platforms. For better performance, specialized algorithm implementations may be available for your system and processor architecture, and are easy to integrate once written.

Conclusion
----------

Of course, do not use Ordo for anything other than testing or contributing for now! It can only be used once it has been completed and extensively checked (and even then, there may still be flaws and bugs, as in any other software).
