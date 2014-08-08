Ordo v0.4.0
===========

Symmetric Cryptography Library
------------------------------

This is the github repository for Ordo, a minimalist cryptography library with an emphasis on symmetric cryptography, which strives to meet high performance, portability, and security standards, while remaining modular in design to facilitate adding new features and maintaining existing ones. The library is written in standard C with system-specific features, but some sections are assembly-optimized for efficiency. Note that while the library is technically usable at this point, it is still very much a work in progress and mustn't be deployed in security-sensitive applications.

Status
------

[![Build Status](https://travis-ci.org/TomCrypto/Ordo.png?branch=master)](https://travis-ci.org/TomCrypto/Ordo)

What's new in 0.4.0:
 - replaced primitive query system with much better limit API

What's new in 0.3.4:
 - added HKDF, SHA-1
 - all hash functions now have a fixed, immutable output length, which simplifies code and reduces the likelihood of overflow or underflow (in exchange, HKDF can be used to stretch insufficiently large hash outputs in a safe and generic fashion - DRBG's are probably next on the list)
 - improved some of the hash function code, particularly the padding implementation
 - restored HMAC to apply hash parameters to the inner hash (result of the above)
 - added a `prim_default()` function to get default primitives
 - added some unit tests for a few modules (work in progress)
 - simplified the library implementation a bit
 - fixed a few bugs

TODO:
 - work on tests (!)
 - go over build system

Feature Map
-----------

This table doesn't include every single feature but gives a high level overview of what is available so far:

 Block Ciphers | Stream Ciphers | Hash Functions | Modes | Authentication | Key Derivation | Misc
 ------------- | -------------- | -------------- | ----- | -------------- | -------------- | ----
 AES           | RC4            | MD5            | ECB   | HMAC           | PBKDF2         | CSPRNG
 Threefish-256 | -              | SHA-1          | CBC   | -              | HKDF           | Curve25519
 -             | -              | SHA-256        | OFB   | -              | -              | -
 -             | -              | Skein-256      | CFB   | -              | -              | -
 -             | -              | -              | CTR   | -              | -              | -

How To Build
------------

Ordo uses a custom Python-based build system, accessible through the `build.py` script, and implemented in the `cantrell` folder (get it?) as an independent module. The build script requires Python 2.5 or later, however you may need to install one or two Python modules for versions prior to 2.7 - the script will display the required dependencies.

To build the library, first configure it, by typing:

    ./build.py configure [options ...]    (or 'python build.py', whatever your shell uses)

See the available configuration options with `--help`, which include compiler/platform/architecture/installation prefix options and various other useful tweaks. If no options are passed, the library will be built with the most generic configuration available (except it will build towards your operating system if it can detect it) and will by default produce a makefile in the `build` folder for most systems, and a Visual Studio solution for Windows. You may then directly use these, or instead type:

    ./build.py build [targets ...]

which will build the relevant targets, or all targets, if none are provided. Available targets are:

    static, shared, test, samples

You can install the library binaries and headers to your system (see `configure --prefix`) with:

    ./build.py install

The Doxygen documentation can be generated with the `doc` command (you will need `doxygen`, and `pdflatex` with a working TeX environment for the LaTeX output). The HTML documentation will be generated in `doc/html`, and the LaTeX documentation will be generated in `doc/latex`, which you can then typeset using the generated makefile. You can also access a recent version of the documentation online through the [project page](http://tomcrypto.github.io/Ordo/).

### Assembly Support

We use the [NASM](http://www.nasm.us/) assembler for our assembly files. For Linux and other Unix-based operating systems this should work out of the box after installing the assembler. For MSVC on Windows using the Visual Studio generators, custom build rules have been set up to autodetect NASM and get it to automatically compile assembly files, but they have not been tested (and may not necessarily work) for all versions of Visual Studio.

### Static Linking

If you wish to link statically to the library, please define the `ORDO_STATIC_LIB` preprocessor token in your project so that the Ordo headers can configure themselves accordingly (otherwise, they will assume you are linking to a shared library, which may raise some unwelcome compiler warnings as well as forbidding access to the internal headers).

Compatibility
-------------

The library will run everywhere a near-C89 compiler (i.e. with `stdint.h` and `long long` support) is available, however system-dependent modules will not be available without an implementation for these platforms. For better performance, specialized algorithm implementations may be available for your system and processor architecture. Python 2.5 or later is required for the build configuration process.

Conclusion
----------

Of course, do not use Ordo for anything other than testing or contributing for now! It can only be used once it has been completed and extensively checked (and even then, there may still be flaws and bugs, as in any other software).
