Ordo v2.1.0
===========

Symmetric Cryptography Library
------------------------------

This is the github repository for Ordo, a minimalist cryptography library with an emphasis on symmetric cryptography, which strives to meet high performance, portability, and security standards, while remaining modular in design to facilitate adding new features and maintaining existing ones. The library is written in standard C, but some sections are assembly-optimized for performance. Note that while the library is technically usable at this point, it is still very much a work in progress and mustn't be deployed in security-sensitive applications.

Status
------

Ordo v2 is out! It's not completely finished but the library has just undergone a major overhaul. Enjoy.

What's new in 2.1:
 - much better memory allocation, zero reliance on mlock (fixed static buffer, very efficient and not very restrictive because of typical allocation patterns used by the library)
 - lots of various consistency and refactoring improvements

A basic test driver has been implemented, which reads a test vector file (see vectors file) by parsing a simple script. It allows to see if Ordo is correctly running at a glance - if you fail a test vector or get a segfault, you have a problem. Read the vectors file (in the test program) and the test driver's code to know more about this.

The design of the library is to have cryptographic primitives (be it cipher primitives, or hash primitives, etc...) be accessible from everywhere in the code, so that different modules are able to access them transparently (like encrypting, hashing, authenticating, encrypting+authenticating, etc...). Suggested library module names:

primitives -> contains declarations for all crypto primitives (block and stream ciphers, hashes, etc...)
enc -> for encryption only (either using block ciphers with modes of operation (CBC, CTR, etc...) via enc_block, or with stream ciphers with enc_stream)
hash -> for hashing/digest operations (MD5, Skein, etc...)
auth -> for authentication-only modes of operation (HMAC, VMAC, etc...)
encauth -> for encryption+authentication modes (GCM, CCM, etc...)
random -> for pseudorandom number generation (using the OS-provided CSPRNG)

This way every part of the library is cleanly separated yet can share cryptographic code. It is not clear yet how much abstraction can be obtained from each individual section of the library - for block and stream cipher encryption the abstraction level is very high as block cipher modes of operation are quite modular and stream ciphers can literally be swapped in and out at will, but for "hash" for instance it will be much lower by the very nature of how hash functions are designed.

Feature Map
-----------

Essentially finished features are in **bold**, features currently in progress are in *italic*, and planned features are in standard font.

* **random**
* *primitives*
    * *block_ciphers*
        * **NullCipher**
        * **Threefish-256**
        * *AES*
    * *stream_ciphers*
        * **RC4**
    * *hash_functions*
        * **SHA-256**
        * **MD5**
        * *Skein-256*
    * misc
* **enc**
    * **enc_block**
        * **ECB**
        * **CBC**
        * **CTR**
        * **CFB**
        * **CFB**
    * **enc_stream**
* **hash**
* *auth*
    * **hmac**
* *kdf*
    * *PBKDF2 (w/ HMAC)*
* encauth
* *testing (test drivers)*
    * *vectors*
    * *performance*

This doesn't include every single feature but gives a high level overview:

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

Alternatively, you can consult the online documentation at the [project page](http://tomcrypto.github.com/Ordo/), though it may not be completely up to date.

How To Build & Compatibility
----------------------------

As Ordo is somewhat environment-dependent (it needs to know, among others, the target operating system for some platform-specific API's such as memory locking, and the target processor's endianness and native word size for processor-specific optimizations) we use a custom makefile to facilitate the build process. The makefile *requires* the `gcc` compiler (or a port of it, for instance `mingw` with a working shell environment such as `MSYS`). The makefile is *not* set up for cross-compiling and you will need to set this up yourself if you wish to build for different operating systems. If you are building for the current operating system, then you may tweak the processor architecture and Ordo will optimize accordingly, but unless you know what you are doing you should just build for your current system.

In general, Ordo expects to be given the following information:

* Operating system, along with various system functions. This is provided by `gcc` and Ordo will automatically select the right codepath based on the operating system `gcc` is reportedly building on.
* Endianness. This is provided by the system libraries, or inferred from the operating system (e.g. Windows is always little-endian). Byte-swapping functions need not be available as Ordo has its own fallback functions, but are recommended for efficiency.
* Processor architecture. This is, again, provided by `gcc` based on compilation flags restricting or enabling instruction sets and other features.

The makefile is used as follows:

    make extra=[arguments to gcc]

Where the `extra` argument is used to refine processor specification. For instance, if your processor supports the AES-NI instructions, you will want to pass `extra="-maes"`. If you want full optimization for your own system, you will want to provide `extra="-march=native"`. Those are passed directly to `gcc` so you can provide extra architecture information if you have more information on your target processor, in order to optimize the library further.

If your operating system is supported by Ordo, it *will run* as everything has a standard C code path. However, if specific optimizations are not available for your system and/or processor architecture, performance may not be ideal.

Finally, there are a few additional configuration options possible:

* `make strip=1` will strip symbols from the the built libraries using the `strip` tool, generally making them a bit smaller.
* `make debug=1` will enable the debug build functionality, which will disable all optimizations and assembly code paths, and enable `gdb` symbols. By default, debug mode is not enabled.
* `make shared=1` will build a shared library (`libordo.so`) instead of a static one (`libordo.a`) by default. Note that you will need to `make clean` if you want to change from a static to a shared library, as the object files are not compatible between both library types (shared libraries require position independent code whereas static ones don't).

To build and run the tests, use `make tests` and `make run_tests`. To build the samples, use `make samples`. The samples will be built into the `samples/bin` directory where you can try them out. Note the `shared`, `debug`, and `strip` arguments also apply to the tests and samples.

For most uses, the build process should go like this:

    make
    make doc
    make tests
    make run_tests # here, check it works properly
    make samples

Finally, `make clean` will remove all generated files in the repository, leaving behind only original content.

Conclusion
----------

Of course, do not use Ordo for anything other than testing or contributing for now! It can only be used once it has been completed and extensively checked (and even then, there may still be flaws and bugs, as in any other software).
