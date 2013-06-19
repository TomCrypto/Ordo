ordo v2.0.0
-----------

Symmetric cryptography library
------------------------------

This directory contains code and headers for the library Ordo, which is currently a work in progress. A simple makefile is provided and is used as follows:
- make DEBUG=1, which includes no optimizations and adds debug symbols
- make, adding all optimizations for maximum performance

There is a test driver shipped with the library, used to verify some test vectors to check the library is properly working, and run some performance tests. A few samples of how to use the library are also provided.

Documentation: The headers and assembly files are documented for Doxygen, the source files are not. The doxyfile is included, and the generated HTML documentation should be located in doc/html/index.html. For practical reasons, the documentation itself is not included in the repository and you will need to generate it yourself via doxygen. There is also "make documentation" which will attempt to call doxygen to automatically produce the documentation.

Status
------

Ordo v2 is out! It's not completely finished but the library has just undergone a major overhaul. Enjoy.

Planned features:
 - build system overhaul (probably using cmake)
 - reformatting, some implementation rewrites and finishing the documentation

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

Special Build Flags
-------------------

List of define flags to pass during compilation and their actions:
* **ORDO_DEBUG**: indicates this is a debug build, some specific features may be disabled if this flag is enabled (right now it has its own place in the version structure (see version.h) and just has the test program print out whether it is running a debug or release build of the library)

Compilation & Compatibility
---------------------------

The code on Github should normally be functional in some way (unless we screwed a commit up), but of course it has only been tested under a limited number of platforms, so you may have to patch up the code to make it work under your compiler/OS, as what shows up as warnings or hints for us may come up as errors for you. Ordo also features a different code path for 32-bit and 64-bit platforms and also based on CPU feature flags for special instructions (we strive to provide decent to excellent performance) which is probably a compatibility black hole, so bear with us until we've got it all sorted out.

GCC is the recommended compiler, as environmental symbols are somewhat compiler-dependent (but we will keep adding symbols as needed to increase compatibility).

Tested under:

- Linux Mint 14 [64-bit] GCC v4.7.2
- Windows 7 [32-bit] GCC v4.6.2 (MinGW)
- Windows 7 [64-bit] GCC v4.7.1 (MinGW)

Instructions for Linux: just use the makefile, and it should work out of the box. The C::B project file can be used too, if you have Code::Blocks installed.
Instructions For Windows:
  - if you use the makefiles (discouraged under Windows) you will need to edit them so that they work properly with whatever compiler you chose to use.
  - if you use the C::B project file, just disable the makefile and manually input the makefile settings into the project's build options, and add the DLL to the linker directories in the test program. Also change some output locations (use common sense) as C::B tends to make some assumptions on file paths. You should not have to change a single line of code except perhaps trivial compiler-specific things...

Conclusion
----------

Of course, do not use Ordo for anything other than testing or contributing for now! It can only be used once it has been completed and extensively checked (and even then, there may still be flaws and bugs, as in any other software).
