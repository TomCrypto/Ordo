Ordo [NZT 18:33 8/01/2012]
----

This directory contains a bunch of code files and headers for Ordo, along with a test unit. The end result will be a static/dynamic library, but for now it's just attached to a simple console program for tests. Currently it includes a .cbp (Code::Blocks Project) file for your convenience and because I see no need to use a manual makefile here, but it should be easy to write/generate a makefile later on.

Current work is focused towards finishing the cipher interface. Important todo's:
 - improve error handling (this is VERY important, the current handling code is inconsistent and more or less fubar)
 - improve stream mode speed by batching up stream calls in groups instead of naively going through the buffer byte by byte
 - implement a couple cipher primitives (algorithms) to work with, such as AES, Threefish and RC5

Other todo's to keep in mind:
 - implement secure memory erasing by adding a better erasing pattern in sfree()

Documentation: The code in a few headers is documented for Doxygen. The doxyfile is not included but can easily be regenerated (it's just a configuration file).

:::Current status and what needs to be done:::

CIPHERS > Modes of operation implemented: ECB, CBC, OFB, CFB, CTR, STREAM
CIPHERS > Primitives implemented: NullCipher, Threefish-256, RC4
/!\ These have not been extensively checked for correctness! /!\
CIPHERS > The API is actually usable at this stage, but still not definitive, parameters will be shuffled around and modified to improve effectiveness and flexibility.

Essentially we want primitives (be it cipher primitives, or hash primitives, etc...) to be accessible from everywhere in the library, and we want different uses to be able to access them transparently (like encrypting, hashing, authenticating, encrypting+authenticating, etc...). Suggested library section names:

primitives -> contains declarations for all crypto primitives (ciphers, hashes, etc...)
encrypt -> for encryption-only modes of operation (CBC, CTR, etc...)
hash -> for hashing modes of operation (MD5/MD, Skein/UBI, etc...)
auth -> for authentication-only modes of operation (HMAC, VMAC, etc...)
encauth -> for encryption+authentication modes (GCM, CCM, etc...)
random -> for pseudorandom number generation (using the OS-provided CSPRNG)

This way every part of the library is cleanly separated yet can share cryptographic code. It is not clear yet how much abstraction can be obtained from each individual section of the library - for "encrypt" the abstraction level is very high as block cipher modes of operation are quite modular, but for "hash" for instance it will be much lower by the very nature of how hash functions are designed.

It is not yet clear how stream ciphers fit into this scheme, they may require a different interface if they can't be woven in as a primitive. But who uses dedicated stream ciphers anymore? I have implemented RC4 with a degenerate 1-byte block cipher using a dedicated "mode of operation" (STREAM), and all stream ciphers should be able to be formalized in a similar fashion, but I am not sure if this is flexible enough.

--------

Please note that "NullCipher" is a test cipher which does absolutely nothing and is only used to test if the rest of the library works. Obviously, it should not be used for any other purpose (you knew that).

--------

The code on Github should normally be functional in some way (unless we screwed a commit up), but of course it has only been tested under a limited number of platforms, so you may have to patch up the code to make it work under your compiler/OS, as what shows up as warnings or hints for us may come up as errors for you. Tested platforms so far:

- Linux Mint 13 [64-bit] GCC w/ Code::Blocks

Of course, do not use Ordo for anything other than testing or contributing for now! It can only be used once it has been completed and extensively checked (and even then, there may still be flaws and bugs, as in any other software).
