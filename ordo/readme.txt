Ordo
----

This directory contains a bunch of code files and headers for Ordo, along with a test unit. The end result will be a static/dynamic library, but for now it's just attached to a simple console program for tests.

Current work is focused towards finishing the cipher interface. Important todo's:
 - implement all encryption-only modes of operation
 - implement a couple cipher primitives (algorithms) to work with, such as AES, Threefish and RC5
 - improve error handling

Other todo's to keep in mind:
 - implement secure memory erasing by adding a better erasing pattern in sfree()

Documentation: The code in a few headers is documented for Doxygen.

:::Current status and what needs to be done:::

CIPHERS > Modes of operation implemented: ECB, OFB, CFB, CTR, STREAM
CIPHERS > Primitives implemented: Identity, XORToy, Threefish-256, RC4
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

It is not yet clear how stream ciphers fit into this scheme, they may require a different interface if they can't be woven in as a primitive. But who uses dedicated stream ciphers anymore? I have implemented RC4 with a degenerate 1-byte block cipher using a dedicated "mode of operation" (STREAM), but I am not sure if this is flexible enough.

--------

Please note these ciphers:
- "Identity": this is a test cipher which does absolutely nothing and is only used to test if the rest of the library works
- "XORToy": this is a test cipher which does a simple byte-to-byte XOR with 0x5A and is only used for testing the library

Obviously, they should not be used for any other purpose (you knew that) and should be deleted when the library is finished anyhow.