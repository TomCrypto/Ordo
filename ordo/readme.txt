Ordo
----

This is a dump of .c, .h (and possibly extra files like assembler files, if applicable) for Ordo.

So far only ciphers have been worked on, so ordo.c and ordo.h are empty and the test unit is hotwired to ciphers.h instead. The API is far from definitive (most of the work is going towards implementing correct modes of operation).

The test unit now kind of figures out stuff for itself and is quite effective. It tests all ciphers in all modes of operations when applicable (for now, 3 ciphers and 2 modes of operation).

The Threefish-256 cipher has been fully implemented (but not checked against test vectors yet!)

::TODO::
-> improve secure memory by using a structure which includes the memory size (I could not do it because of unexplained errors)
-> improve cipher API to handle errors better, etc...
-> implement more modes of operation and make sure they all work
-> implement secure memory erasing (right not it's just a memset zero, don't think it's enough)


Please note these ciphers:
- "Identity": this is a test cipher which does absolutely nothing and is only used to test if the rest of the library works
- "XORToy": this is a test cipher which does a simple byte-to-byte XOR with 0x5A and is only used for testing the library

Obviously, they should not be used for any other purpose (you knew that) and should be deleted when the library is finished anyhow.