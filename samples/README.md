Ordo
====

Code Samples
------------

These are some code samples for Ordo. To build them from here, just hit "make [name of sample]". A brief description of each sample follows:

**md5sum**: a very simple clone of the popular `md5sum` utility.

**encrypt**: a basic file encryption/decryption tool.

Please note those are only *samples* to demonstrate how the API works, and should not be taken as an example of actual applications to write.

If you are building them using the shared library (`libordo.so`), you will need to run them from this directory, due to how shared libraries work (in general they are installed into `/usr/lib` after being built, but Ordo doesn't do that yet)
