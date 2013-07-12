Ordo
====

Test Driver
-----------

This folder contains a test driver for the Ordo library, which will run various tests in order to verify that it is working correctly. The results will be displayed in a table, showing the number of tests passed (and if any failed). Any failed test indicates the library is not working and should be reported and/or fixed. Remember to build with `shared=1` (in the makefile) if you want to link to a shared library instead of a static one, and `nopthread=1` if you do not require `pthread` support.

The test driver can use colors to help you visually parse the output - which may be quite long - if your terminal supports it. To enable this, pass the `-color` flag as an argument to the program, such as:

    ./bin/tests -color

The test driver can also output extended test information (to debug any failures) which may be enabled by passing the `-extended` argument:

    ./bin/tests -extended

If this argument is passed, the extended information will be output to `stderr`, whereas the table is output to `stdout`. Since `stderr` is by default redirected to `stdout`, it is recommended to redirect either `stdout` or `stderr` (or both) to different locations, as the two streams don't look all that nice interleaved.
