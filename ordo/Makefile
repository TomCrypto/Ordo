# Debug flags (no optimization, native feature flags, warnings, and ordo debug flag)
CFLAGS_DEBUG = -O0 -Wall -Wno-implicit-function-declaration -pedantic -pipe -march=native -mno-avx -D ORDO_DEBUG -ggdb

# Release flags (full optimization, native feature flags, warnings)
CFLAGS_RELEASE = -O6 -Wall -Wno-implicit-function-declaration -pedantic -pipe -march=native -mno-avx

# The default build target is release
default: release

# Simply push all the source files (+ assembler files) to gcc and build/link. Make sure the lib/ folder exists...
debug: $(shell find src/ -name '*.c')
	@mkdir lib -p
	gcc -shared -fpic -Iinclude/ $(CFLAGS_DEBUG) -o lib/libordo.so $(shell find src/ -name '*.c') $(shell find src/ -name '*.S')
	@echo "\n[#] Ordo built in <debug> mode."

# Simply push all the source files (+ assembler files) to gcc and build/link. Make sure the lib/ folder exists...
release: $(shell find src/ -name '*.c')
	@mkdir lib -p
	gcc --shared -fpic -Iinclude/ $(CFLAGS_RELEASE) -o lib/libordo.so $(shell find src/ -name '*.c') $(shell find src/ -name '*.S')
	@echo "\n[#] Ordo built in <release> mode."

# Generate the doxygen documentation
documentation:
	@doxygen Doxyfile
	@echo "\n[#] Ordo documentation generated."

# Removes the shared library
clean:
	@rm -f ./lib/ --recursive
