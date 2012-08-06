# Debug flags (no optimization, no feature flags, warnings, C90 conformance, and ordo debug flag)
CFLAGS_DEBUG = -Wall -ansi=c90 -D ORDO_DEBUG

# Release flags (full optimization, native feature flags, warnings, and C90 conformance)
CFLAGS_RELEASE = -O6 -Wall -march=native

# The default build target is release
default: release

# Simply push all the source files (+ assembler files) to gcc and build/link. Make sure /bin/debug exists...
debug: $(shell find src/ -name '*.c')
	mkdir bin
	mkdir bin/debug
	gcc -Iinclude/ $(CFLAGS_DEBUG) -o ./bin/debug/ordo $(shell find src/ -name '*.c') $(shell find src/ -name '*.S')
	@echo "\n[#] Ordo built in <debug> mode."

# Simply push all the source files (+ assembler files) to gcc and build/link. Make sure /bin/release exists...
release: $(shell find src/ -name '*.c')
	mkdir bin
	mkdir bin/release
	gcc -Iinclude/ $(CFLAGS_RELEASE) -o ./bin/release/ordo $(shell find src/ -name '*.c') $(shell find src/ -name '*.S')
	@echo "\n[#] Ordo built in <release> mode."

# Removes the executables and folders
clean:
	rm -f ./bin/debug/ordo
	rm -f ./bin/release/ordo
	rmdir bin/debug
	rmdir bin/release
