# Debug flags (no optimization, no feature flags, warnings, C90 conformance, and ordo debug flag)
CFLAGS_DEBUG = -Wall -ansi=c90 -D ORDO_DEBUG

# Release flags (full optimization, native feature flags, warnings, and C90 conformance)
CFLAGS_RELEASE = -O6 -Wall -march=native -ansi=c90

# The default build target is release
default: release

# Simply push all the source files (+ assembler files) to gcc and build/link
debug: $(wildcard *.c) $(wildcard *.S)
	gcc $(CFLAGS_DEBUG) -o ../bin/debug/ordo $(wildcard *.c) $(wildcard *.S)
	@echo "\n[#] Ordo built in <debug> mode."

# Simply push all the source files (+ assembler files) to gcc and build/link
release: $(wildcard *.c) $(wildcard *.S)
	gcc $(CFLAGS_RELEASE) -o ../bin/release/ordo $(wildcard *.c) $(wildcard *.S)
	@echo "\n[#] Ordo built in <release> mode."

# Removes the executable
clean:
	rm -f ../bin/debug/ordo
	rm -f ../bin/release/ordo
