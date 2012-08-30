# Debug flags (no optimization, native feature flags, warnings, and ordo debug flag)
CFLAGS_DEBUG = -O0 -Wall -Wno-implicit-function-declaration -march=native -mno-avx -D ORDO_DEBUG -ggdb

# Release flags (full optimization, native feature flags, warnings)
CFLAGS_RELEASE = -O6 -Wall -Wno-implicit-function-declaration -march=native -mno-avx

# The default build target is release
default: release

# Simply push all the source files (+ assembler files) to gcc and build/link. Make sure /bin/debug exists...
debug: $(shell find src/ -name '*.c')
	@mkdir bin -p
	@mkdir bin/debug -p
	gcc -Iinclude/ $(CFLAGS_DEBUG) -o ./bin/debug/ordo $(shell find src/ -name '*.c') $(shell find src/ -name '*.S')
	@echo "\n[#] Ordo built in <debug> mode."

# Simply push all the source files (+ assembler files) to gcc and build/link. Make sure /bin/release exists...
release: $(shell find src/ -name '*.c')
	@mkdir bin -p
	@mkdir bin/release -p
	gcc -Iinclude/ $(CFLAGS_RELEASE) -o ./bin/release/ordo $(shell find src/ -name '*.c') $(shell find src/ -name '*.S')
	@echo "\n[#] Ordo built in <release> mode."

# Removes the executables and folders
clean:
	@rm -f ./bin/ --recursive
