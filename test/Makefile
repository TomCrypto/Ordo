# Debug flags (no optimization and debug symbols on)
CFLAGS_DEBUG = -O0 -pedantic -pipe -ggdb

# Release flags (optimization on, no debug symbols)
CFLAGS_RELEASE = -O2 -pedantic -pipe

# Default build is release
default: release

# Simply compile all files and give gcc the libordo.so
debug: $(shell find src/ -name '*.c')
	@mkdir bin -p
	gcc -I../ordo/include/ -Iinclude/ $(CFLAGS_DEBUG) -o ./bin/ordo $(shell find src/ -name '*.c') ../ordo/lib/libordo.so
	@echo "\n[#] Test unit built in <debug> mode."

# Simply compile all files and give gcc the libordo.so
release: $(shell find src/ -name '*.c')
	@mkdir bin -p
	gcc -I../ordo/include/ -Iinclude/ $(CFLAGS_RELEASE) -o ./bin/ordo $(shell find src/ -name '*.c') ../ordo/lib/libordo.so
	@echo "\n[#] Test unit built in <release> mode."

# Removes the test unit
clean:
	@rm -f ./bin/ --recursive
