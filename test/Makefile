# Debug flags (no optimization and debug symbols on)
CFLAGS_DEBUG = -O0 -ggdb

# Release flags (optimization on, no debug symbols)
CFLAGS_RELEASE = -O2

# Default build is release
default: release

# Simply compile the main.c file and give it the libordo.so
debug: src/main.c
	@mkdir bin -p
	gcc -I../ordo/include/ $(CFLAGS_DEBUG) -o ./bin/ordo src/main.c ../ordo/lib/libordo.so
	@echo "\n[#] Test unit built in <debug> mode."

# Simply compile the main.c file and give it the libordo.so
release: src/main.c
	@mkdir bin -p
	gcc -I../ordo/include/ $(CFLAGS_RELEASE) -o ./bin/ordo src/main.c ../ordo/lib/libordo.so
	@echo "\n[#] Test unit built in <release> mode."

# Removes the test unit
clean:
	@rm -f ./bin/ --recursive
