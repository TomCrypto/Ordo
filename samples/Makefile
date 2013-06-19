LIBINCLUDE = ../ordo/include/
LIBHEADERS = $(shell find $(LIBINCLUDE) -name '*.h')
LIBPATH = ../ordo/lib/
CC = gcc

CFLAGS = -O2 -Wall -Wextra -pedantic -pedantic-errors -pipe

# use libordo.so for shared library

md5sum:
	mkdir -p bin/
	$(CC) src/md5sum.c -o bin/md5sum -I$(LIBINCLUDE) $(addprefix $(LIBPATH), libordo.a)

encrypt:
	mkdir -p bin/
	$(CC) src/encrypt.c -o bin/encrypt -I$(LIBINCLUDE) $(addprefix $(LIBPATH), libordo.a)

clean:
	@rm -f bin/ --recursive
