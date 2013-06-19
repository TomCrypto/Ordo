OBJ = $(subst .c,.o,$(subst src/,obj/,$(shell find src/ -name '*.c')))
HEADERS = $(shell find include/ -name '*.h')
LIBINCLUDE = ../ordo/include/
LIBHEADERS = $(shell find $(LIBINCLUDE) -name '*.h')
LIBPATH = ../ordo/lib/
TARGET = ordo
CC = gcc

CFLAGS_DEBUG = -O0 -Wall -Wextra -ggdb -pedantic -pedantic-errors -pipe
CFLAGS_RELEASE = -O2 -Wall -Wextra -pedantic -pedantic-errors -pipe

# Sets DEBUG to 0 if it hasn't been set by command-line (e.g. make DEBUG=1)
DEBUG ?= 0
ifeq ($(DEBUG), 1)
	CFLAGS = $(CFLAGS_DEBUG)
else
	CFLAGS = $(CFLAGS_RELEASE)
endif

debug: $(TARGET)

$(TARGET): $(OBJ) $(ASM)
	@mkdir -p bin/
	@$(CC) $(OBJ) -o $(addprefix bin/, $(TARGET)) $(addprefix $(LIBPATH), libordo.a) # .so for shared

$(OBJ): obj/%.o : src/%.c $(HEADERS) $(LIBHEADERS)
	@mkdir -p $(@D)
	@$(CC) $(CFLAGS) -I$(LIBINCLUDE) -Iinclude/ -c $< -o $@

clean:
	@rm -f obj/ --recursive
	@rm -f bin/ --recursive
