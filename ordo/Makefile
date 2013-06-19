ASM = $(subst .S,.o,$(subst src/,obj/,$(shell find src/ -name '*.S')))
OBJ = $(subst .c,.o,$(subst src/,obj/,$(shell find src/ -name '*.c')))
HEADERS = $(shell find include/ -name '*.h')
TARGET = libordo.a # shared library: libordo.so
LDFLAGS = ar rcs # shared library: -shared
CC = gcc

# add -fpic for shared library
CFLAGS_DEBUG = -O0 -D ORDO_DEBUG -ggdb \
               -Wall -Wno-implicit-function-declaration -Wno-long-long \
               -pedantic -pedantic-errors -pipe

CFLAGS_RELEASE = -O6 -march=native -mno-avx \
                 -Wall -Wno-implicit-function-declaration -Wno-long-long \
                 -pedantic -pedantic-errors -pipe

# Sets DEBUG to 0 if it hasn't been set by command-line (e.g. make DEBUG=1)
DEBUG ?= 0
ifeq ($(DEBUG), 1)
	CFLAGS = $(CFLAGS_DEBUG)
else
	CFLAGS = $(CFLAGS_RELEASE)
endif

debug: $(TARGET)

# for shared library
# $(CC) $(LDFLAGS) $(OBJ) $(ASM) -o $(addprefix lib/, $(TARGET))

$(TARGET): $(OBJ) $(ASM)
	@mkdir -p lib/
	ar -cvq $(addprefix lib/, $(TARGET)) $(OBJ) $(ASM)

$(OBJ): obj/%.o : src/%.c $(HEADERS)
	@mkdir -p $(@D)
	@$(CC) $(CFLAGS) -Iinclude/ -c $< -o $@

$(ASM): obj/%.o : src/%.S $(HEADERS)
	@mkdir -p $(@D)
	@$(CC) $(CFLAGS) -Iinclude/ -c $< -o $@

documentation:
	@doxygen Doxyfile

clean:
	@rm -f obj/ --recursive
	@rm -f lib/ --recursive
