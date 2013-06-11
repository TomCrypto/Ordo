ASM = $(subst .S,.o,$(subst src/,obj/,$(shell find src/ -name '*.S')))
OBJ = $(subst .c,.o,$(subst src/,obj/,$(shell find src/ -name '*.c')))
HEADERS = $(shell find include/ -name '*.h')
TARGET = libordo.so
LDFLAGS = -shared
CC = gcc

CFLAGS_DEBUG = -fpic -O0 -D ORDO_DEBUG -ggdb \
               -Wall -Wno-implicit-function-declaration -Wno-long-long \
               -pedantic -pipe

CFLAGS_RELEASE = -fpic -O6 -march=native -mno-avx \
                 -Wall -Wno-implicit-function-declaration -Wno-long-long \
                 -pedantic -pipe

# Sets DEBUG to 0 if it hasn't been set by command-line (e.g. make DEBUG=1)
DEBUG ?= 0
ifeq ($(DEBUG), 1)
	CFLAGS = $(CFLAGS_DEBUG)
else
	CFLAGS = $(CFLAGS_RELEASE)
endif

debug: $(TARGET)

$(TARGET): $(OBJ) $(ASM)
	@mkdir -p lib/
	@$(CC) $(LDFLAGS) $(OBJ) $(ASM) -o $(addprefix lib/, $(TARGET))

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
