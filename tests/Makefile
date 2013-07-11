TARGET = tests

BINDIR = bin
OBJDIR = obj
SRCDIR = src
INCLUDE = include

CC ?= gcc
CFLAGS = -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable \
         -pedantic -pedantic-errors

ifeq ($(nopthread), 1)
	LDFLAGS = 
else
    CFLAGS += -pthread
	LDFLAGS = -pthread
endif

# Chooses the proper compiler flags to use based on debug
# or release. By default release, use `make debug=1 ...`.
ifeq ($(debug), 1)
	CFLAGS += -O0 -ggdb
else
	CFLAGS += -O3
endif

# Decides whether to link to the Ordo shared library or not.
ifeq ($(shared), 1)
	ORDO_LIBNAME = libordo.so
else
	ORDO_LIBNAME = libordo.a
endif

ORDO_LIBDIR = ../lib/
ORDO_LIBPATH = $(addprefix $(ORDO_LIBDIR), $(ORDO_LIBNAME))
ORDO_INCLUDE = ../include/

HEADERS = $(wildcard $(INCLUDE)/*.h)
SRC = $(shell find $(SRCDIR)/ -name '*.c')
OBJ = $(subst .c,.o,$(subst $(SRCDIR)/,$(OBJDIR)/,$(SRC)))
BINPATH = $(addprefix $(BINDIR)/, $(TARGET))

default: $(OBJDIR) $(BINDIR) $(BINPATH)

$(OBJDIR):
	@mkdir $@

$(BINDIR):
	@mkdir $@

$(BINPATH): $(OBJ)
	$(CC) $(LDFLAGS) $(OBJ) -o $(BINPATH) $(ORDO_LIBPATH)

$(OBJDIR)/%.o: $(SRCDIR)/%.c $(HEADERS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -I$(INCLUDE) -I$(ORDO_INCLUDE) -c $< -o $@

# make cleanbin :: Removes all binary files
.PHONY: clean_bin
clean_bin:
	rm -rf $(BINDIR)

# make clean_obj :: Removes all object files
.PHONY: clean_obj
clean_obj:
	rm -rf $(OBJDIR)

# make clean :: Removes all generated files
.PHONY: clean
clean: clean_bin clean_obj
	
