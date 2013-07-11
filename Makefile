LIBDIR = lib
OBJDIR = obj
SRCDIR = src
INCLUDE = include

CC ?= gcc
CFLAGS = -Wall -Wextra -Wno-unused-parameter \
         -std=c99 -pedantic -pedantic-errors

# Chooses the proper compiler flags to use based on debug
# or release. By default release, use `make debug=1 ...`.
ifeq ($(debug), 1)
	CFLAGS += -O0 -ggdb -D ORDO_DEBUG -D ORDO_DEBUG_MEM
else
	CFLAGS += -O3
endif

# Decides whether to build a shared or a static library.
# Use `make shared=1 ...` to build Ordo as a shared lib.
ifeq ($(shared), 1)
	LIBNAME = libordo.so
	LDFLAGS = -shared
	CFLAGS += -fpic
	LD = $(CC)
else
	LIBNAME = libordo.a
	LDFLAGS = rcs
	LD = ar
endif

# If you use `make strip=1`, the library will be stripped.
ifeq ($(strip), 1)
	STRIP = strip $(addprefix $(LIBDIR)/, $(LIBNAME)) --strip-unneeded
else
	STRIP = 
endif

# Add the extra arguments (if any)
CFLAGS += $(extra)

HEADERS = $(shell find $(INCLUDE)/ -name '*.h')
SRC = $(shell find $(SRCDIR)/ -name '*.c')
ASM = $(shell find $(SRCDIR)/ -name '*.S')
SRCOBJ = $(subst .c,.c.o,$(subst $(SRCDIR)/,$(OBJDIR)/,$(SRC)))
ASMOBJ = $(subst .S,.S.o,$(subst $(SRCDIR)/,$(OBJDIR)/,$(ASM)))
LIBPATH = $(addprefix $(LIBDIR)/, $(LIBNAME))
LIBPATH_A = $(addprefix $(LIBDIR)/, libordo.a)
LIBPATH_SO = $(addprefix $(LIBDIR)/, libordo.so)

default: $(OBJDIR) $(LIBDIR) $(LIBPATH) striplib

$(OBJDIR):
	@mkdir $@

$(LIBDIR):
	@mkdir $@

$(LIBPATH_A): $(SRCOBJ) $(ASMOBJ)
	$(LD) $(LDFLAGS) $(LIBPATH) $(SRCOBJ) $(ASMOBJ)

$(LIBPATH_SO): $(SRCOBJ) $(ASMOBJ)
	$(LD) $(LDFLAGS) $(SRCOBJ) $(ASMOBJ) -o $(LIBPATH)

$(OBJDIR)/%.c.o: $(SRCDIR)/%.c $(HEADERS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -I$(INCLUDE) -c $< -o $@

$(OBJDIR)/%.S.o: $(SRCDIR)/%.S $(HEADERS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -I$(INCLUDE) -c $< -o $@

# this is a no-op if "strip=1" is not provided
.PHONY: striplib
striplib:
	$(STRIP)

# make tests :: Builds the test driver
.PHONY: tests
tests:
	cd tests; make

# make clean_tests :: Cleans the test driver
.PHONY: clean_tests
clean_tests:
	cd tests; make clean

# make samples :: Builds all samples
.PHONY: samples
samples:
	cd samples; make all

# make clean_samples :: Cleans the samples
.PHONY: clean_samples
clean_samples:
	cd samples; make clean

# make clean_bin :: Removes all binary files
.PHONY: clean_bin
clean_bin:
	rm -rf $(LIBDIR)

# make clean_obj :: Removes all object files
.PHONY: cleanobj
clean_obj:
	rm -rf $(OBJDIR)

# make doc :: Builds documentation for Ordo
.PHONY: doc
doc:
	doxygen
	mkdir -p doc
	cd doc/latex; make
	cd doc; ln -s -f html/index.html doc.html
	cd doc; ln -s -f latex/refman.pdf doc.pdf

# make clean_doc :: Removes all documentation
.PHONY: clean_doc
clean_doc:
	rm -rf doc

# make clean :: Removes all generated files
.PHONY: clean
clean: clean_doc clean_bin clean_obj clean_tests clean_samples
	
