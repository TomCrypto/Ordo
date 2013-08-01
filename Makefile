LIBDIR = lib
OBJDIR = obj
SRCDIR = src
INCLUDE = include

CC ?= gcc
CFLAGS = -Wall -Wextra \
         -Wno-unused-parameter \
         -std=c99 -pedantic -pedantic-errors

ifeq ($(nopthread), 1)
	LDFLAGS = 
else
	CFLAGS += -pthread
	LDFLAGS = -pthread
endif

# Chooses the proper compiler flags to use based on debug
# or release. By default release, use `make debug=1 ...`.
ifeq ($(debug), 1)
	CFLAGS += -O0 -ggdb -D ORDO_DEBUG
else
	CFLAGS += -O3
endif

# Adds the -no-integrated-as flag if using clang
ifeq ($(CC), clang)
    CFLAGS += -no-integrated-as
endif

# Decides whether to build a shared or a static library.
# Use `make shared=1 ...` to build Ordo as a shared lib.
ifeq ($(shared), 1)
	LIBNAME = libordo.so
	LDFLAGS += -shared
	CFLAGS += -fpic
	LD = $(CC)
else
	LIBNAME = libordo.a
	LDFLAGS = rcs # do not link -pthread!
	LD = ar
endif

# If you use `make strip=1`, the library will be stripped.
ifeq ($(strip), 1)
	STRIP = strip $(addprefix $(LIBDIR)/, $(LIBNAME)) --strip-unneeded
else
	STRIP = 
endif

CFLAGS += $(extra)

HEADERS = $(shell find $(INCLUDE)/ -name '*.h')
SRC = $(shell find $(SRCDIR)/ -name '*.c')
ASM = $(shell find $(SRCDIR)/ -name '*.S')
SRCOBJ = $(subst .c,.c.o,$(subst $(SRCDIR)/,$(OBJDIR)/,$(SRC)))
ASMOBJ = $(subst .S,.S.o,$(subst $(SRCDIR)/,$(OBJDIR)/,$(ASM)))
LIBPATH = $(addprefix $(LIBDIR)/, $(LIBNAME))
LIBPATH_A = $(addprefix $(LIBDIR)/, libordo.a)
LIBPATH_SO = $(addprefix $(LIBDIR)/, libordo.so)

default: $(OBJDIR) $(LIBDIR) $(LIBPATH)
	$(STRIP)

$(OBJDIR):
	@mkdir $@

$(LIBDIR):
	@mkdir $@

$(LIBPATH_A): $(SRCOBJ) $(ASMOBJ)
	$(LD) $(LDFLAGS) $(LIBPATH_A) $(SRCOBJ) $(ASMOBJ)

$(LIBPATH_SO): $(SRCOBJ) $(ASMOBJ)
	$(LD) $(LDFLAGS) $(SRCOBJ) $(ASMOBJ) -o $(LIBPATH_SO)

$(OBJDIR)/%.c.o: $(SRCDIR)/%.c $(HEADERS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -I$(INCLUDE) -c $< -o $@

$(OBJDIR)/%.S.o: $(SRCDIR)/%.S $(HEADERS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -I$(INCLUDE) -c $< -o $@

.PHONY: tests
tests:
	cd tests; $(MAKE)

.PHONY: clean_tests
clean_tests:
	cd tests; $(MAKE) clean

.PHONY: samples
samples:
	cd samples; $(MAKE) all

.PHONY: clean_samples
clean_samples:
	cd samples; $(MAKE) clean

.PHONY: clean_bin
clean_bin:
	rm -rf $(LIBDIR)

.PHONY: cleanobj
clean_obj:
	rm -rf $(OBJDIR)

.PHONY: doc
doc:
	doxygen
	mkdir -p doc
	cd doc/latex; $(MAKE)
	cd doc; ln -s -f html/index.html doc.html
	cd doc; ln -s -f latex/refman.pdf doc.pdf

.PHONY: clean_doc
clean_doc:
	rm -rf doc

.PHONY: clean
clean: clean_doc clean_bin clean_obj clean_tests clean_samples
	
