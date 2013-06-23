LIBDIR = lib
OBJDIR = obj
SRCDIR = src
INCLUDE = include

CC = gcc
CFLAGS = -Wall -Wextra \
         -Wno-implicit-function-declaration -Wno-long-long \
         -Wno-unused-parameter -Wno-unused-label \
         -pedantic -pedantic-errors -pipe

# Chooses the proper compiler flags to use based on debug
# or release. By default release, use `make debug=1 ...`.
ifeq ($(debug), 1)
	CFLAGS += -O0 -ggdb -D ORDO_DEBUG
else
	CFLAGS += -O6
endif

# Decides whether to build a shared or a static library.
# Use `make shared=1 ...` to build Ordo as a shared lib.
ifeq ($(shared), 1)
	LIBNAME = libordo.so
	LDFLAGS = -shared
	CFLAGS += -fpic
	LD = gcc
else
	LIBNAME = libordo.a
	LDFLAGS = rcs
	LD = ar
endif

# If you use `make strip=1`, the library will be stripped.
ifeq ($(strip), 1)
	STRIP = strip $(addprefix $(LIBDIR)/, $(LIBNAME))
else
	STRIP = 
endif

# Add the extra arguments (if any)
CFLAGS += $(extra)

HEADERS = $(wildcard $(INCLUDE)/*.h)
SRC = $(shell find $(SRCDIR)/ -name '*.c')
ASM = $(shell find $(SRCDIR)/ -name '*.S')
SRCOBJ = $(subst .c,.c.o,$(subst $(SRCDIR)/,$(OBJDIR)/,$(SRC)))
ASMOBJ = $(subst .S,.S.o,$(subst $(SRCDIR)/,$(OBJDIR)/,$(ASM)))
LIBPATH = $(addprefix $(LIBDIR)/, $(LIBNAME))
LIBPATH_A = $(addprefix $(LIBDIR)/, libordo.a)
LIBPATH_SO = $(addprefix $(LIBDIR)/, libordo.so)

default: $(OBJDIR) $(LIBDIR) $(LIBPATH) $(STRIP)

$(OBJDIR):
	@mkdir $@

$(LIBDIR):
	@mkdir $@

$(STRIP):
	$(STRIP)

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

# make tests :: Builds the test driver
.PHONY: tests
tests:
	cd tests; make

# make runtests :: Runs the test driver
.PHONY: run_tests
run_tests:
	cd tests; ./bin/tests

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
	rm -f $(LIBDIR)/ --recursive

# make clean_obj :: Removes all object files
.PHONY: cleanobj
clean_obj:
	rm -f $(OBJDIR)/ --recursive

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
	rm -f doc/ --recursive

# make clean :: Removes all generated files
.PHONY: clean
clean: clean_doc clean_bin clean_obj clean_tests clean_samples
	
