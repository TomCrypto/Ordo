BINDIR = bin
SRCDIR = src

CC ?= gcc
CFLAGS = -O2 -Wall -Wextra -std=c89 -pedantic -pedantic-errors -Wno-unused-parameter
CFLAGS += $(extra)

CXX ?= g++
CXXFLAGS = -O2 -Wall -Wextra
CXXFLAGS += $(extra)

ifeq ($(nopthread), 1)
	LDFLAGS = 
else
	CFLAGS += -pthread
	LDFLAGS = -pthread
endif

ifeq ($(shared), 1)
	ORDO_LIBNAME = libordo.so
else
	ORDO_LIBNAME = libordo.a
endif

ORDO_LIBDIR = ../lib/
ORDO_LIBPATH = $(addprefix $(ORDO_LIBDIR), $(ORDO_LIBNAME))
ORDO_INCLUDE = ../include/

.PHONY: all
all: md5sum benchmark external info
	

.PHONY: md5sum
md5sum:
	@mkdir -p $(BINDIR)
	$(CC) $(LDFLAGS) $(CFLAGS) $(SRCDIR)/md5sum.c -o $(BINDIR)/md5sum -I$(ORDO_INCLUDE) $(ORDO_LIBPATH)

.PHONY: benchmark
benchmark:
	@mkdir -p $(BINDIR)
	$(CC) $(LDFLAGS) $(CFLAGS) $(SRCDIR)/benchmark.c -o $(BINDIR)/benchmark -I$(ORDO_INCLUDE) $(ORDO_LIBPATH)

.PHONY: external
external:
	@mkdir -p $(BINDIR)
	$(CXX) $(LDFLAGS) $(CXXFLAGS) $(SRCDIR)/external.cpp -o $(BINDIR)/external -I$(ORDO_INCLUDE) $(ORDO_LIBPATH)

.PHONY: info
info:
	@mkdir -p $(BINDIR)
	$(CC) $(LDFLAGS) $(CFLAGS) $(SRCDIR)/info.c -o $(BINDIR)/info -I$(ORDO_INCLUDE) $(ORDO_LIBPATH)

.PHONY: clean
clean:
	rm -rf $(BINDIR)

