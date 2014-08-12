all: static shared test samples

static: libordo_s.a

samples: hashsum benchmark version info

INFO_LDFLAGS=-lrt
INFO_HEADERS=../include/ordo/definitions.h
INFO_DEPS=libordo_s.a libutil.a
INFO_CFLAGS=-O3 -Wall -Wextra -std=c89 -pedantic -Wno-long-long -Wno-unused-parameter -Wno-missing-braces -Wno-missing-field-initializers -march=native -Wno-maybe-initialized
INFO_SOURCES=../samples/src/info.c
INFO_INCLUDE=-I../include -I../samples/util/include
INFO_DEFINES=-DORDO_STATIC_LIB
obj/INFO____samples_src_info_c.o: ../samples/src/info.c $(INFO_HEADERS) .objdir
	cc $(INFO_CFLAGS) $(INFO_DEFINES) $(INFO_INCLUDE) -c ../samples/src/info.c -o obj/INFO____samples_src_info_c.o

info: obj/INFO____samples_src_info_c.o libordo_s.a libutil.a
	cc obj/INFO____samples_src_info_c.o libordo_s.a libutil.a -o info libordo_s.a libutil.a $(INFO_LDFLAGS)

LIBORDO_S_A_HEADERS=../include/ordo/definitions.h
LIBORDO_S_A_DEPS=
LIBORDO_S_A_CFLAGS=-O3 -Wall -Wextra -std=c89 -pedantic -Wno-long-long -Wno-unused-parameter -Wno-missing-braces -Wno-missing-field-initializers -march=native -Wno-maybe-initialized -fvisibility=hidden 
LIBORDO_S_A_SOURCES=
LIBORDO_S_A_INCLUDE=-I../include
LIBORDO_S_A_DEFINES=-DBUILDING_ORDO -DORDO_STATIC_LIB -DORDO_ARCH=\"generic\" -DORDO_PLATFORM=\"linux\" -DORDO_FEATURE_LIST=\"\" -DORDO_FEATURE_ARRAY=0 -DWITH_AES=1 -DWITH_THREEFISH256=1 -DWITH_NULLCIPHER=1 -DWITH_RC4=1 -DWITH_MD5=1 -DWITH_SHA1=1 -DWITH_SHA256=1 -DWITH_SKEIN256=1 -DWITH_ECB=1 -DWITH_CBC=1 -DWITH_CTR=1 -DWITH_CFB=1 -DWITH_OFB=1
libordo_s.a: 
	ar rcs libordo_s.a 

LIBUTIL_A_HEADERS=
LIBUTIL_A_DEPS=
LIBUTIL_A_CFLAGS=-O3 -Wall -Wextra -std=c89 -pedantic -Wno-long-long -Wno-unused-parameter -Wno-missing-braces -Wno-missing-field-initializers -march=native -Wno-maybe-initialized
LIBUTIL_A_SOURCES=
LIBUTIL_A_INCLUDE=-I../samples/util/include
LIBUTIL_A_DEFINES=
libutil.a: 
	ar rcs libutil.a 

BENCHMARK_LDFLAGS=-lrt
BENCHMARK_HEADERS=../include/ordo/definitions.h
BENCHMARK_DEPS=libordo_s.a libutil.a
BENCHMARK_CFLAGS=-O3 -Wall -Wextra -std=c89 -pedantic -Wno-long-long -Wno-unused-parameter -Wno-missing-braces -Wno-missing-field-initializers -march=native -Wno-maybe-initialized
BENCHMARK_SOURCES=../samples/src/benchmark.c
BENCHMARK_INCLUDE=-I../include -I../samples/util/include
BENCHMARK_DEFINES=-DORDO_STATIC_LIB
obj/BENCHMARK____samples_src_benchmark_c.o: ../samples/src/benchmark.c $(BENCHMARK_HEADERS) .objdir
	cc $(BENCHMARK_CFLAGS) $(BENCHMARK_DEFINES) $(BENCHMARK_INCLUDE) -c ../samples/src/benchmark.c -o obj/BENCHMARK____samples_src_benchmark_c.o

benchmark: obj/BENCHMARK____samples_src_benchmark_c.o libordo_s.a libutil.a
	cc obj/BENCHMARK____samples_src_benchmark_c.o libordo_s.a libutil.a -o benchmark libordo_s.a libutil.a $(BENCHMARK_LDFLAGS)

HASHSUM_LDFLAGS=-lrt
HASHSUM_HEADERS=../include/ordo/definitions.h
HASHSUM_DEPS=libordo_s.a libutil.a
HASHSUM_CFLAGS=-O3 -Wall -Wextra -std=c89 -pedantic -Wno-long-long -Wno-unused-parameter -Wno-missing-braces -Wno-missing-field-initializers -march=native -Wno-maybe-initialized
HASHSUM_SOURCES=../samples/src/hashsum.c
HASHSUM_INCLUDE=-I../include -I../samples/util/include
HASHSUM_DEFINES=-DORDO_STATIC_LIB
obj/HASHSUM____samples_src_hashsum_c.o: ../samples/src/hashsum.c $(HASHSUM_HEADERS) .objdir
	cc $(HASHSUM_CFLAGS) $(HASHSUM_DEFINES) $(HASHSUM_INCLUDE) -c ../samples/src/hashsum.c -o obj/HASHSUM____samples_src_hashsum_c.o

hashsum: obj/HASHSUM____samples_src_hashsum_c.o libordo_s.a libutil.a
	cc obj/HASHSUM____samples_src_hashsum_c.o libordo_s.a libutil.a -o hashsum libordo_s.a libutil.a $(HASHSUM_LDFLAGS)

VERSION_LDFLAGS=-lrt
VERSION_HEADERS=../include/ordo/definitions.h
VERSION_DEPS=libordo_s.a libutil.a
VERSION_CFLAGS=-O3 -Wall -Wextra -std=c89 -pedantic -Wno-long-long -Wno-unused-parameter -Wno-missing-braces -Wno-missing-field-initializers -march=native -Wno-maybe-initialized
VERSION_SOURCES=../samples/src/version.c
VERSION_INCLUDE=-I../include -I../samples/util/include
VERSION_DEFINES=-DORDO_STATIC_LIB
obj/VERSION____samples_src_version_c.o: ../samples/src/version.c $(VERSION_HEADERS) .objdir
	cc $(VERSION_CFLAGS) $(VERSION_DEFINES) $(VERSION_INCLUDE) -c ../samples/src/version.c -o obj/VERSION____samples_src_version_c.o

version: obj/VERSION____samples_src_version_c.o libordo_s.a libutil.a
	cc obj/VERSION____samples_src_version_c.o libordo_s.a libutil.a -o version libordo_s.a libutil.a $(VERSION_LDFLAGS)

TEST_HEADERS=../include/ordo/definitions.h
TEST_DEPS=libordo_s.a
TEST_CFLAGS=-O3 -Wall -Wextra -std=c89 -pedantic -Wno-long-long -Wno-unused-parameter -Wno-missing-braces -Wno-missing-field-initializers -march=native -Wno-maybe-initialized
TEST_SOURCES=
TEST_INCLUDE=-I../include -I../test/include
TEST_DEFINES=-DORDO_STATIC_LIB
test: libordo_s.a
	cc libordo_s.a -o test libordo_s.a

shared:
	echo "Shared library will not be built." > shared
	echo "Please configure (with --shared)." >> shared

clean:
	rm -rf libordo_s.a
	rm -rf shared
	rm -rf hashsum version info benchmark test
	rm -rf libutil.a
	rm -rf obj
	rm -rf .objdir

install:
	mkdir -p /usr/local/include
	mkdir -p /usr/local/lib
	cp -r ../include/ordo.h /usr/local/include
	cp -r ../include/ordo /usr/local/include
	cp -r libordo_s.a /usr/local/lib
	

doc:
	cd ../doc && doxygen

.objdir:
	mkdir obj
	touch .objdir
