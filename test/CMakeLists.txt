CMAKE_MINIMUM_REQUIRED(VERSION 2.8.11)

PROJECT(Test C)

SET(BIN_NAME "test")

SET(INCLUDE_FILES
    include/testenv.h
)

SET(SOURCE_FILES
    src/main.c
    src/test_vectors/md5.c
    src/test_vectors/sha256.c
    src/test_vectors/skein256.c
    src/test_vectors/hmac.c
    src/test_vectors/pbkdf2.c
    src/test_vectors/rc4.c
    src/test_vectors/aes.c
    src/test_vectors/threefish256.c
    src/test_vectors/ecb.c
    src/test_vectors/cbc.c
    src/test_vectors/ctr.c
    src/test_vectors/cfb.c
    src/test_vectors/ofb.c
    src/test_vectors/curve25519.c
    src/unit_tests/misc.c
    src/unit_tests/internal.c
    src/unit_tests/os_random.c
)

SOURCE_GROUP("Includes" FILES ${INCLUDE_FILES})
SOURCE_GROUP("Source" FILES ${SOURCE_FILES})

ADD_EXECUTABLE(${BIN_NAME} ${INCLUDE_FILES} ${SOURCE_FILES})

TARGET_INCLUDE_DIRECTORIES(${BIN_NAME} PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)
TARGET_COMPILE_DEFINITIONS(${BIN_NAME} PRIVATE ORDO_STATIC_LIB)

TARGET_LINK_LIBRARIES(${BIN_NAME} ordo_s)
