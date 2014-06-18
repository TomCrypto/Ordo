CMAKE_MINIMUM_REQUIRED(VERSION 2.8.11)

PROJECT(Test C)

SET(BIN_NAME "test")

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99")

SET(INCLUDE_FILES
    include/kat/parser.h
    include/kat/kats.h
    include/testenv.h
    include/tests.h
)

SET(SOURCE_FILES
    src/main.c
    src/testenv.c
    src/kat/parser.c
    src/tests/misc.c
    src/tests/internal.c
    src/tests/stream.c
    src/tests/os_random.c
    src/tests/block.c
    src/tests/block_modes.c
    src/tests/digest/skein256.c
    src/tests/digest.c
    src/tests/hmac.c
    src/tests/pbkdf2.c
    src/tests/enc_stream.c
)

SOURCE_GROUP("Includes" FILES ${INCLUDE_FILES})
SOURCE_GROUP("Source" FILES ${SOURCE_FILES})

ADD_EXECUTABLE(${BIN_NAME} ${INCLUDE_FILES} ${SOURCE_FILES})

TARGET_INCLUDE_DIRECTORIES(${BIN_NAME} PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)
TARGET_COMPILE_DEFINITIONS(${BIN_NAME} PRIVATE ORDO_STATIC_LIB)

TARGET_LINK_LIBRARIES(${BIN_NAME} ordo_s)
