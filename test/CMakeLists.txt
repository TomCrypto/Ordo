CMAKE_MINIMUM_REQUIRED(VERSION 2.8.11)

PROJECT(Test C)

SET(BIN_NAME "test")

SET(INCLUDE_FILES
    include/tests/utility/errors.h
    include/tests/utility/utils.h
    include/tests/stream/stream.h
    include/tests/misc/os_random.h
    include/tests/block/block.h
    include/tests/block_modes/block_modes.h
    include/tests/digest/specific/skein256.h
    include/tests/digest/digest.h
    include/tests/hmac/hmac.h
    include/tests/pbkdf2/pbkdf2.h
    include/testenv.h
)

SET(SOURCE_FILES
    src/main.c
    src/testenv.c
    src/tests/utility/errors.c
    src/tests/utility/utils.c
    src/tests/stream/stream.c
    src/tests/misc/os_random.c
    src/tests/block/block.c
    src/tests/block_modes/block_modes.c
    src/tests/digest/specific/skein256.c
    src/tests/digest/digest.c
    src/tests/hmac/hmac.c
    src/tests/pbkdf2/pbkdf2.c
)

SOURCE_GROUP("Includes" FILES ${INCLUDE_FILES})
SOURCE_GROUP("Source" FILES ${SOURCE_FILES})

ADD_EXECUTABLE(${BIN_NAME} ${INCLUDE_FILES} ${SOURCE_FILES})

TARGET_INCLUDE_DIRECTORIES(${BIN_NAME} PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)
TARGET_COMPILE_DEFINITIONS(${BIN_NAME} PRIVATE ORDO_STATIC_LIB)

TARGET_LINK_LIBRARIES(${BIN_NAME} ordo_s)
