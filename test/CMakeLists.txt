CMAKE_MINIMUM_REQUIRED(VERSION 2.8.12)

################################################################################
# :: Project for the Ordo test driver.                                         #
################################################################################

PROJECT(Test C)

SET(BIN_NAME "test")

################################################################################
# :: Declare custom build options here.                                        #
################################################################################

OPTION(TEST_STATIC_LIB "Link test driver to static library" OFF)

################################################################################
# :: Link to threads if needed (only if linking statically).                   #
################################################################################

IF((NOT NO_POOL) AND (NOT SYSTEM_WINDOWS) AND (TEST_STATIC_LIB))
    FIND_PACKAGE(Threads REQUIRED)
ENDIF()

################################################################################
# :: List all the source code and header files the test driver uses.           #
################################################################################

SET(INCLUDE_FILES
    include/tests/utility/errors.h
    include/tests/utility/mem.h
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
    src/tests/utility/mem.c
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

################################################################################
# :: This is for IDE's to place the various input files where they belong.     #
################################################################################

SOURCE_GROUP("Includes" FILES ${INCLUDE_FILES})
SOURCE_GROUP("Source" FILES ${SOURCE_FILES})

################################################################################
# :: Add the test driver as a single build target.                             #
################################################################################

ADD_EXECUTABLE(${BIN_NAME} ${INCLUDE_FILES} ${SOURCE_FILES})

################################################################################
# :: Set include directories so the compiler (and/or IDE) can find headers.    #
################################################################################

TARGET_INCLUDE_DIRECTORIES(${BIN_NAME} PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)

################################################################################
# :: Set any specific preprocessor tokens that need to be defined.             #
################################################################################

IF(TEST_STATIC_LIB)
    TARGET_COMPILE_DEFINITIONS(${BIN_NAME} PRIVATE ORDO_STATIC_LIB)
ENDIF()

IF(NO_POOL)
    TARGET_COMPILE_DEFINITIONS(${BIN_NAME} PRIVATE ORDO_NO_POOL)
ENDIF()

################################################################################
# :: Link to the Ordo library (shared or static).                              #
################################################################################

IF(TEST_STATIC_LIB)
    IF((NOT SYSTEM_WINDOWS) AND (NOT NO_POOL))
        TARGET_LINK_LIBRARIES(${BIN_NAME} ordo_s ${CMAKE_THREAD_LIBS_INIT})
    ELSE()
        TARGET_LINK_LIBRARIES(${BIN_NAME} ordo_s)
    ENDIF()
ELSE()
    TARGET_LINK_LIBRARIES(${BIN_NAME} ordo)
ENDIF()
