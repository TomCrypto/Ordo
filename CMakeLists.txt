CMAKE_MINIMUM_REQUIRED(VERSION 2.8.11)

PROJECT(Ordo C ASM_NASM)
ENABLE_LANGUAGE(ASM_NASM)

SET(LIB_NAME "ordo")
SET(SRC_PATH "src" )

INCLUDE(CheckIncludeFile)
INCLUDE(CheckTypeSize)

CHECK_INCLUDE_FILE("stdint.h" HAVE_STDINT_H)
SET(CMAKE_EXTRA_INCLUDE_FILES stdint.h)
CHECK_TYPE_SIZE("uint8_t" HAVE_UINT8_T)
CHECK_TYPE_SIZE("uint16_t" HAVE_UINT16_T)
CHECK_TYPE_SIZE("uint32_t" HAVE_UINT32_T)
CHECK_TYPE_SIZE("uint64_t" HAVE_UINT64_T)
CHECK_TYPE_SIZE("long long" HAVE_LONG_LONG)
CHECK_TYPE_SIZE("unsigned long long" HAVE_UNSIGNED_LONG_LONG)
SET(CMAKE_EXTRA_INCLUDE_FILES)

FIND_PACKAGE(PythonInterp REQUIRED)

IF(NOT (HAVE_STDINT_H AND HAVE_UINT8_T AND HAVE_UINT16_T AND HAVE_UINT32_T AND HAVE_UINT64_T))
    MESSAGE(FATAL_ERROR "Standard fixed-width types required!")
ENDIF()

IF(NOT (HAVE_LONG_LONG AND HAVE_UNSIGNED_LONG_LONG))
    MESSAGE(FATAL_ERROR "Long long support required!")
ENDIF()

IF("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
    SET(COMPILER_GNU ON)
ELSEIF("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
    SET(COMPILER_CLANG ON)
ELSEIF("${CMAKE_C_COMPILER_ID}" STREQUAL "Intel")
    SET(COMPILER_INTEL ON)
ELSEIF("${CMAKE_C_COMPILER_ID}" STREQUAL "MSVC")
    SET(COMPILER_MSVC ON)
ELSE()
    MESSAGE(FATAL_ERROR "Unsupported compiler!")
ENDIF()

SET(ARCH_GENERIC   "generic")
SET(FEATURES              "")

IF(    "${CMAKE_SYSTEM_NAME}" STREQUAL "Windows")
    SET(SYSTEM                         "win32")
ELSEIF("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
    SET(SYSTEM                         "linux")
ELSEIF("${CMAKE_SYSTEM_NAME}" STREQUAL "FreeBSD")
    SET(SYSTEM                         "freebsd")
ELSEIF("${CMAKE_SYSTEM_NAME}" STREQUAL "OpenBSD")
    SET(SYSTEM                         "openbsd")
ELSEIF("${CMAKE_SYSTEM_NAME}" STREQUAL "NetBSD")
    SET(SYSTEM                         "netbsd")
ELSEIF("${CMAKE_SYSTEM_NAME}" STREQUAL "Darwin")
    SET(SYSTEM                         "darwin")
ELSE()
    SET(SYSTEM  "generic")
    SET(SYSTEM_GENERIC ON)
ENDIF()

SET(ARCH "${ARCH_GENERIC}" CACHE STRING "Architecture to build for")
IF(SYSTEM_GENERIC)
    SET_PROPERTY(CACHE ARCH PROPERTY STRINGS ${ARCH_GENERIC})
ENDIF()

IF(NOT SYSTEM_GENERIC)
    INCLUDE(${SRC_PATH}/${SYSTEM}/.archs)
    IF(NOT ${ARCH} STREQUAL ${ARCH_GENERIC})
        INCLUDE(${SRC_PATH}/${SYSTEM}/${ARCH}/.features)
    ENDIF()
ENDIF()

OPTION(LTO "Link-Time Optimization" ON)
OPTION(NATIVE "Native Optimization" ON)
OPTION(COMPAT "For Older Compilers" OFF)

IF(COMPILER_GNU OR COMPILER_CLANG)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -Wall -Wextra")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c89 -pedantic")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-missing-braces")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-variable")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-parameter")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-long-long") # shut up!
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-missing-field-initializers")

    IF(COMPILER_GNU AND NOT COMPAT)
        SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-maybe-uninitialized")
    ENDIF()

    IF(LTO AND NOT (COMPILER_GNU AND COMPAT))
        SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -flto")

        IF(COMPILER_GNU)
            SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ffat-lto-objects")
        ENDIF()
    ENDIF()

    IF(NATIVE AND NOT (COMPILER_GNU AND COMPAT))
        SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=native")
    ENDIF()
ELSEIF(COMPILER_INTEL)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ansi-alias")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -Wall -Wextra")    
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c89 -pedantic")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden")

    IF(LTO AND NOT COMPAT)
        SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ipo")
    ENDIF()

    IF(NATIVE)
        IF(NOT ICC_TARGET)
            MESSAGE(FATAL_ERROR "Please provide target arch via ICC_TARGET")
        ELSE()
            SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -x${ICC_TARGET}")
        ENDIF()
    ENDIF()
ELSEIF(COMPILER_MSVC)
    # Disable some overzealous (but harmless) Visual Studio warnings
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W4 /wd4706 /wd4100 /wd4127")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /O2 /MP")

    IF(LTO AND NOT COMPAT)
        SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /GL")
        SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /LTCG")
        SET(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /LTCG")
    ENDIF()
ENDIF()

SET(INCLUDE_FILES
    include/ordo.h
    include/ordo/definitions.h
    include/ordo/misc/utils.h
    include/ordo/misc/endianness.h
    include/ordo/misc/os_random.h
    include/ordo/misc/curve25519.h
    include/ordo/enc/enc_block.h
    include/ordo/enc/enc_stream.h
    include/ordo/kdf/pbkdf2.h
    include/ordo/common/error.h
    include/ordo/common/query.h
    include/ordo/common/interface.h
    include/ordo/common/identification.h
    include/ordo/common/version.h
    include/ordo/auth/hmac.h
    include/ordo/internal/alg.h
    include/ordo/internal/implementation.h
    include/ordo/internal/sys.h
    include/ordo/digest/digest.h
    include/ordo/primitives/stream_ciphers/rc4.h
    include/ordo/primitives/stream_ciphers/stream_params.h
    include/ordo/primitives/hash_functions/hash_params.h
    include/ordo/primitives/hash_functions/skein256.h
    include/ordo/primitives/hash_functions/sha256.h
    include/ordo/primitives/hash_functions/md5.h
    include/ordo/primitives/block_modes.h
    include/ordo/primitives/block_ciphers/threefish256.h
    include/ordo/primitives/block_ciphers/aes.h
    include/ordo/primitives/block_ciphers/block_params.h
    include/ordo/primitives/block_ciphers/nullcipher.h
    include/ordo/primitives/hash_functions.h
    include/ordo/primitives/block_modes/mode_params.h
    include/ordo/primitives/block_modes/ctr.h
    include/ordo/primitives/block_modes/ofb.h
    include/ordo/primitives/block_modes/cfb.h
    include/ordo/primitives/block_modes/ecb.h
    include/ordo/primitives/block_modes/cbc.h
    include/ordo/primitives/stream_ciphers.h
    include/ordo/primitives/block_ciphers.h
)

SET(IN_FILES
    alg.c
    utils.c
    block_ciphers.c
    block_modes.c
    digest.c
    enc_block.c
    enc_stream.c
    endianness.c
    error.c
    identification.c
    hash_functions.c
    hash_params.c
    hmac.c
    ordo.c
    os_random.c
    pbkdf2.c
    stream_ciphers.c
    version.c
    curve25519.c
    curve25519.asm
)

SET(PRIM_LIST AES NULLCIPHER THREEFISH256 MD5 SHA256 SKEIN256 RC4 ECB CBC CTR CFB OFB)

FOREACH(PRIM ${PRIM_LIST})
    OPTION(WITH_${PRIM} "Include this primitive" ON)
ENDFOREACH()

IF(WITH_SKEIN256 AND NOT WITH_THREEFISH256)
    MESSAGE(FATAL_ERROR "WITH_SKEIN256 requires WITH_THREEFISH256!")
ENDIF()

FOREACH(PRIM ${PRIM_LIST})
    IF(WITH_${PRIM})
        STRING(TOLOWER ${PRIM} PRIM_FILE)
        LIST(APPEND IN_FILES ${PRIM_FILE}.c ${PRIM_FILE}.asm)
    ENDIF()
ENDFOREACH()

FUNCTION(PROCESS FOLDER)
    FOREACH(F ${IN_FILES})
        IF(EXISTS ${CMAKE_SOURCE_DIR}/${FOLDER}/${F})
            LIST(REMOVE_ITEM IN_FILES ${F})

            IF(COMPILER_MSVC)
                GET_FILENAME_COMPONENT(FILE_EXT ${F} EXT)
                IF(FILE_EXT STREQUAL ".asm")
                    IF(CMAKE_SIZEOF_VOID_P EQUAL 8)
                        SET(OBJ_TYPE win64)
                    ELSE()
                        SET(OBJ_TYPE win32)
                    ENDIF()

                    SET(OBJ_FILE ${CMAKE_CURRENT_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/${F}.obj)
                    SET(CMD ${CMAKE_ASM_NASM_COMPILER} -f ${OBJ_TYPE} ${CMAKE_SOURCE_DIR}/${FOLDER}/${F} -o ${OBJ_FILE})
                    ADD_CUSTOM_COMMAND(OUTPUT ${OBJ_FILE} COMMAND ${CMD} DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${FOLDER}/${F})

                    LIST(APPEND SOURCE_FILES ${OBJ_FILE})
                ELSE()
                    LIST(APPEND SOURCE_FILES ${CMAKE_SOURCE_DIR}/${FOLDER}/${F})
                ENDIF()
            ELSE()
                LIST(APPEND SOURCE_FILES ${CMAKE_SOURCE_DIR}/${FOLDER}/${F})
            ENDIF()
        ENDIF()
    ENDFOREACH()
    SET(SOURCE_FILES ${SOURCE_FILES} PARENT_SCOPE)
    SET(IN_FILES ${IN_FILES} PARENT_SCOPE)
ENDFUNCTION()

IF(NOT SYSTEM_GENERIC)
    IF(NOT ${ARCH} STREQUAL ${ARCH_GENERIC})
        FOREACH(FEATURE ${FEATURES})
            PROCESS(${SRC_PATH}/${SYSTEM}/${ARCH}/${FEATURE})
        ENDFOREACH()

        PROCESS(${SRC_PATH}/${SYSTEM}/${ARCH})
    ENDIF()

    PROCESS(${SRC_PATH}/${SYSTEM})
ENDIF()

PROCESS(${SRC_PATH})

EXECUTE_PROCESS(COMMAND ${PYTHON_EXECUTABLE} resolve.py ${SOURCE_FILES}
                WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
                RESULT_VARIABLE RESOLVE_EXITCODE)

IF(RESOLVE_EXITCODE)
    MESSAGE(FATAL_ERROR "Resolution script failed!")
ENDIF()

SOURCE_GROUP("Includes" FILES ${INCLUDE_FILES})
SOURCE_GROUP("Source" FILES ${SOURCE_FILES})

ADD_LIBRARY(${LIB_NAME} SHARED ${INCLUDE_FILES} ${SOURCE_FILES})
ADD_LIBRARY(${LIB_NAME}_s STATIC ${INCLUDE_FILES} ${SOURCE_FILES})

INSTALL(FILES include/ordo.h DESTINATION include)
INSTALL(DIRECTORY include/ordo DESTINATION include)
INSTALL(TARGETS ${LIB_NAME} ${LIB_NAME}_s LIBRARY DESTINATION lib
                                          ARCHIVE DESTINATION lib)
TARGET_INCLUDE_DIRECTORIES(${LIB_NAME} PUBLIC
                           ${CMAKE_CURRENT_LIST_DIR}/include)
TARGET_INCLUDE_DIRECTORIES(${LIB_NAME}_s PUBLIC
                           ${CMAKE_CURRENT_LIST_DIR}/include)

FUNCTION(ADD_TOKEN TOKEN)
    TARGET_COMPILE_DEFINITIONS(${LIB_NAME}   PRIVATE ${TOKEN})
    TARGET_COMPILE_DEFINITIONS(${LIB_NAME}_s PRIVATE ${TOKEN})
ENDFUNCTION()

ADD_TOKEN(_CRT_NO_SECURE_WARNINGS)
ADD_TOKEN(BUILDING_${LIB_NAME})
ADD_TOKEN(annotation=0)

FOREACH(PRIM ${PRIM_LIST})
    IF(WITH_${PRIM})
        ADD_TOKEN(WITH_${PRIM}=1)
    ELSE()
        ADD_TOKEN(WITH_${PRIM}=0)
    ENDIF()
ENDFOREACH()

IF(NOT SYSTEM_GENERIC)
    ADD_TOKEN(ORDO_ARCH="${ARCH}")
ENDIF()

ADD_TOKEN(ORDO_SYSTEM="${SYSTEM}")

IF(FEATURES)
    FUNCTION(JOIN VALUES GLUE OUTPUT)
        STRING(REPLACE ";" "${GLUE}" _TMP_STR "${VALUES}")
        SET(${OUTPUT} "${_TMP_STR}" PARENT_SCOPE)
    ENDFUNCTION()

    ADD_TOKEN(ORDO_HAS_FEATURES)
    JOIN("${FEATURES}" " " FEATURE_LIST)

    ADD_TOKEN(ORDO_FEATURE_LIST="${FEATURE_LIST}")
    
    SET(FEATURE_ARRAY, "")
    FOREACH(FEATURE ${FEATURES})
        SET(FEATURE_ARRAY ${FEATURE_ARRAY}\"${FEATURE}\",)
    ENDFOREACH()

    ADD_TOKEN(ORDO_FEATURE_ARRAY=${FEATURE_ARRAY})
ENDIF()

IF(SYSTEM_GENERIC)
    INCLUDE(TestBigEndian)
    test_big_endian(TEST_ENDIAN)
    
    IF(TEST_ENDIAN)
        ADD_TOKEN(ORDO_BIG_ENDIAN)
    ELSE()
        ADD_TOKEN(ORDO_LITTLE_ENDIAN)
    ENDIF()
ENDIF()

ADD_SUBDIRECTORY(extra/test test)
ADD_SUBDIRECTORY(extra/samples samples)

FIND_PACKAGE(Doxygen)

IF(DOXYGEN_FOUND)
    CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile
                   ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile @ONLY)
    ADD_CUSTOM_TARGET(doc
        ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
ENDIF()
