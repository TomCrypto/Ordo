CMAKE_MINIMUM_REQUIRED(VERSION 2.8.12)

################################################################################
# :: Project for the Ordo symmetric cryptography library.                      #
################################################################################

PROJECT(Ordo C ASM)

SET(LIB_NAME "ordo")

################################################################################
# :: Declare custom build options here.                                        #
################################################################################

OPTION(STATIC_LIB "Build also as a static library" OFF)
OPTION(NO_ASM "No assembly code (standard C only)" OFF)
OPTION(NATIVE_ARCH "Tune for host CPU architecture" ON)
OPTION(NO_POOL "Turn off the built-in memory pool" OFF)

################################################################################
# :: Detect the compiler in use, and warn about unsupported compilers.         #
# ---------------------------------------------------------------------------- #
# Note: We currently only support GCC, MinGW, Clang, and MSVC.                 #
################################################################################

IF("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
    SET(COMPILER_GNU ON)
ELSEIF("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
    SET(COMPILER_CLANG ON)
ELSEIF("${CMAKE_C_COMPILER_ID}" STREQUAL "MSVC")
    SET(COMPILER_MSVC ON)
ELSE()
    MESSAGE(SEND_ERROR "Unsupported compiler!")
ENDIF()

################################################################################
# :: Detect the current system, and warn about unsupported systems.            #
# ---------------------------------------------------------------------------- #
# Note: We currently only support Linux, BSD's, and Windows.                   #
################################################################################

IF("${CMAKE_SYSTEM_NAME}" STREQUAL "Windows")
    SET(SYSTEM_WINDOWS ON)
ELSEIF("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
    SET(SYSTEM_LINUX ON)
ELSEIF("${CMAKE_SYSTEM_NAME}" STREQUAL "FreeBSD")
    SET(SYSTEM_FREEBSD ON)
ELSEIF("${CMAKE_SYSTEM_NAME}" STREQUAL "OpenBSD")
    SET(SYSTEM_OPENBSD ON)
ELSEIF("${CMAKE_SYSTEM_NAME}" STREQUAL "NetBSD")
    SET(SYSTEM_NETBSD ON)
ELSE()
    MESSAGE(SEND_ERROR "Unsupported system!")
ENDIF()

################################################################################
# :: Find the pthread library in order to use its mutex functionality.         #
# ---------------------------------------------------------------------------- #
# Note: Windows does not require pthreads as it has a standard mutex.          #
################################################################################

IF((NOT NO_POOL) AND (NOT SYSTEM_WINDOWS))
    FIND_PACKAGE(Threads REQUIRED)
ENDIF()

################################################################################
# :: Define compiler-specific compilation flags.                               #
################################################################################

IF(NOT COMPILER_MSVC)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -O3")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-variable")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-parameter")

    IF(NATIVE_ARCH)
        SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=native")
        IF(NOT NO_ASM)
            SET(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -march=native")
        ENDIF()
    ENDIF()
ELSE()
    # Disable some overzealous (but harmless) Visual Studio warnings
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W4 /wd4706 /wd4100 /wd4127")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /O2")
ENDIF()

IF((NOT NO_ASM) AND (COMPILER_CLANG))
    SET(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -no-integrated-as")
ENDIF()


################################################################################
# :: List all the source code and header files in the library.                 #
# ---------------------------------------------------------------------------- #
# Note: the list includes assembly files, which may require special treatment. #
################################################################################

SET(INCLUDE_FILES
    include/ordo.h
    include/ordo/common/errors.h
    include/ordo/common/version.h
    include/ordo/common/identification.h
    include/ordo/common/utils.h
    include/ordo/common/query.h
    include/ordo/kdf/pbkdf2.h
    include/ordo/misc/os_random.h
    include/ordo/internal/endianness.h
    include/ordo/internal/mem/mutex.h
    include/ordo/internal/mem/params.h
    include/ordo/internal/mem/base.h
    include/ordo/internal/api.h
    include/ordo/internal/mem.h
    include/ordo/internal/environment.h
    include/ordo/internal/asm/resolve.h
    include/ordo/digest/digest.h
    include/ordo/enc/enc_stream.h
    include/ordo/enc/block_modes.h
    include/ordo/enc/block_modes/cfb.h
    include/ordo/enc/block_modes/mode_params.h
    include/ordo/enc/block_modes/cbc.h
    include/ordo/enc/block_modes/ecb.h
    include/ordo/enc/block_modes/ctr.h
    include/ordo/enc/block_modes/ofb.h
    include/ordo/enc/enc_block.h
    include/ordo/primitives/stream_ciphers.h
    include/ordo/primitives/hash_functions.h
    include/ordo/primitives/block_ciphers.h
    include/ordo/primitives/hash_functions/sha256.h
    include/ordo/primitives/hash_functions/md5.h
    include/ordo/primitives/hash_functions/skein256.h
    include/ordo/primitives/hash_functions/hash_params.h
    include/ordo/primitives/stream_ciphers/rc4.h
    include/ordo/primitives/stream_ciphers/stream_params.h
    include/ordo/primitives/block_ciphers/block_params.h
    include/ordo/primitives/block_ciphers/threefish256.h
    include/ordo/primitives/block_ciphers/aes.h
    include/ordo/primitives/block_ciphers/nullcipher.h
    include/ordo/auth/hmac.h
)

SET(SOURCE_FILES
    src/ordo.c
    src/ordo/common/errors.c
    src/ordo/common/utils.c
    src/ordo/common/version.c
    src/ordo/kdf/pbkdf2.c
    src/ordo/misc/os_random.c
    src/ordo/internal/mem/base.c
    src/ordo/internal/mem/mutex.c
    src/ordo/internal/mem.c
    src/ordo/digest/digest.c
    src/ordo/enc/enc_stream.c
    src/ordo/enc/block_modes.c
    src/ordo/enc/block_modes/cbc.c
    src/ordo/enc/block_modes/ecb.c
    src/ordo/enc/block_modes/cfb.c
    src/ordo/enc/block_modes/ofb.c
    src/ordo/enc/block_modes/ctr.c
    src/ordo/enc/enc_block.c
    src/ordo/primitives/hash_functions.c
    src/ordo/primitives/block_ciphers.c
    src/ordo/primitives/stream_ciphers.c
    src/ordo/primitives/hash_functions/skein256.c
    src/ordo/primitives/hash_functions/md5.c
    src/ordo/primitives/hash_functions/hash_params.c
    src/ordo/primitives/hash_functions/sha256.c
    src/ordo/primitives/stream_ciphers/rc4.c
    src/ordo/primitives/block_ciphers/nullcipher.c
    src/ordo/primitives/block_ciphers/threefish256.c
    src/ordo/primitives/block_ciphers/aes.c
    src/ordo/auth/hmac.c
)

IF(NOT NO_ASM)
    SET(SOURCE_FILES ${SOURCE_FILES}
        src/ordo/primitives/stream_ciphers/asm/rc4.S
        src/ordo/primitives/block_ciphers/asm/threefish256.S
        src/ordo/primitives/block_ciphers/asm/aes.S
    )
ENDIF()

################################################################################
# :: This is for IDE's to place the various input files where they belong.     #
################################################################################

SOURCE_GROUP("Includes" FILES ${INCLUDE_FILES})
SOURCE_GROUP("Source" FILES ${SOURCE_FILES})

################################################################################
# :: Add the shared and static libraries as build targets.                     #
# ---------------------------------------------------------------------------- #
# Note: the static library is suffixed with "_s" to avoid naming conflicts.    #
################################################################################

ADD_LIBRARY(${LIB_NAME} SHARED ${INCLUDE_FILES} ${SOURCE_FILES})

IF(STATIC_LIB)
    ADD_LIBRARY(${LIB_NAME}_s STATIC ${INCLUDE_FILES} ${SOURCE_FILES})
ENDIF()

################################################################################
# :: Install the headers and libraries somewhere suitable.                     #
# ---------------------------------------------------------------------------- #
# Note: On Linux, this will probably install in /usr/local/*, and will require #
#       root. On Windows, it may install in Program Files\Ordo or similar.     #
################################################################################

INSTALL(FILES include/ordo.h DESTINATION include)
INSTALL(DIRECTORY include/ordo DESTINATION include)

IF(STATIC_LIB)
    INSTALL(TARGETS ${LIB_NAME} ${LIB_NAME}_s LIBRARY DESTINATION lib
                                              ARCHIVE DESTINATION lib)
ELSE()
    INSTALL(TARGETS ${LIB_NAME} LIBRARY DESTINATION lib
                                ARCHIVE DESTINATION lib)
ENDIF()

################################################################################
# :: Set include directories so the compiler (and/or IDE) can find headers.    #
################################################################################

TARGET_INCLUDE_DIRECTORIES(${LIB_NAME} PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)
IF(STATIC_LIB)
    TARGET_INCLUDE_DIRECTORIES(${LIB_NAME}_s PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)
ENDIF()

################################################################################
# :: Set any specific preprocessor tokens that need to be defined.             #
################################################################################

TARGET_COMPILE_DEFINITIONS(${LIB_NAME} PRIVATE BUILDING_${LIB_NAME})
IF(STATIC_LIB)
    TARGET_COMPILE_DEFINITIONS(${LIB_NAME}_s PRIVATE BUILDING_${LIB_NAME})
ENDIF()

IF(NO_POOL)
    TARGET_COMPILE_DEFINITIONS(${LIB_NAME} PRIVATE ORDO_DISABLE_POOL)
    IF(STATIC_LIB)
        TARGET_COMPILE_DEFINITIONS(${LIB_NAME}_s PRIVATE ORDO_DISABLE_POOL)
    ENDIF()
ENDIF()

IF(NO_ASM)
    TARGET_COMPILE_DEFINITIONS(${LIB_NAME} PRIVATE ORDO_NO_ASM)
    IF(STATIC_LIB)
        TARGET_COMPILE_DEFINITIONS(${LIB_NAME}_s PRIVATE ORDO_NO_ASM)
    ENDIF()
ENDIF()

################################################################################
# :: When pthreads is required, link it into the shared library.               #
################################################################################

IF((NOT NO_POOL) AND (NOT SYSTEM_WINDOWS))
    TARGET_LINK_LIBRARIES(${LIB_NAME} ${CMAKE_THREAD_LIBS_INIT})
ELSE()
    TARGET_LINK_LIBRARIES(${LIB_NAME})
ENDIF()

################################################################################
# :: Reference any additional projects (tests, etc...) in here.                #
################################################################################

add_subdirectory(test)
add_subdirectory(samples)

################################################################################
# :: Generate the documentation using doxygen (if available).                  #
################################################################################

FIND_PACKAGE(Doxygen)

if(DOXYGEN_FOUND)
    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in
                   ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile @ONLY)
    add_custom_target(doc
        ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
endif()
