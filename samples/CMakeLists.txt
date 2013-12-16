CMAKE_MINIMUM_REQUIRED(VERSION 2.8.12)

################################################################################
# :: Project for the Ordo library samples.                                     #
################################################################################

PROJECT(Samples C)

################################################################################
# :: Chain all the samples (they all only have a single file).                 #
################################################################################

SET(SOURCE_FILES ${SOURCE_FILES} src/benchmark.c)
ADD_EXECUTABLE(benchmark src/benchmark.c)

SET(SOURCE_FILES ${SOURCE_FILES} src/info.c)
ADD_EXECUTABLE(info src/info.c)

SET(SOURCE_FILES ${SOURCE_FILES} src/md5sum.c)
ADD_EXECUTABLE(md5sum src/md5sum.c)

################################################################################
# :: This is for IDE's to place the various input files where they belong.     #
################################################################################

SOURCE_GROUP("Source" FILES ${SOURCE_FILES})

################################################################################
# :: Set include directories so the compiler (and/or IDE) can find headers.    #
################################################################################

TARGET_INCLUDE_DIRECTORIES(benchmark PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)
TARGET_INCLUDE_DIRECTORIES(info PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)
TARGET_INCLUDE_DIRECTORIES(md5sum PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)

################################################################################
# :: Link to the Ordo library (shared only).                                   #
################################################################################

TARGET_LINK_LIBRARIES(benchmark ordo)
TARGET_LINK_LIBRARIES(info ordo)
TARGET_LINK_LIBRARIES(md5sum ordo)
