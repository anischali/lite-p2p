cmake_minimum_required(VERSION 3.21.0)

project(liteP2P VERSION 1.0.1 DESCRIPTION "a lite p2p library wrappers")

find_package(SWIG REQUIRED)
find_package(PythonLibs REQUIRED)
include(${SWIG_USE_FILE})

include(GNUInstallDirs)


include_directories(
    ${PYTHON_INCLUDE_PATH}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

set(CMAKE_SWIG_FLAGS "")

set_source_files_properties(lite-p2p.i PROPERTIES 
    CPLUSPLUS ON
)

#swig_add_library(pylite_p2p
#    LANGUAGE python
#    SOURCES lite-p2p.i
#)

#swig_link_libraries(pylite_p2p ${PYTHON_LIBRARIES})

swig_add_library(sharplite_p2p
    LANGUAGE csharp
    SOURCES lite-p2p.i
)
