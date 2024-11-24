cmake_minimum_required(VERSION 3.21.0)

project(liteP2P VERSION 1.0.1 DESCRIPTION "a lite p2p library")

enable_language(C CXX ASM)

add_library(lite-p2p)

file(GLOB lite_p2p_HEADERS ${CMAKE_CURRENT_LIST_DIR}/*/*.hpp)

set_target_properties(lite-p2p PROPERTIES
    VERSION ${PROJECT_VERSION}
    PUBLIC_HEADER "${lite_p2p_HEADERS}"
    SOVERSION 1
)

target_include_directories(lite-p2p PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/lib
)

target_sources(lite-p2p PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/lib/peer_connection.cpp
    ${CMAKE_CURRENT_LIST_DIR}/lib/stun_client.cpp
)

if (DEFINED DEBUG)
add_compile_definitions(-g -ggdb -O0)
add_link_options(-g -ggdb -O0)
endif()

if (DEFINED STUN_TEST_TOOLS)
add_executable(stun-client)
target_include_directories(stun-client PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/lib
)

target_sources(stun-client PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/test/stun-client.cpp
)

target_link_libraries(stun-client lite-p2p)
endif()


configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/lite-p2p.pc.in
    ${CMAKE_CURRENT_BINARY_DIR}/lite-p2p.pc
    @ONLY
)

install(TARGETS lite-p2p
    LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_PREFIX}/include/lite-p2p/
)

install(
    FILES ${CMAKE_CURRENT_BINARY_DIR}/lite-p2p.pc
    DESTINATION lib/pkgconfig
)

set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_GENERATOR "RPM")
set(CPACK_PACKAGE_NAME "lite-p2p")
set(CPACK_PACKAGE_RELEASE 1)
set(CPACK_PACKAGE_CONTACT "Anis CHALI")
set(CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CPACK_PACKAGE_RELEASE}.${CMAKE_SYSTEM_PROCESSOR}")
include(CPack)

