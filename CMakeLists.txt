cmake_minimum_required(VERSION 3.21.0)


project(liteP2P VERSION 1.0.1 DESCRIPTION "a lite p2p library")

enable_language(C CXX ASM)

add_compile_options(-Wall)
add_library(lite-p2p)

file(GLOB lite_p2p_HEADERS ${CMAKE_CURRENT_LIST_DIR}/include/lite-p2p/*.hpp)

include(FetchContent)
if (ANDROID)
    FetchContent_Declare(
        android_openssl
        DOWNLOAD_EXTRACT_TIMESTAMP true
        URL https://github.com/KDAB/android_openssl/archive/refs/heads/master.zip
    )
    FetchContent_MakeAvailable(android_openssl)
    target_include_directories(lite-p2p PUBLIC
        ${android_openssl_SOURCE_DIR}/ssl_3/${CMAKE_ANDROID_ARCH_ABI}/include
    )
    target_link_libraries(lite-p2p PUBLIC
        ${android_openssl_SOURCE_DIR}/ssl_3/${CMAKE_ANDROID_ARCH_ABI}/libssl.a
        ${android_openssl_SOURCE_DIR}/ssl_3/${CMAKE_ANDROID_ARCH_ABI}/libcrypto.a
    )
    target_compile_definitions(lite-p2p PUBLIC
        QT_ANDROID_MIN_SDK_VERSION=24
    )
endif()

find_package(OpenSSL)


set_target_properties(lite-p2p PROPERTIES
VERSION ${PROJECT_VERSION}
PUBLIC_HEADER "${lite_p2p_HEADERS}"
SOVERSION 1
)

target_include_directories(lite-p2p PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/include
)

target_sources(lite-p2p PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/lib/peer_connection.cpp
    ${CMAKE_CURRENT_LIST_DIR}/lib/stun_client.cpp
    ${CMAKE_CURRENT_LIST_DIR}/lib/turn_client.cpp
    ${CMAKE_CURRENT_LIST_DIR}/lib/ice_agent.cpp
    ${CMAKE_CURRENT_LIST_DIR}/lib/network.cpp
    ${CMAKE_CURRENT_LIST_DIR}/lib/crypto.cpp
)


if (DEFINED LITE_P2P_TEST_TOOLS)
add_executable(stun-client)
target_include_directories(stun-client PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/include
)

target_sources(stun-client PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/test/stun-client.cpp
)

target_link_libraries(stun-client lite-p2p)

install(TARGETS stun-client
    DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
)

add_executable(turn-client)
target_include_directories(turn-client PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/include
)

target_sources(turn-client PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/test/turn-client.cpp
)

target_link_libraries(turn-client lite-p2p)

install(TARGETS turn-client
    DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
)
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

