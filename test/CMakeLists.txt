cmake_minimum_required(VERSION 3.0)

project(liteP2P VERSION 1.0.1 DESCRIPTION "a lite p2p library")

enable_language(C CXX ASM)

add_compile_options(-Wall -O3)

include(FetchContent)

add_executable(stun-client)
target_include_directories(stun-client PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/include
)

target_sources(stun-client PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/stun-client.cpp
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
    ${CMAKE_CURRENT_LIST_DIR}/turn-client.cpp
)

target_link_libraries(turn-client lite-p2p)

install(TARGETS turn-client
    DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
)

add_executable(lite-crypto)
target_include_directories(lite-crypto PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/include
)

target_sources(lite-crypto PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/lite-crypto.cpp
)

target_link_libraries(lite-crypto lite-p2p)

install(TARGETS lite-crypto
    DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
)

add_executable(lite-crypto-time)
target_include_directories(lite-crypto-time PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/include
)

target_sources(lite-crypto-time PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/lite-crypto-time.cpp
)

target_link_libraries(lite-crypto-time lite-p2p)

install(TARGETS lite-crypto-time
    DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
)