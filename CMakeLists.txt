cmake_minimum_required(VERSION 3.21.0)


project(liteP2P  VERSION 1.0.1 DESCRIPTION "a lite p2p library")

enable_language(C CXX ASM)

add_library(lite-p2p)

add_executable(stun-client)

target_include_directories(lite-p2p PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/lib
)

target_sources(lite-p2p PRIVATE
     ${CMAKE_CURRENT_LIST_DIR}/lib/peer_connection.cpp
     ${CMAKE_CURRENT_LIST_DIR}/lib/stun_client.cpp
)

target_include_directories(stun-client PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/lib
)

target_sources(stun-client PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/test/stun-client.cpp
)

target_link_libraries(stun-client lite-p2p)
