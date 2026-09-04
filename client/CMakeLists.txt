cmake_minimum_required(VERSION 3.20)
project(vauth_client LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(sdbus-c++ CONFIG REQUIRED)

add_executable(vauth-agent-debug
    debug_agent.cpp
)
target_include_directories(vauth-agent-debug PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
)
target_link_libraries(vauth-agent-debug PRIVATE
    SDBusCpp::sdbus-c++
)
set_target_properties(vauth-agent-debug PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
)
