cmake_minimum_required(VERSION 3.20)
project(ffido CXX)

set(CMAKE_CXX_STANDARD 20)

add_executable(ffido
    src/ffido.cpp
)

find_package(PkgConfig REQUIRED)
pkg_check_modules(TINYCBOR REQUIRED tinycbor)

target_include_directories(ffido PRIVATE
    ${TINYCBOR_INCLUDE_DIRS},
)
target_compile_options(ffido PRIVATE -g)
target_link_libraries(ffido PRIVATE
    ${TINYCBOR_LIBRARIES}
)
