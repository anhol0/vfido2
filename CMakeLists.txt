set(PN vfido)

cmake_minimum_required(VERSION 3.20)
project(${PN} CXX)

set(CMAKE_CXX_STANDARD 20)

add_executable(${PN}
    src/${PN}.cpp
    src/response.cpp
    src/registration.cpp
    src/make_cred_parsing.cpp
    src/device.cpp
)

find_package(PkgConfig REQUIRED)
pkg_check_modules(TINYCBOR REQUIRED tinycbor)

target_include_directories(${PN} PRIVATE
    ${TINYCBOR_INCLUDE_DIRS},
)
target_compile_options(${PN} PRIVATE -g)
target_link_libraries(${PN} PRIVATE
    ${TINYCBOR_LIBRARIES}
)
