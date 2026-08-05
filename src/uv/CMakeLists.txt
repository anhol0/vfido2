set(PN uv)

cmake_minimum_required(VERSION 3.20)
project(${PN} CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(SOURCE_DIR src)

add_library(${PN}
    ${SOURCE_DIR}/auth.cpp
)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PAM REQUIRED pam)
target_include_directories(${PN} PUBLIC ${PAM_INCLUDE_DIRS})
target_compile_options(${PN} PRIVATE -g)
target_link_libraries(${PN} PRIVATE
    ${PAM_LIBRARIES}
)
