set(PN uv)

cmake_minimum_required(VERSION 3.20)
project(${PN} CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(SOURCE_DIR src)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PAM REQUIRED pam)

add_library(uv_process
    ${SOURCE_DIR}/cancellable_process.cpp
)
target_include_directories(uv_process PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/..
)

add_library(${PN}
    ${SOURCE_DIR}/auth.cpp
    ${SOURCE_DIR}/auth_handler.cpp
)
target_include_directories(${PN} PRIVATE ${PAM_INCLUDE_DIRS})
target_include_directories(uv PRIVATE
      ${CMAKE_CURRENT_SOURCE_DIR}/..
)
target_link_libraries(${PN} PRIVATE
    ${PAM_LIBRARIES}
    uv_process
)
