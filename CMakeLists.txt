set(PN vfido)

cmake_minimum_required(VERSION 3.20)
project(${PN} CXX)

set(CMAKE_CXX_STANDARD 20)

add_executable(${PN}
    src/${PN}.cpp
    src/event.cpp
    src/response.cpp
    src/registration.cpp
    src/make_cred_parsing.cpp
    src/make_authmakecred_response.cpp
    src/device.cpp
    src/crypto.cpp
    src/cbor.cpp
    src/credential.cpp
    src/tpm.cpp
)

find_package(PkgConfig REQUIRED)
pkg_check_modules(TINYCBOR REQUIRED tinycbor)
pkg_check_modules(OPENSSL REQUIRED openssl)
pkg_check_modules(TSS2_ESYS REQUIRED tss2-esys)
pkg_check_modules(TSS2_RC REQUIRED tss2-rc)
target_include_directories(${PN} PRIVATE
    ${TINYCBOR_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
    ${TSS2_ESYS_INCLUDE_DIRS}
    ${TSS2_RC_INCLUDE_DIRS}
)
target_compile_options(${PN} PRIVATE -g)
target_link_libraries(${PN} PRIVATE
    ${TINYCBOR_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${TSS2_ESYS_LIBRARIES}
    ${TSS2_RC_LIBRARIES}
)
