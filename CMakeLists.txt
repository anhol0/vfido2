set(PN vfido)

cmake_minimum_required(VERSION 3.20)
project(${PN} CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(SOURCE_DIR src)


add_executable(${PN}
    # Uncategorized
    ${SOURCE_DIR}/${PN}.cpp
    ${SOURCE_DIR}/event.cpp
    ${SOURCE_DIR}/response.cpp
    ${SOURCE_DIR}/device.cpp
    # Registration
    ${SOURCE_DIR}/registration/registration.cpp
    ${SOURCE_DIR}/registration/make_authmakecred_response.cpp
    # Credential storing
    ${SOURCE_DIR}/credentials/credential.cpp
    # Cryptography operations
    ${SOURCE_DIR}/cryptography/crypto.cpp
    ${SOURCE_DIR}/cryptography/tpm.cpp
    # Authentication
    ${SOURCE_DIR}/authentication/authenticate.cpp
    ${SOURCE_DIR}/authentication/get_assertion_parsing.cpp
    # CBOR Operations
    ${SOURCE_DIR}/cbor_operations/cbor.cpp
    ${SOURCE_DIR}/cbor_operations/make_cred_parsing.cpp
)

find_package(PkgConfig REQUIRED)
pkg_check_modules(TINYCBOR REQUIRED tinycbor)
pkg_check_modules(OPENSSL REQUIRED openssl)
pkg_check_modules(TSS2_ESYS REQUIRED tss2-esys)
pkg_check_modules(TSS2_RC REQUIRED tss2-rc)
pkg_check_modules(TSS2_MU REQUIRED tss2-mu)
target_include_directories(${PN} PRIVATE ${SOURCE_DIR})
target_include_directories(${PN} PRIVATE
    ${TINYCBOR_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
    ${TSS2_ESYS_INCLUDE_DIRS}
    ${TSS2_RC_INCLUDE_DIRS}
    ${TSS2_MU_INCLUDE_DIRS}
)
target_compile_options(${PN} PRIVATE -g)
target_link_libraries(${PN} PRIVATE
    ${TINYCBOR_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${TSS2_ESYS_LIBRARIES}
    ${TSS2_RC_LIBRARIES}
    ${TSS2_MU_LIBRARIES}
)
