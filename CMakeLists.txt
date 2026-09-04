set(PN vauth)

cmake_minimum_required(VERSION 3.20)
project(${PN} CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(SOURCE_DIR src)

include(CTest)

add_subdirectory(${SOURCE_DIR}/uv)

find_package(PkgConfig REQUIRED)
find_package(sdbus-c++ CONFIG REQUIRED)
pkg_check_modules(SYSTEMD REQUIRED IMPORTED_TARGET libsystemd)

add_library(vauth_dbus
    ${SOURCE_DIR}/dbus/agent_registry.cpp
    ${SOURCE_DIR}/dbus/agent_service.cpp
    ${SOURCE_DIR}/dbus/interaction_registry.cpp
    ${SOURCE_DIR}/dbus/secret_pipe.cpp
)
target_include_directories(vauth_dbus PUBLIC ${SOURCE_DIR})
target_compile_definitions(vauth_dbus PRIVATE
    $<$<CONFIG:Debug>:DEBUG>
)
target_link_libraries(vauth_dbus PUBLIC
    SDBusCpp::sdbus-c++
    PkgConfig::SYSTEMD
)

add_library(ctaphid_frame_processor
    ${SOURCE_DIR}/frame_processor.cpp
)
target_include_directories(ctaphid_frame_processor PUBLIC ${SOURCE_DIR})

add_library(ctaphid_packet
    ${SOURCE_DIR}/packet.cpp
)
target_include_directories(ctaphid_packet PUBLIC ${SOURCE_DIR})

add_executable(${PN}
    # Uncategorized
    ${SOURCE_DIR}/${PN}.cpp
    ${SOURCE_DIR}/event.cpp
    ${SOURCE_DIR}/response.cpp
    ${SOURCE_DIR}/device.cpp
    # Registration
    ${SOURCE_DIR}/registration/registration.cpp
    ${SOURCE_DIR}/registration/make_credential_response.cpp
    # Credential storing
    ${SOURCE_DIR}/credentials/credential.cpp
    # Cryptography operations
    ${SOURCE_DIR}/cryptography/crypto.cpp
    ${SOURCE_DIR}/cryptography/store_security.cpp
    ${SOURCE_DIR}/cryptography/tpm.cpp
    # Authentication
    ${SOURCE_DIR}/authentication/authenticate.cpp
    ${SOURCE_DIR}/authentication/get_assertion_response.cpp
    # CBOR Operations
    ${SOURCE_DIR}/cbor_operations/cbor.cpp
    ${SOURCE_DIR}/cbor_operations/cbor_utils.cpp
    ${SOURCE_DIR}/cbor_operations/make_cred_parsing.cpp
    ${SOURCE_DIR}/cbor_operations/get_assertion_parsing.cpp
)

target_compile_definitions(${PN} PRIVATE
    $<$<CONFIG:Debug>:DEBUG>
    $<$<CONFIG:Debug>:VAUTH_DEVELOPMENT_BUILD>
    $<$<CONFIG:Debug>:VAUTH_DEBUG_PAM_CONFIG_DIR="${PROJECT_SOURCE_DIR}/config">
)

pkg_check_modules(TINYCBOR REQUIRED tinycbor)
pkg_check_modules(OPENSSL REQUIRED openssl)
pkg_check_modules(TSS2_ESYS REQUIRED tss2-esys)
pkg_check_modules(TSS2_FAPI REQUIRED tss2-fapi)
pkg_check_modules(TSS2_RC REQUIRED tss2-rc)
pkg_check_modules(TSS2_MU REQUIRED tss2-mu)
target_include_directories(${PN} PRIVATE ${SOURCE_DIR})
target_include_directories(${PN} PRIVATE
    ${TINYCBOR_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
    ${TSS2_ESYS_INCLUDE_DIRS}
    ${TSS2_FAPI_INCLUDE_DIRS}
    ${TSS2_RC_INCLUDE_DIRS}
    ${TSS2_MU_INCLUDE_DIRS}
)
target_link_libraries(${PN} PRIVATE
    ${TINYCBOR_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${TSS2_ESYS_LIBRARIES}
    ${TSS2_FAPI_LIBRARIES}
    ${TSS2_RC_LIBRARIES}
    ${TSS2_MU_LIBRARIES}
    ctaphid_frame_processor
    ctaphid_packet
    uv
    vauth_dbus
)

option(
    VAUTH_BUILD_DEBUG_AGENT
    "Build the temporary console D-Bus user-interaction agent"
    ${BUILD_TESTING}
)
if(VAUTH_BUILD_DEBUG_AGENT)
    add_subdirectory(client)
endif()

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
