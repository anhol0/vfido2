add_executable(frame_processor_tests
    frame_processor_test.cpp
)

target_link_libraries(frame_processor_tests PRIVATE
    ctaphid_frame_processor
    ctaphid_packet
)

add_test(
    NAME frame_processor
    COMMAND frame_processor_tests
)

add_executable(request_parsing_tests
    request_parsing_test.cpp
    ${PROJECT_SOURCE_DIR}/src/cbor_operations/cbor_utils.cpp
    ${PROJECT_SOURCE_DIR}/src/registration/registration.cpp
    ${PROJECT_SOURCE_DIR}/src/cbor_operations/make_cred_parsing.cpp
    ${PROJECT_SOURCE_DIR}/src/authentication/authenticate.cpp
    ${PROJECT_SOURCE_DIR}/src/cbor_operations/get_assertion_parsing.cpp
)

target_include_directories(request_parsing_tests PRIVATE
    ${PROJECT_SOURCE_DIR}/src
    ${TINYCBOR_INCLUDE_DIRS}
)

target_link_libraries(request_parsing_tests PRIVATE
    ${TINYCBOR_LIBRARIES}
)

add_test(
    NAME request_parsing
    COMMAND request_parsing_tests
)

add_executable(cbor_response_tests
    cbor_response_test.cpp
    ${PROJECT_SOURCE_DIR}/src/cbor_operations/cbor.cpp
    ${PROJECT_SOURCE_DIR}/src/cbor_operations/cbor_utils.cpp
)

target_include_directories(cbor_response_tests PRIVATE
    ${PROJECT_SOURCE_DIR}/src
    ${TINYCBOR_INCLUDE_DIRS}
)

target_link_libraries(cbor_response_tests PRIVATE
    ${TINYCBOR_LIBRARIES}
)

add_test(
    NAME cbor_response
    COMMAND cbor_response_tests
)

add_executable(uv_process_tests
    uv_process_test.cpp
)

target_include_directories(uv_process_tests PRIVATE
    ${PROJECT_SOURCE_DIR}/src
)

target_link_libraries(uv_process_tests PRIVATE
    uv_process
)

add_test(
    NAME uv_process
    COMMAND uv_process_tests
)

add_executable(crypto_tests
    crypto_test.cpp
    ${PROJECT_SOURCE_DIR}/src/cryptography/crypto.cpp
    ${PROJECT_SOURCE_DIR}/src/credentials/credential.cpp
)

target_include_directories(crypto_tests PRIVATE
    ${PROJECT_SOURCE_DIR}/src
    ${OPENSSL_INCLUDE_DIRS}
)

target_compile_definitions(crypto_tests PRIVATE
    VFIDO_DEVELOPMENT_BUILD
)

target_link_libraries(crypto_tests PRIVATE
    ${OPENSSL_LIBRARIES}
)

add_test(
    NAME crypto
    COMMAND crypto_tests
)

add_executable(store_security_integration_tests
    store_security_integration_test.cpp
    ${PROJECT_SOURCE_DIR}/src/cryptography/crypto.cpp
    ${PROJECT_SOURCE_DIR}/src/cryptography/store_security.cpp
    ${PROJECT_SOURCE_DIR}/src/cryptography/tpm.cpp
    ${PROJECT_SOURCE_DIR}/src/credentials/credential.cpp
)

target_include_directories(store_security_integration_tests PRIVATE
    ${PROJECT_SOURCE_DIR}/src
    ${OPENSSL_INCLUDE_DIRS}
    ${TSS2_ESYS_INCLUDE_DIRS}
    ${TSS2_FAPI_INCLUDE_DIRS}
    ${TSS2_MU_INCLUDE_DIRS}
    ${TSS2_RC_INCLUDE_DIRS}
)

target_compile_definitions(store_security_integration_tests PRIVATE
    VFIDO_DEVELOPMENT_BUILD
)

target_link_libraries(store_security_integration_tests PRIVATE
    ${OPENSSL_LIBRARIES}
    ${TSS2_ESYS_LIBRARIES}
    ${TSS2_FAPI_LIBRARIES}
    ${TSS2_MU_LIBRARIES}
    ${TSS2_RC_LIBRARIES}
)

find_program(SWTPM_EXECUTABLE swtpm)
find_program(SWTPM_IOCTL_EXECUTABLE swtpm_ioctl)
find_program(TPM2_STARTUP_EXECUTABLE tpm2_startup)
find_program(TPM2_CLEAR_EXECUTABLE tpm2_clear)
find_program(TPM2_FLUSHCONTEXT_EXECUTABLE tpm2_flushcontext)
find_program(TPM2_NVDEFINE_EXECUTABLE tpm2_nvdefine)
find_program(TPM2_NVINCREMENT_EXECUTABLE tpm2_nvincrement)
find_program(TPM2_NVUNDEFINE_EXECUTABLE tpm2_nvundefine)
find_program(TSS2_PROVISION_EXECUTABLE tss2_provision)

if(
    SWTPM_EXECUTABLE AND
    SWTPM_IOCTL_EXECUTABLE AND
    TPM2_STARTUP_EXECUTABLE AND
    TPM2_CLEAR_EXECUTABLE AND
    TPM2_FLUSHCONTEXT_EXECUTABLE AND
    TPM2_NVDEFINE_EXECUTABLE AND
    TPM2_NVINCREMENT_EXECUTABLE AND
    TPM2_NVUNDEFINE_EXECUTABLE AND
    TSS2_PROVISION_EXECUTABLE
)
    add_test(
        NAME store_security_swtpm
        COMMAND bash
            ${CMAKE_CURRENT_SOURCE_DIR}/swtpm_integration_test.sh
            $<TARGET_FILE:store_security_integration_tests>
            /etc/tpm2-tss/fapi-profiles/
    )
endif()
