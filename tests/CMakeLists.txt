add_executable(frame_processor_tests
    frame_processor_test.cpp
)

target_link_libraries(frame_processor_tests PRIVATE
    ctaphid_frame_processor
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
