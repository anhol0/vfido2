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
