cmake_minimum_required(VERSION 3.21)
project(vauth_client LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(CTest)

find_package(sdbus-c++ CONFIG REQUIRED)

option(VAUTH_BUILD_UI "Build the Slint vAuth user-interaction agent" ON)
option(
    VAUTH_BUILD_DEBUG_AGENT
    "Build the temporary console D-Bus user-interaction agent"
    ${BUILD_TESTING}
)

if(VAUTH_BUILD_UI)
    find_package(Slint REQUIRED)
    find_package(rlottie REQUIRED)

    file(READ
        "${CMAKE_CURRENT_SOURCE_DIR}/assets/fingerprint_waiting.json"
        VAUTH_FINGERPRINT_WAITING_JSON
    )
    file(READ
        "${CMAKE_CURRENT_SOURCE_DIR}/assets/fingerprint_success.json"
        VAUTH_FINGERPRINT_SUCCESS_JSON
    )
    file(READ
        "${CMAKE_CURRENT_SOURCE_DIR}/assets/fingerprint_failure.json"
        VAUTH_FINGERPRINT_FAILURE_JSON
    )
    configure_file(
        animation_data.hpp.in
        "${CMAKE_CURRENT_BINARY_DIR}/generated/animation_data.hpp"
        @ONLY
    )

    add_executable(vauth-ui
        main.cpp
        agent_client.cpp
        interaction_model.cpp
    )
    slint_target_sources(vauth-ui ui/appwindow.slint)
    target_include_directories(vauth-ui PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../src
        ${CMAKE_CURRENT_BINARY_DIR}/generated
    )
    target_link_libraries(vauth-ui PRIVATE
        Slint::Slint
        SDBusCpp::sdbus-c++
        rlottie::rlottie
    )
    target_compile_definitions(vauth-ui PRIVATE
        $<$<CONFIG:Debug>:DEBUG>
    )
    set_target_properties(vauth-ui PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    )
endif()

if(VAUTH_BUILD_DEBUG_AGENT)
    add_executable(vauth-agent-debug
        debug_agent.cpp
    )
    target_include_directories(vauth-agent-debug PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../src
    )
    target_link_libraries(vauth-agent-debug PRIVATE
        SDBusCpp::sdbus-c++
    )
    set_target_properties(vauth-agent-debug PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    )
endif()

if(BUILD_TESTING)
    add_executable(ui_model_tests
        tests/interaction_model_test.cpp
        interaction_model.cpp
    )
    target_include_directories(ui_model_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../tests
    )
    add_test(NAME ui_model COMMAND ui_model_tests)
endif()
