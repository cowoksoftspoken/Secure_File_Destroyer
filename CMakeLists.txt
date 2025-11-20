cmake_minimum_required(VERSION 3.15)
project(secure_delete LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/src)

set(SRC_COMMON
    src/main.cpp
    src/utils.cpp
    src/algorithms.cpp
    src/folder_delete.cpp
    src/ssd_erase.cpp
)

if (WIN32)
    set(PLATFORM_SRC platform/win_delete.cpp)
else()
    set(PLATFORM_SRC platform/posix_delete.cpp)
endif()

add_executable(secure-delete
    ${SRC_COMMON}
    ${PLATFORM_SRC}
)

if (WIN32)
    target_link_libraries(secure-delete ws2_32)
endif()

enable_testing()

file(GLOB TEST_SOURCES test/*.cpp)

foreach(test_file ${TEST_SOURCES})
    get_filename_component(test_name ${test_file} NAME_WE)

    add_executable(${test_name}
        ${test_file}
        src/utils.cpp
        src/algorithms.cpp
        src/folder_delete.cpp
        ${PLATFORM_SRC}
    )

    target_include_directories(${test_name} PRIVATE include)

    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()
