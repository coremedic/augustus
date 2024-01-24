cmake_minimum_required(VERSION 3.27)
project(augustus)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXE_LINKER_FLAGS "-static")
include_directories(include)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_definitions(-DDEBUG)
endif()

add_executable(augustus src/main.cpp
        src/aes.c
        include/aes.h
        include/aes.hpp
        include/structs.hpp)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set_target_properties(augustus PROPERTIES WIN32_EXECUTABLE TRUE)
endif()