cmake_minimum_required(VERSION 3.10)
project(sldms3fs)

# Add this line to set the required file offset bits
add_definitions(-D_FILE_OFFSET_BITS=64)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add cmake modules path
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")

# Find required packages
find_package(FUSE REQUIRED)
find_package(CURL REQUIRED)
find_package(RocksDB REQUIRED)

# Add include directories
include_directories(
    ${FUSE_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
    ${ROCKSDB_INCLUDE_DIRS}
    ${CMAKE_SOURCE_DIR}
)

# Add debug symbols and disable optimization for debug build
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -O0")
# -fsanitize=address

# Add debug build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

# Print the build type
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

# Optional: Add sanitizers for better debugging
if(CMAKE_BUILD_TYPE MATCHES Debug)
    message(STATUS "Adding debug flags and sanitizers")
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address)
endif()

# Create the executable
add_executable(sldms3fs 
    main.cpp
    sldms3fs.cpp
    sldms3fs_cache.cpp
)

# Link libraries
target_link_libraries(sldms3fs
    ${FUSE_LIBRARIES}
    ${CURL_LIBRARIES}
    ${ROCKSDB_LIBRARIES}
    pthread
)

# Print FUSE paths for debugging
message(STATUS "FUSE include dir: ${FUSE_INCLUDE_DIR}")
message(STATUS "FUSE libraries: ${FUSE_LIBRARIES}") 