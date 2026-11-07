project(rsnativekit_security)
cmake_minimum_required(VERSION 3.9.0)

set(PACKAGE_NAME rsnativekit_security)
set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_STANDARD 20)

# Define C++ library and add all sources
add_library(${PACKAGE_NAME} SHARED src/main/cpp/cpp-adapter.cpp src/main/cpp/native-checks.cpp)

# Add Nitrogen specs: android/build.gradle passes the tree matching the app's
# react-native-nitro-modules version (see ../nitro-compat.json).
if(NOT DEFINED RS_NITROGEN_DIR)
  set(RS_NITROGEN_DIR generated)
endif()
include(${CMAKE_SOURCE_DIR}/../nitrogen/${RS_NITROGEN_DIR}/android/rsnativekit_security+autolinking.cmake)

# Set up local includes
include_directories("src/main/cpp" "../cpp")

find_library(LOG_LIB log)

# Link all libraries together
target_link_libraries(
        ${PACKAGE_NAME}
        ${LOG_LIB}
        android # <-- Android core
)
