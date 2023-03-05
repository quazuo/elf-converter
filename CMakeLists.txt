cmake_minimum_required(VERSION 3.16)
project(converter)

set(CMAKE_CXX_STANDARD 20)

include(FindPkgConfig)

add_executable(converter main.cpp convert.h const.h struct.h convert.cpp)

pkg_check_modules (CAPSTONE REQUIRED capstone)

# Use CAPSTONE_FOUND, CAPSTONE_LIBRARIES, CAPSTONE_INCLUDE_DIRS vars
target_link_libraries(${PROJECT_NAME} ${CAPSTONE_LIBRARIES})

pkg_check_modules (KEYSTONE REQUIRED keystone)

# Use KEYSTONE_FOUND, KEYSTONE_LIBRARIES, KEYSTONE_INCLUDE_DIRS vars
target_link_libraries(${PROJECT_NAME} ${KEYSTONE_LIBRARIES})


