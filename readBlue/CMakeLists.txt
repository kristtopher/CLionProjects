cmake_minimum_required(VERSION 3.8)
project(readBlue)

set(CMAKE_CXX_STANDARD 11)

set(LIB /usr/local/lib/libtomcrypt.a)

add_executable(readBlue main.cpp)

target_link_libraries(readBlue ${LIB})