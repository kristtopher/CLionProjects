cmake_minimum_required(VERSION 3.9)
project(rc4)

set(CMAKE_CXX_STANDARD 11)

add_executable(rc4 main.cpp rc4.h rc4.cpp)