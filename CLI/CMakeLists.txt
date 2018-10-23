cmake_minimum_required(VERSION 3.9)
project(CLI)

set(CMAKE_CXX_STANDARD 11)

add_executable(CLI main.cpp Node.h Node.cpp)