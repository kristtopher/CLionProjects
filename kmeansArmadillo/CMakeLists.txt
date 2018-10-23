cmake_minimum_required(VERSION 3.9)
project(kmeansArmadillo)

set(CMAKE_CXX_STANDARD 11)
set (CMAKE_CXX_FLAGS "-larmadillo")
#set (CMAKE_CXX_FLAGS "-larmadillo -fopenmp")

add_executable(kmeansArmadillo main.cpp)