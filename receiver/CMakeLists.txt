cmake_minimum_required(VERSION 3.9)
project(receiver)

set(CMAKE_CXX_STANDARD 11)
set(LIB -lbluetooth)
set(LIB2 /usr/local/lib/libtomcrypt.a)

add_executable(receiver main.cpp)

target_link_libraries(receiver ${LIB} ${LIB2})
