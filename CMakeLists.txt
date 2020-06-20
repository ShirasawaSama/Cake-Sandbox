cmake_minimum_required(VERSION 3.13)
project(cake_sandbox)

set(CMAKE_CXX_STANDARD 17)

aux_source_directory(${PROJECT_SOURCE_DIR}/src src)
add_executable(cake_sandbox ${src})