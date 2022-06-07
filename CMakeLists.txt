cmake_minimum_required(VERSION 3.5)

add_subdirectory("./drivers")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(main)
