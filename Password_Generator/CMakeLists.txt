cmake_minimum_required(VERSION 3.20)
project(C_Project C)

# Add path for custom modules
set(CMAKE_MODULE_PATH
  ${CMAKE_MODULE_PATH}
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake"
  )

include(CompilerSetup)

add_executable(executable
  main.c
  alphabet.h
  alphabet.c
  information_content.h
  information_content.c
  pw_generator.c
  pw_generator.h
  )

enable_c_warnings_for(executable)
link_math_library(executable)