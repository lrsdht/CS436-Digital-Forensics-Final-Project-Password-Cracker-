cmake_minimum_required(VERSION 3.16)
project(password_cracker LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(cracker
  main.cpp
  attacks.cpp
)

target_include_directories(cracker PRIVATE ${CMAKE_SOURCE_DIR})

# Optional: if you want code to reliably find repo files regardless of working dir:
target_compile_definitions(cracker PRIVATE PROJECT_ROOT="${CMAKE_SOURCE_DIR}")

# Link filesystem library if needed (for some compilers/platforms)
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.0)
    target_link_libraries(cracker stdc++fs)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.0)
    target_link_libraries(cracker c++fs)
endif()