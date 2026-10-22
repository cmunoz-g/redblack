cmake_minimum_required(VERSION 3.25...4.2.3)
project(redblack VERSION 1.0 LANGUAGES C)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

add_compile_options(-Wall -Wextra -fsanitize=address,undefined)
add_link_options(-fsanitize=address,undefined)

add_library(rbcore STATIC core.c)
target_link_libraries(rbcore PRIVATE OpenSSL::Crypto)
target_include_directories(rbcore PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_executable(redblack main.c)
target_link_libraries(redblack PRIVATE rbcore)

add_executable(test_core test.c)
target_link_libraries(test_core PRIVATE rbcore)

enable_testing()
add_test(NAME core COMMAND test_core)
