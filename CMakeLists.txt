cmake_minimum_required(VERSION 3.0)

project(HRACS)

include_directories(Header)

add_executable(build main.cpp)

link_directories(/usr/local/lib /lib/x86_64-linux-gnu/ /usr/include)
target_link_libraries(build pbc gmp cryptopp ssl crypto sodium)

set(CMAKE_BUILD_TYPE Debug)