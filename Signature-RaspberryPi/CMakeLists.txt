cmake_minimum_required(VERSION 3.10)
project(dsa C)

set(CMAKE_C_STANDARD 11)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# MQTT comm
find_library(MQTT_LIB NAMES paho-mqtt3c paho-mqtt3c-static PATHS /usr/lib /usr/lib/x86_64-linux-gnu /usr/lib/aarch64-linux-gnu)
if(NOT MQTT_LIB)
    find_package(PahoMqttC REQUIRED)
    set(MQTT_LIB PahoMqttC::PahoMqttC)
endif()
include_directories(/usr/include ${CMAKE_SOURCE_DIR})

# UART comm - optional for WSL/cross-platform
find_library(WIRINGPI_LIB wiringPi PATHS /usr/lib /usr/local/lib)
if(WIRINGPI_LIB)
    message(STATUS "Found wiringPi: ${WIRINGPI_LIB}")
else()
    message(STATUS "wiringPi not found - building for WSL/cross-platform mode")
    set(WIRINGPI_LIB "")
endif()

# ML-KEM lib
find_library(OQS_LIB oqs PATHS /usr/lib /usr/local/lib /usr/lib/x86_64-linux-gnu /usr/lib/aarch64-linux-gnu)
include_directories(/usr/local/include ${CMAKE_SOURCE_DIR}) 

# Test program for UART
if(WIRINGPI_LIB)
    add_executable(pingpong pingpong.c)
    target_link_libraries(pingpong PRIVATE ${WIRINGPI_LIB})
endif()

# ML-KEM exec client
add_executable(DSA_tests DSA-Test.c transport.c queue.c)
target_link_libraries(DSA_tests ${OQS_LIB} ${MQTT_LIB} OpenSSL::Crypto)
if(WIRINGPI_LIB)
    target_link_libraries(DSA_tests ${WIRINGPI_LIB})
endif()