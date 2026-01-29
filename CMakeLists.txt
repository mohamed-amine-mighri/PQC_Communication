cmake_minimum_required(VERSION 3.10)
project(dsa C)

set(CMAKE_C_STANDARD 11)

# MQTT comm
find_library(MQTT_LIB NAMES paho-mqtt3c PATHS /usr/lib/aarch64-linux-gnu/libpaho-mqtt3c.so REQUIRED)
include_directories(/usr/include ${CMAKE_SOURCE_DIR})


# UART comm
find_library(WIRINGPI_LIB wiringPi REQUIRED) 

# ML-KEM lib
find_library(OQS_LIB oqs PATHS /usr/local/lib)
include_directories(/usr/local/include ${CMAKE_SOURCE_DIR}) 

# Test prorgam for UART
add_executable(pingpong pingpong.c)
target_link_libraries(pingpong PRIVATE ${WIRINGPI_LIB})

# ML-KEM exec client
add_executable(DSA_tests DSA-Test.c transport.c queue.c)
target_link_libraries(DSA_tests ${WIRINGPI_LIB} ${OQS_LIB} ${MQTT_LIB})