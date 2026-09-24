#
# Copyright (c) 2018 Nordic Semiconductor
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(peripheral_uart)

file(GLOB PQCLEAN_FALCON512_SOURCES CONFIGURE_DEPENDS
  ${CMAKE_CURRENT_SOURCE_DIR}/src/pqclean/falcon512/*.c
)
file(GLOB PQCLEAN_COMMON_SOURCES CONFIGURE_DEPENDS
  ${CMAKE_CURRENT_SOURCE_DIR}/src/pqclean/common/*.c
)

# NORDIC SDK APP START
target_sources(app PRIVATE
  src/main.c
  ${PQCLEAN_FALCON512_SOURCES}
  ${PQCLEAN_COMMON_SOURCES}
)

target_include_directories(app PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/src/pqclean/falcon512
  ${CMAKE_CURRENT_SOURCE_DIR}/src/pqclean/common
)
# NORDIC SDK APP END