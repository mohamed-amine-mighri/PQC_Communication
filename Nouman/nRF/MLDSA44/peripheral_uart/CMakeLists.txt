#
# Copyright (c) 2018 Nordic Semiconductor
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(peripheral_uart)

# Pull in every .c file under the ML-DSA-44 and common PQClean folders.
# CONFIGURE_DEPENDS makes CMake re-scan the folder on the next build if you
# add/remove files, but a `west build -p` (pristine) is still the safe way
# to force a full reconfigure if a new file doesn't get picked up.
file(GLOB PQCLEAN_MLDSA44_SOURCES CONFIGURE_DEPENDS
  ${CMAKE_CURRENT_SOURCE_DIR}/src/pqclean/mldsa44/*.c
)
file(GLOB PQCLEAN_COMMON_SOURCES CONFIGURE_DEPENDS
  ${CMAKE_CURRENT_SOURCE_DIR}/src/pqclean/common/*.c
)

# NORDIC SDK APP START
target_sources(app PRIVATE
  src/main.c
  ${PQCLEAN_MLDSA44_SOURCES}
  ${PQCLEAN_COMMON_SOURCES}
)

target_include_directories(app PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/src/pqclean/mldsa44
  ${CMAKE_CURRENT_SOURCE_DIR}/src/pqclean/common
)
# NORDIC SDK APP END