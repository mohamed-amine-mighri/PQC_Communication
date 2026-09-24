# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file LICENSE.rst or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION ${CMAKE_VERSION}) # this file comes with cmake

# If CMAKE_DISABLE_SOURCE_CHANGES is set to true and the source directory is an
# existing directory in our source tree, calling file(MAKE_DIRECTORY) on it
# would cause a fatal error, even though it would be a no-op.
if(NOT EXISTS "C:/peripheral_uart")
  file(MAKE_DIRECTORY "C:/peripheral_uart")
endif()
file(MAKE_DIRECTORY
  "C:/peripheral_uart/build/peripheral_uart"
  "C:/peripheral_uart/build/_sysbuild/sysbuild/images/peripheral_uart-prefix"
  "C:/peripheral_uart/build/_sysbuild/sysbuild/images/peripheral_uart-prefix/tmp"
  "C:/peripheral_uart/build/_sysbuild/sysbuild/images/peripheral_uart-prefix/src/peripheral_uart-stamp"
  "C:/peripheral_uart/build/_sysbuild/sysbuild/images/peripheral_uart-prefix/src"
  "C:/peripheral_uart/build/_sysbuild/sysbuild/images/peripheral_uart-prefix/src/peripheral_uart-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "C:/peripheral_uart/build/_sysbuild/sysbuild/images/peripheral_uart-prefix/src/peripheral_uart-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "C:/peripheral_uart/build/_sysbuild/sysbuild/images/peripheral_uart-prefix/src/peripheral_uart-stamp${cfgdir}") # cfgdir has leading slash
endif()
