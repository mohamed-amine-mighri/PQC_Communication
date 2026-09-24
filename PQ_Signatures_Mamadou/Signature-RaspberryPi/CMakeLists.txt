cmake_minimum_required(VERSION 3.10)
project(dsa_local C)

set(CMAKE_C_STANDARD 11)

# ---------------- liboqs ----------------
find_library(OQS_LIB oqs PATHS /usr/local/lib /usr/lib REQUIRED)
include_directories(/usr/local/include ${CMAKE_SOURCE_DIR})

add_executable(dsa_local DSA-Test-local.c)
target_link_libraries(dsa_local PRIVATE ${OQS_LIB})

# (Optionnel) pingpong UART si tu veux le garder
find_library(WIRINGPI_LIB wiringPi)
if(WIRINGPI_LIB)
  add_executable(pingpong pingpong.c)
  target_link_libraries(pingpong PRIVATE ${WIRINGPI_LIB})
endif()

# ---------------- OpenSSL (RSA ref) ----------------
# Pour activer: cmake -DUSE_OPENSSL=ON ..
option(USE_OPENSSL "Enable OpenSSL RSA reference" OFF)

if(USE_OPENSSL)
  find_package(OpenSSL REQUIRED)

  # Active le #ifdef USE_OPENSSL dans ton code C
  target_compile_definitions(dsa_local PRIVATE USE_OPENSSL)

  # Inclut headers OpenSSL (souvent déjà inclus via OpenSSL::Crypto, mais sûr)
  target_include_directories(dsa_local PRIVATE ${OPENSSL_INCLUDE_DIR})

  # Link libcrypto
  target_link_libraries(dsa_local PRIVATE OpenSSL::Crypto)
endif()
