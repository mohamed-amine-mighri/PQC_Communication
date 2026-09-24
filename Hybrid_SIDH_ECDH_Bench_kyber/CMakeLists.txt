cmake_minimum_required(VERSION 3.16)
project(sike_masking C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if (CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
  add_compile_options(-Wall -Wextra -Wpedantic -Wno-deprecated-declarations)
endif()

# --- Options
option(USE_PQSIDH "Link with PQCrypto-SIDH (p434)" ON)
option(USE_PQSIDH_COMPRESSED "Use compressed p434 API" OFF)
option(USE_LIBOQS "Enable Kyber KEM targets (liboqs)" ON)
option(BUILD_DEMO "Build local demo target 'sike_demo' (no MQTT)" OFF)

# --- POSIX defs utiles
add_compile_definitions(_GNU_SOURCE _DEFAULT_SOURCE)

# --- Includes globaux de ton projet
include_directories(${CMAKE_SOURCE_DIR}/include)

# --- Détection clock_gettime (certains systèmes exigent -lrt)
include(CheckSymbolExists)
check_symbol_exists(clock_gettime "time.h" HAS_CLOCK_GETTIME)
if (NOT HAS_CLOCK_GETTIME)
  set(NEED_RT TRUE)
endif()

# --- OpenSSL, Threads
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# --- Mosquitto (avec ou sans pkg-config)
find_package(PkgConfig QUIET)
if (PkgConfig_FOUND)
  pkg_check_modules(MOSQ QUIET libmosquitto)
endif()
if (MOSQ_FOUND)
  add_library(mosquitto_unknown INTERFACE)
  target_include_directories(mosquitto_unknown INTERFACE ${MOSQ_INCLUDE_DIRS})
  target_link_libraries(mosquitto_unknown INTERFACE ${MOSQ_LIBRARIES})
else()
  find_library(MOSQUITTO_LIB mosquitto REQUIRED)
  find_path(MOSQUITTO_INCLUDE mosquitto.h
            HINTS /usr/include /usr/local/include /opt/homebrew/include)
  add_library(mosquitto_unknown INTERFACE)
  target_link_libraries(mosquitto_unknown INTERFACE ${MOSQUITTO_LIB})
  if (MOSQUITTO_INCLUDE)
    target_include_directories(mosquitto_unknown INTERFACE ${MOSQUITTO_INCLUDE})
  endif()
endif()

# --- PQCrypto-SIDH
set(SIDH_ROOT "$ENV{HOME}/PQCrypto-SIDH" CACHE PATH "Path to PQCrypto-SIDH root")
if (USE_PQSIDH)
  if (USE_PQSIDH_COMPRESSED)
    set(SIDH_LIB "${SIDH_ROOT}/lib434_compressed/libsidh.a")
  else()
    set(SIDH_LIB "${SIDH_ROOT}/lib434/libsidh.a")
  endif()
  if (NOT EXISTS "${SIDH_LIB}")
    message(FATAL_ERROR "libsidh.a introuvable: ${SIDH_LIB}\nSet SIDH_ROOT ou construis la lib avec 'make' dans ${SIDH_ROOT}.")
  endif()
endif()

# --- liboqs (une seule cible INTERFACE à réutiliser)
if (USE_LIBOQS AND NOT TARGET oqs_unknown)
  set(OQS_FOUND FALSE)
  if (PkgConfig_FOUND)
    pkg_check_modules(OQS QUIET liboqs)
    if (OQS_FOUND)
      add_library(oqs_unknown INTERFACE)
      target_include_directories(oqs_unknown INTERFACE ${OQS_INCLUDE_DIRS})
      target_link_libraries(oqs_unknown INTERFACE ${OQS_LIBRARIES})
    endif()
  endif()
  if (NOT OQS_FOUND)
    find_library(OQS_LIB oqs REQUIRED)
    find_path(OQS_INCLUDE_DIR oqs/oqs.h HINTS /usr/local/include /usr/include)
    add_library(oqs_unknown INTERFACE)
    target_link_libraries(oqs_unknown INTERFACE ${OQS_LIB})
    target_include_directories(oqs_unknown INTERFACE ${OQS_INCLUDE_DIR})
    set(OQS_FOUND TRUE)
  endif()
endif()

# ================= libs =================
# 1) code commun (masking/SIDH bridge)

# Résoudre les variantes de noms/emplacements
set(SHAKE_MASK_SRC "")
if (EXISTS "${CMAKE_SOURCE_DIR}/src/common/shake_mask.c")
  list(APPEND SHAKE_MASK_SRC src/common/shake_mask.c)
elseif (EXISTS "${CMAKE_SOURCE_DIR}/src/common/masking.c")
  list(APPEND SHAKE_MASK_SRC src/common/masking.c)
elseif (EXISTS "${CMAKE_SOURCE_DIR}/src/masking.c")
  list(APPEND SHAKE_MASK_SRC src/masking.c)
else()
  message(FATAL_ERROR "Aucun fichier de masking trouvé (shake_mask.c / masking.c).")
endif()

set(SIDH_BRIDGE_SRC "")
if (EXISTS "${CMAKE_SOURCE_DIR}/src/common/sidh_bridge.c")
  list(APPEND SIDH_BRIDGE_SRC src/common/sidh_bridge.c)
elseif (EXISTS "${CMAKE_SOURCE_DIR}/src/sidh_bridge.c")
  list(APPEND SIDH_BRIDGE_SRC src/sidh_bridge.c)
else()
  message(FATAL_ERROR "sidh_bridge.c introuvable.")
endif()

set(SIDH_HOOKS_SRC "")
if (EXISTS "${CMAKE_SOURCE_DIR}/src/common/sidh_bridge_hooks.c")
  list(APPEND SIDH_HOOKS_SRC src/common/sidh_bridge_hooks.c)
elseif (EXISTS "${CMAKE_SOURCE_DIR}/src/sidh_bridge_hooks.c")
  list(APPEND SIDH_HOOKS_SRC src/sidh_bridge_hooks.c)
else()
  message(FATAL_ERROR "sidh_bridge_hooks.c introuvable.")
endif()

add_library(bench_common STATIC
  ${SHAKE_MASK_SRC}
  ${SIDH_BRIDGE_SRC}
  ${SIDH_HOOKS_SRC}
)
target_include_directories(bench_common PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(bench_common PUBLIC OpenSSL::Crypto)

# ================= apps =================
function(add_app name)
  add_executable(${name} ${ARGN})
  target_include_directories(${name} PUBLIC ${CMAKE_SOURCE_DIR}/include)
  target_link_libraries(${name} PUBLIC bench_common transport_mqtt OpenSSL::Crypto Threads::Threads)
endfunction()

# SIKE/hybrid apps (MQTT)
add_app(alice_mqtt      src/apps/alice_mqtt.c)
add_app(bob_mqtt        src/apps/bob_mqtt.c)
add_app(bench_tx_alice  src/apps/bench_tx_alice.c)
add_app(bench_tx_bob    src/apps/bench_tx_bob.c)
add_app(bench_tx_alice_normal  src/apps/bench_tx_alice_normal.c)
add_app(bench_tx_bob_normal    src/apps/bench_tx_bob_normal.c)

# Kyber (liboqs)
if (USE_LIBOQS)
  add_executable(alice_kyber_mqtt src/apps/alice_kyber_mqtt.c)
  target_link_libraries(alice_kyber_mqtt PUBLIC oqs_unknown transport_mqtt OpenSSL::Crypto Threads::Threads)
  add_executable(bob_kyber_mqtt   src/apps/bob_kyber_mqtt.c)
  target_link_libraries(bob_kyber_mqtt   PUBLIC oqs_unknown transport_mqtt OpenSSL::Crypto Threads::Threads)
endif()

# Démo locale (optionnel)
if (BUILD_DEMO)
  add_executable(sike_demo src/demo_main.c)
  target_link_libraries(sike_demo PUBLIC bench_common transport_mqtt OpenSSL::Crypto Threads::Threads)
endif()

# --- Messages utiles
message(STATUS "SIDH_ROOT = ${SIDH_ROOT}")
if (USE_PQSIDH)
  if (USE_PQSIDH_COMPRESSED)
    message(STATUS "Using compressed p434 API: ${SIDH_ROOT}/src/P434/P434_compressed_api.h")
  else()
    message(STATUS "Using standard p434 API: ${SIDH_ROOT}/src/P434/P434_api.h")
  endif()
  message(STATUS "Linking SIDH lib: ${SIDH_LIB}")
endif()
