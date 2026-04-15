idf_component_register(
    SRCS
        "app_main.c"
        ${APP_SRC}
        ${TRANSPORT_SRC}
        "bench_common.c"
        "dsa.c"
        "bench_local.c"
        "randombytes_esp32.c"
    INCLUDE_DIRS
        "."
    REQUIRES
        DSA
    PRIV_REQUIRES
        esp_timer
        mbedtls
)

# ------------------- Numeric compile defs -------------------
if(DEFINED BENCH_IDLE)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE BENCH_IDLE=${BENCH_IDLE})
endif()

if(DEFINED KEYPAIR_ITERS)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE KEYPAIR_ITERS=${KEYPAIR_ITERS})
endif()
if(DEFINED SV_ITERS)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE SV_ITERS=${SV_ITERS})
endif()
if(DEFINED WHOLE_ITERS)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE WHOLE_ITERS=${WHOLE_ITERS})
endif()
if(DEFINED WARMUP)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE WARMUP=${WARMUP})
endif()
if(DEFINED MSG_LEN)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE MSG_LEN=${MSG_LEN})
endif()
if(DEFINED WARMUP_CRYPTO)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE WARMUP_CRYPTO=${WARMUP_CRYPTO})
endif()

# ------------------- String compile defs (IMPORTANT) -------------------
# BENCH_OP / BENCH_ALG doivent être des strings C.
# IMPORTANT: tu dois passer -DBENCH_OP=keypair et -DBENCH_ALG=MAYO_1 (SANS guillemets) côté idf.py

if(DEFINED BENCH_OP)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE BENCH_OP=\"${BENCH_OP}\")
endif()

if(DEFINED BENCH_ALG)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE BENCH_ALG=\"${BENCH_ALG}\")
endif()