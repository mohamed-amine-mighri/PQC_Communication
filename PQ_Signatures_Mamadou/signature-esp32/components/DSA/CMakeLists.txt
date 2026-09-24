# components/DSA/CMakeLists.txt

# --- PQClean sources ---
file(GLOB DSA_DIR
    "falcon-512/*.c"
    "falcon-1024/*.c"
    "falcon-padded-512/*.c"
    "falcon-padded-1024/*.c"
    "ml-dsa-44/*.c"
    "ml-dsa-65/*.c"
    "ml-dsa-87/*.c"
    "sphincs-sha2-128f/*.c"
    "sphincs-sha2-128s/*.c"
    "sphincs-sha2-192f/*.c"
    "sphincs-sha2-192s/*.c"
    "sphincs-sha2-256f/*.c"
    "sphincs-sha2-256s/*.c"
    "sphincs-shake-128f/*.c"
    "sphincs-shake-128s/*.c"
    "sphincs-shake-192f/*.c"
    "sphincs-shake-192s/*.c"
    "sphincs-shake-256f/*.c"
    "sphincs-shake-256s/*.c"
)

# --- DSA common sources ---
file(GLOB DSA_COMMON "common/*.c")
list(FILTER DSA_COMMON EXCLUDE REGEX ".*/randombytes.*\\.c$")
list(APPEND DSA_COMMON
    "common/randombytes_mayo_esp32.c"
    "common/pqclean_randombytes_esp32.c"
)

# --- MAYO sources ---
file(GLOB MAYO_CORE    "mayo/src/*.c")
file(GLOB MAYO_COMMON  "mayo/src/common/*.c")
file(GLOB MAYO_GENERIC "mayo/src/generic/*.c")
file(GLOB MAYO_VARIANT "mayo/src/mayo_1/*.c")

list(FILTER MAYO_COMMON EXCLUDE REGEX ".*/randombytes.*\\.c$")

set(MAYO_SRCS
    ${MAYO_CORE}
    ${MAYO_COMMON}
    ${MAYO_GENERIC}
    ${MAYO_VARIANT}
)

idf_component_register(
    SRCS
        ${DSA_DIR}
        ${DSA_COMMON}
        ${MAYO_SRCS}
    INCLUDE_DIRS
        "."
        "common"
        "mayo/include"
        "mayo/src"
        "mayo/src/common"
        "mayo/src/generic"
        "mayo/src/mayo_1"
    PRIV_INCLUDE_DIRS
        "mayo/src/common"
    REQUIRES
        esp_system
        esp_hw_support
)

# ✅ FIX : MAYO_VARIANT=MAYO_1 en mode statique
# - NE PAS utiliser ENABLE_PARAMS_DYNAMIC (dimensionne les buffers pour MAYO-5 → trop grand)
# - MAYO_VARIANT=MAYO_1 → sk_t/pk_t dimensionnés pour MAYO-1 uniquement
# - NULL est passé comme mayo_params_t* car les macros PARAM_* ignorent p en mode statique
target_compile_definitions(${COMPONENT_LIB} PUBLIC
    ENABLE_PARAMS_DYNAMIC=1
    MAYO_BUILD_TYPE_REF
)