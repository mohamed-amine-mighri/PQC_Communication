idf_component_register(
    SRCS
        # coeur MAYO
        "src/mayo.c"
        "src/params.c"
        "src/arithmetic.c"

        # impl générique + commun
        "src/generic/mayo_generic.c"
        "src/common/randombytes.c"
        "src/common/fips202.c"
        "src/common/sha2.c"

        # >>> VARIANTE MAYO-1 UNIQUEMENT <<<
        "src/mayo_1/api.c"
        "src/mayo_1/sign.c"
        "src/mayo_1/params.c"
    INCLUDE_DIRS
        "include"
        "src"
        "src/common"
        "src/generic"
        "src/mayo_1"
)

# Optionnel: éviter warnings qui deviennent erreurs selon ton toolchain
target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-unused-function -Wno-unused-variable)