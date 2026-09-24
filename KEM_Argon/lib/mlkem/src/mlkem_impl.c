// ML-KEM C implementation file
// This file is compiled as pure C and provides the PQCLEAN functions

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

// Include all the ML-KEM implementation files as pure C
#include "../../../components/mlkem/clean512/params.h"
#include "../../../components/mlkem/clean512/api.h"
#include "../../../components/mlkem/clean512/compat.h"

#include "../../../components/mlkem/clean512/cbd.c"
#include "../../../components/mlkem/clean512/fips202.c"
#include "../../../components/mlkem/clean512/indcpa.c"
#include "../../../components/mlkem/clean512/kem.c"
#include "../../../components/mlkem/clean512/ntt.c"
#include "../../../components/mlkem/clean512/poly.c"
#include "../../../components/mlkem/clean512/polyvec.c"
#include "../../../components/mlkem/clean512/reduce.c"
#include "../../../components/mlkem/clean512/symmetric-shake.c"
#include "../../../components/mlkem/clean512/verify.c"
