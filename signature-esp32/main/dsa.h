#pragma once
#include <stdint.h>
#include <stddef.h>

// include PQClean api headers (tes chemins)
#include "falcon-512/api.h"
#include "falcon-1024/api.h"
#include "falcon-padded-512/api.h"
#include "falcon-padded-1024/api.h"
#include "ml-dsa-44/api.h"
#include "ml-dsa-65/api.h"
#include "ml-dsa-87/api.h"
#include "sphincs-sha2-128f/api.h"
#include "sphincs-sha2-128s/api.h"
#include "sphincs-sha2-192f/api.h"
#include "sphincs-sha2-192s/api.h"
#include "sphincs-sha2-256f/api.h"
#include "sphincs-sha2-256s/api.h"
#include "sphincs-shake-128f/api.h"
#include "sphincs-shake-128s/api.h"
#include "sphincs-shake-192f/api.h"
#include "sphincs-shake-192s/api.h"
#include "sphincs-shake-256f/api.h"
#include "sphincs-shake-256s/api.h"

enum DSA_ALGO {
    FALCON_512, FALCON_1024, FALCON_PADDED_512, FALCON_PADDED_1024,
    ML_DSA_44, ML_DSA_65, ML_DSA_87,
    SPHINCS_SHA2_128F, SPHINCS_SHA2_128S,
    SPHINCS_SHA2_192F, SPHINCS_SHA2_192S,
    SPHINCS_SHA2_256F, SPHINCS_SHA2_256S,
    SPHINCS_SHAKE_128F, SPHINCS_SHAKE_128S,
    SPHINCS_SHAKE_192F, SPHINCS_SHAKE_192S,
    SPHINCS_SHAKE_256F, SPHINCS_SHAKE_256S,
    MAYO_SIG_1,
    RSA_2048
};

const char* getAlgoName(enum DSA_ALGO algo);

int dsa_keygen(enum DSA_ALGO algo, uint8_t *pk, uint8_t *sk);

int dsa_signature(enum DSA_ALGO algo,
                  uint8_t *sig, size_t *siglen,
                  const uint8_t *m, size_t mlen,
                  const uint8_t *sk);

int dsa_verify(enum DSA_ALGO algo,
               const uint8_t *sig, size_t siglen,
               const uint8_t *m, size_t mlen,
               const uint8_t *pk);

void alloc_space_for_dsa(enum DSA_ALGO algo,
                         uint8_t **pk, uint8_t **sk,
                         size_t *pk_len, size_t *sk_len, size_t *sig_len);

void free_space_for_dsa(uint8_t *pk, uint8_t *sk);
