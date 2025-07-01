/*
 * Copyright (C) 2025 raposeidon
 * Licensed under the Apache License, Version 2.0 (the "License");
*/
// This file implements the mikey::utils::generateRandomR function to generate
// cryptographically secure random bytes.

#include "utils/Random.h"
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <vector>
#include <cstdint>
#include <stdexcept>
#include <iostream>

namespace eccsi_sakke::utils {

std::vector<uint8_t> generateRandomR(size_t num_bytes) {
    static bool fips_available = false;
    static bool fips_checked = false;
    static OSSL_PROVIDER* fips_provider = nullptr;
    static OSSL_PROVIDER* def_provider = nullptr;

    // 1. FIPS mode check and provider loading (performed once per process)
    if (!fips_checked) {
        fips_provider = OSSL_PROVIDER_load(NULL, "fips");
        def_provider = OSSL_PROVIDER_load(NULL, "default");
        fips_available = (fips_provider != nullptr);
        fips_checked = true;
    }

    std::vector<uint8_t> result(num_bytes);

    if (fips_available) {
        // 2. In FIPS environment, use CTR-DRBG engine explicitly
        EVP_RAND* rand_algo = EVP_RAND_fetch(NULL, "CTR-DRBG", NULL);
        if (!rand_algo)
            throw std::runtime_error("Failed to fetch CTR-DRBG (FIPS)");

        EVP_RAND_CTX* rand_ctx = EVP_RAND_CTX_new(rand_algo, NULL);
        if (!rand_ctx) {
            EVP_RAND_free(rand_algo);
            throw std::runtime_error("Failed to create EVP_RAND_CTX");
        }

        if (EVP_RAND_instantiate(rand_ctx, 128, 0, NULL, 0, NULL) != 1) {
            ERR_print_errors_fp(stderr);
            EVP_RAND_CTX_free(rand_ctx);
            EVP_RAND_free(rand_algo);
            throw std::runtime_error("EVP_RAND_instantiate failed (FIPS)");
        }

        if (EVP_RAND_generate(rand_ctx, result.data(), result.size(), 0, 0, NULL, 0) != 1) {
            ERR_print_errors_fp(stderr);
            EVP_RAND_uninstantiate(rand_ctx);
            EVP_RAND_CTX_free(rand_ctx);
            EVP_RAND_free(rand_algo);
            throw std::runtime_error("EVP_RAND_generate failed (FIPS)");
        }

        EVP_RAND_uninstantiate(rand_ctx);
        EVP_RAND_CTX_free(rand_ctx);
        EVP_RAND_free(rand_algo);
        // Note: Provider unloading is omitted because providers are managed statically.
        return result;
    }

    // 3. If FIPS provider is not available, use RAND_bytes (standard secure random)
    if (RAND_bytes(result.data(), result.size()) != 1) {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("RAND_bytes failed (non-FIPS)");
    }
    return result;
}

}
