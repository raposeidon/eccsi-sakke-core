/*
 * Copyright (C) 2025 raposeidon
 * Licensed under the Apache License, Version 2.0 (the "License");
*/

#pragma once
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <vector>
#include <iostream>
#include <stdexcept>

namespace eccsi_sakke::sakke {
/**
 * @class SHAHash
 * @brief Static utility for SHA-based hashing and deterministic integer derivation for SAKKE (RFC 6508).
 *
 * - Provides flexible hash support (SHA-256, SHA-384, SHA-512).
 * - Core: Implements HashToIntegerRange as described in SAKKE spec.
 * - All methods are stateless and thread-safe.
 */
class SHAHash {
public:
    /**
     * @enum HashType
     * @brief Supported hash algorithms for SHAHash.
     */
    enum HashType {
        SHA256 = 256, ///< SHA-256
        SHA384 = 384, ///< SHA-384
        SHA512 = 512  ///< SHA-512
    };

    /**
     * @brief Returns the digest length for a given hash type.
     * @param type HashType (SHA256, SHA384, SHA512)
     * @return Digest length in bytes
     * @throws std::invalid_argument on unsupported type
     */
    static size_t hashLength(HashType type) {
        switch (type) {
            case SHA256: return SHA256_DIGEST_LENGTH;
            case SHA384: return SHA384_DIGEST_LENGTH;
            case SHA512: return SHA512_DIGEST_LENGTH;
            default: throw std::invalid_argument("Unsupported hash type");
        }
    }

    /**
     * @brief HashToIntegerRange for SAKKE: hashes input and deterministically maps it to a positive integer in [0, n-1].
     * @details Implements the "HashToIntegerRange" procedure from RFC 6508 using the specified SHA variant.
     * @param[out] v      Output BIGNUM (v = result mod n)
     * @param[in]  s      Input byte array
     * @param[in]  s_len  Length of input array
     * @param[in]  n      Modulus for reduction
     * @param[in]  hash_type Hash algorithm to use
     * @return True on success, false on error (allocation/hash failure)
     *
     * @note Output BIGNUM 'v' must be pre-allocated.
     * @note Thread-safe. Handles all memory management internally.
     */
    static bool hashToIntegerRangeSHA(
        BIGNUM* v, 
        const uint8_t* s, size_t s_len, 
        BIGNUM* n, 
        HashType hash_type)
    {
        const size_t hash_len = hashLength(hash_type);
        std::vector<unsigned char> hash_A, hash_h, hi_concat_A, hash_vi, vprime;
        BIGNUM* vprime_bn = nullptr;
        BN_CTX* bn_ctx = BN_CTX_new();
        if (!bn_ctx) {
            std::cerr << "Failed to create BN_CTX!\n";
            return false;
        }

        // 1. A = hashfn(s)
        if (!hash(hash_A, std::vector<unsigned char>(s, s + s_len), hash_type)) {
            std::cerr << "Hash of input failed!\n";
            BN_CTX_free(bn_ctx);
            return false;
        }

        // 2. h_0 = 00...00
        hash_h.assign(hash_len, 0);

        // 3. l = ceiling(log2(n) / (hash_len * 8))
        const unsigned int l = (BN_num_bits(n) + (hash_len * 8) - 1) / (hash_len * 8);

        // 4. for i = 1..l
        vprime.assign(l * hash_len, 0);
        for (unsigned int i = 0; i < l; ++i) {
            // h_i = hashfn(h_(i-1))
            if (!hash(hash_h, hash_h, hash_type)) {
                BN_CTX_free(bn_ctx);
                return false;
            }
            // v_i = hashfn(h_i || A)
            hi_concat_A.clear();
            hi_concat_A.reserve(2 * hash_len);
            hi_concat_A.insert(hi_concat_A.end(), hash_h.begin(), hash_h.end());
            hi_concat_A.insert(hi_concat_A.end(), hash_A.begin(), hash_A.end());
            if (!hash(hash_vi, hi_concat_A, hash_type)) {
                BN_CTX_free(bn_ctx);
                return false;
            }
            std::copy(hash_vi.begin(), hash_vi.end(), vprime.begin() + i * hash_len);
        }

        // 5. v' = v_1 || ... || v_l
        vprime_bn = BN_bin2bn(vprime.data(), vprime.size(), nullptr);
        if (!vprime_bn) {
            BN_CTX_free(bn_ctx);
            std::cerr << "Unable to create BN 'vprime'!\n";
            return false;
        }

        // 6. v = v' mod n
        bool success = BN_nnmod(v, vprime_bn, n, bn_ctx);
        BN_clear_free(vprime_bn);
        BN_CTX_free(bn_ctx);
        return success;
    }

private:
    /**
     * @brief Computes hash of input using specified HashType.
     * @param[out] output    Output vector (digest)
     * @param[in]  input     Input data
     * @param[in]  hash_type Hash algorithm
     * @return True on success, false on failure.
     */
    static bool hash(
        std::vector<unsigned char>& output, 
        const std::vector<unsigned char>& input, 
        HashType hash_type)
    {
        switch (hash_type) {
            case SHA256: return hash_sha256(output, input);
            case SHA384: return hash_sha384(output, input);
            case SHA512: return hash_sha512(output, input);
            default: return false;
        }
    }

    /**
     * @brief SHA-256 hash function.
     */    
    static bool hash_sha256(std::vector<unsigned char>& output, const std::vector<unsigned char>& input) {
        output.resize(SHA256_DIGEST_LENGTH);
        SHA256_CTX ctx;
        return SHA256_Init(&ctx) == 1 &&
               SHA256_Update(&ctx, input.data(), input.size()) == 1 &&
               SHA256_Final(output.data(), &ctx) == 1;
    }

    /**
     * @brief SHA-384 hash function.
     */
    static bool hash_sha384(std::vector<unsigned char>& output, const std::vector<unsigned char>& input) {
        output.resize(SHA384_DIGEST_LENGTH);
        SHA512_CTX ctx;
        return SHA384_Init(&ctx) == 1 &&
               SHA384_Update(&ctx, input.data(), input.size()) == 1 &&
               SHA384_Final(output.data(), &ctx) == 1;
    }


    /**
     * @brief SHA-512 hash function.
     */    
    static bool hash_sha512(std::vector<unsigned char>& output, const std::vector<unsigned char>& input) {
        output.resize(SHA512_DIGEST_LENGTH);
        SHA512_CTX ctx;
        return SHA512_Init(&ctx) == 1 &&
               SHA512_Update(&ctx, input.data(), input.size()) == 1 &&
               SHA512_Final(output.data(), &ctx) == 1;
    }
};

}
