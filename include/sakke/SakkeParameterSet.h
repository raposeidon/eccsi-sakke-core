/*
 * Copyright (C) 2025 raposeidon
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#pragma once
#include <string>
#include <cstdint>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/err.h>

namespace eccsi_sakke::sakke {

/**
 * @enum SakkeHashAlg
 * @brief Supported hash algorithms for SAKKE parameter sets.
 * @note Extend as needed for other hash algorithms.
 */
enum class SakkeHashAlg : uint8_t {
    SHA256 = 1, ///< SHA-256 (default)
    SHA384 = 2, ///< SHA-384
    SHA512 = 3  ///< SHA-512
    // Add more algorithms if necessary
};

/**
 * @struct SakkeParameterSet
 * @brief Structure defining the domain parameters and cryptographic settings for a SAKKE instance.
 *
 * - Used to initialize ECC group and hash operations.
 * - Parameter set follows RFC 6508/6509 standards.
 */
struct SakkeParameterSet {
    int iana;                   ///< IANA-assigned parameter set identifier (e.g., 1 for RFC 6509 set)
    int n_bits;                 ///< Symmetric key length (bits)

    // Elliptic curve domain parameters
    std::string p;              ///< Prime field modulus (hexadecimal string)
    std::string q;              ///< Order of the subgroup (hexadecimal string)
    std::string Px;             ///< Base point P: X coordinate (hexadecimal string)
    std::string Py;             ///< Base point P: Y coordinate (hexadecimal string)

    // SAKKE-specific generator value
    std::string g;              ///< Generator 'g' for SAKKE DH computations (hexadecimal string)

    std::string a;              ///< Elliptic curve coefficient 'a' (dec string)
    std::string b;              ///< Elliptic curve coefficient 'b' (dec string)

    // Hashing information
    SakkeHashAlg hash_alg;      ///< Hash algorithm (SakkeHashAlg)
    int hash_len;               ///< Hash output length (bytes)
};

/**
 * @brief Returns the reference to the RFC 6509 Appendix A SAKKE parameter set (IANA = 1).
 * @return const SakkeParameterSet& Static reference to parameter set.
 */
const SakkeParameterSet& sakke_param_set_1();

/**
 * @brief Returns a string representation of the specified parameter set.
 * @param param_set IANA parameter set number (default: 1)
 * @return std::string Human-readable summary of the parameter set
 */
std::string printParameterSet(int param_set = 1);

/**
 * @brief Returns a pointer to the SAKKE parameter set for a given IANA identifier.
 * @param param_set IANA parameter set number
 * @return const SakkeParameterSet* Pointer to the parameter set, or nullptr if not found.
 */
const SakkeParameterSet* get_sakke_param_by_id(const int param_set);

}
