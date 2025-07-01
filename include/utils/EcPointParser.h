/*
 * Copyright (C) 2025 raposeidon
 * Licensed under the Apache License, Version 2.0 (the "License");
*/

#pragma once

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <memory>
#include <string>
#include <stdexcept>

namespace eccsi_sakke::utils {

/**
 * @class EcPointParser
 * @brief Static utility class for parsing elliptic curve points from hexadecimal strings for use with OpenSSL.
 *
 * - All functions throw std::invalid_argument or std::runtime_error on parse or allocation failure.
 * - Only uncompressed EC point format is supported (must start with "04").
 * - Supports P-256 and SAKKE curves as used in SAKKE/ECCSI protocols.
 */
class EcPointParser {
public:
    /// Smart pointer type for EC_POINT (managed by EC_POINT_free)
    using ECPointPtr = std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>;


    /**
     * @brief Parses a hexadecimal string into an EC_POINT (uncompressed format only).
     * @param hex    Input hexadecimal string ("04 | x | y", where x and y are big-endian).
     * @param group  OpenSSL EC_GROUP pointer defining the curve domain.
     * @return ECPointPtr Smart pointer to the created EC_POINT.
     * @throws std::invalid_argument if input is invalid or length mismatch.
     * @throws std::runtime_error if allocation or coordinate set fails.
     * @note The input string must start with "04" (uncompressed format).
     */
    static ECPointPtr fromHextoPoint(const std::string& hex, const EC_GROUP* group) {
        if (hex.empty() || hex.size() < 4 || hex.substr(0, 2) != "04") {
            throw std::invalid_argument("Hex string must start with 04 (uncompressed)");
        }

        int degree = EC_GROUP_get_degree(group);
        size_t coord_bytes = (degree + 7) / 8;
        size_t xyHexLen = hex.length() - 2; // 0x04
        if (xyHexLen != coord_bytes * 4) { // *2(x, y), *2(hex)
            throw std::invalid_argument("EC point hex length does not match curve degree (X, Y length)");
        }

        size_t halfLen = xyHexLen / 2;
        std::string x_hex = hex.substr(2, halfLen);
        std::string y_hex = hex.substr(2 + halfLen, halfLen);

        BIGNUM* x = nullptr;
        BIGNUM* y = nullptr;
        if (!BN_hex2bn(&x, x_hex.c_str()) || !BN_hex2bn(&y, y_hex.c_str())) {
            BN_clear_free(x); BN_clear_free(y);
            throw std::runtime_error("BN_hex2bn conversion failed");
        }

        ECPointPtr point(EC_POINT_new(group), EC_POINT_free);
        if (!point) {
            BN_clear_free(x); BN_clear_free(y);
            throw std::runtime_error("Failed to create EC_POINT");
        }

        if (!EC_POINT_set_affine_coordinates(group, point.get(), x, y, nullptr)) {
            BN_clear_free(x); BN_clear_free(y);
            throw std::runtime_error("EC_POINT_set_affine_coordinates failed (point not on curve?)");
        }

        BN_clear_free(x); BN_clear_free(y);
        return point;
    }

    /**
     * @brief Parses KPAK public key hex into EC_POINT (wrapper for fromHextoPoint).
     * @param kpakHex KPAK public key in hex (uncompressed)
     * @param group   Curve group (typically NIST P-256)
     * @return ECPointPtr Smart pointer to EC_POINT
     * @throws Exception on failure (see fromHextoPoint)
     */
    static ECPointPtr fromKPAK(const std::string& kpakHex, const EC_GROUP* group) {
        return fromHextoPoint(kpakHex, group);
    }

    /**
     * @brief Parses SAKKE Z parameter hex into EC_POINT.
     * @param zHex   Z parameter in hex (uncompressed)
     * @param group  Curve group for SAKKE parameter set
     * @return ECPointPtr Smart pointer to EC_POINT
     * @throws Exception on failure (see fromHextoPoint)
     */
    static ECPointPtr fromZ(const std::string& zHex, const EC_GROUP* group) {
        return fromHextoPoint(zHex, group);
    }

    /**
     * @brief Parses RSK public key hex into EC_POINT.
     * @param rskHex RSK public key in hex (uncompressed)
     * @param group  Curve group
     * @return ECPointPtr Smart pointer to EC_POINT
     * @throws Exception on failure (see fromHextoPoint)
     */
    static ECPointPtr fromRSK(const std::string& rskHex, const EC_GROUP* group) {
        return fromHextoPoint(rskHex, group);
    }
};

}