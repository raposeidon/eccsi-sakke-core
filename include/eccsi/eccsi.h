/*
 * Copyright (C) 2025 raposeidon
 * Licensed under the Apache License, Version 2.0 (the "License");
*/

#pragma once
#include "eccsisakke_export.h"
#include "utils/OctetString.h"
#include "utils/LoggerMacro.h"
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <memory>
#include <stdexcept>
#include <string>

namespace eccsi_sakke::eccsi {

    /**
     * @class ECCSI
     * @brief Stateless API for ECCSI digital signature scheme (RFC 6507).
     *
     * - All methods are static; direct instantiation is not allowed.
     * - Designed for robust, thread-safe, and exception-safe signature processing.
     * - Used as the cryptographic core for SAKKE/ECCSI implementations.
     *
     * @note All keys and signatures are passed as OctetString (binary, not PEM).
     * @note Curve is fixed: NIST P-256.
     * @note Logging is handled via Logger macros.
     */
    class ECCSISAKKE_API ECCSI
    {
    public:
        ECCSI() = delete;
        ~ECCSI() = delete;
        /**
         * @brief Generates an ECCSI signature for a given message.
         * @throws std::runtime_error on curve initialization or parsing errors
         * @param message  Message to sign (with null-termination if required by protocol)
         * @param userId   User identifier (binary)
         * @param pvt      ECCSI public verification token
         * @param ssk      ECCSI signature secret key
         * @param kpak     Community KPAK
         * @param jRandom  Ephemeral random (32 bytes, field F_q)
         * @param signature [out] Output signature: r||s||PVT (RFC 6507)
         * @return true if successful, false otherwise (check logs)
         * @example
         *   try {
         *     OctetString sig;
         *     if (!ECCSI::sign(msg, userId, pvt, ssk, kpak, j, sig))
         *         Logger::error("Sign failed");
         *   } catch (const std::exception& e) {
         *     Logger::error("Exception: %s", e.what());
         *   }
         */
        static bool sign(const eccsi_sakke::utils::OctetString &message,
                         const eccsi_sakke::utils::OctetString &userId,
                         const eccsi_sakke::utils::OctetString &pvt,
                         const eccsi_sakke::utils::OctetString &ssk,
                         const eccsi_sakke::utils::OctetString &kpak,
                         eccsi_sakke::utils::OctetString &signature,
                         bool useTestVector = false);

        /**
         * @brief Verifies an ECCSI signature.
         * @throws std::runtime_error on curve initialization or parsing errors
         * @param message    Message that was signed
         * @param signature  Signature as r||s||PVT
         * @param userId     User identifier
         * @param kpak       Community KPAK
         * @return true if valid, false otherwise
         * @example
         *   try {
         *     if (!ECCSI::verify(msg, sig, userId, kpak))
         *         Logger::error("Signature invalid");
         *   } catch (const std::exception& e) {
         *     Logger::error("Exception: %s", e.what());
         *   }
         */
        static bool verify(const eccsi_sakke::utils::OctetString &message,
                           const eccsi_sakke::utils::OctetString &signature,
                           const eccsi_sakke::utils::OctetString &userId,
                           const eccsi_sakke::utils::OctetString &kpak);

    /**
     * @brief Validates a received SSK (Signer Secret Key) according to RFC 6507 Section 5.1.2.
     *
     * This function verifies that the SSK, KPAK, and PVT values provided by the KMS are consistent
     * and suitable for installation as a signing key for the given user.
     * The following check is performed, as required by the standard:
     *   - LHS: [HS]PVT + KPAK
     *   - RHS: [SSK]G
     *   - The SSK is valid if LHS == RHS on the NIST P-256 curve.
     *
     * @param user_id   User identifier as OctetString.
     * @param KPAK      KPAK public key (OctetString, uncompressed EC point).
     * @param SSK       Signer Secret Key (OctetString, integer).
     * @param PVT       PVT ephemeral public key (OctetString, uncompressed EC point).
     * @param[out] hash_out Output: hash value used in the verification (OctetString).
     *
     * @return true if SSK is valid; false otherwise (parse error, on-curve check fail, or validation fail).
     */
    static bool validateSSK(const eccsi_sakke::utils::OctetString& user_id,
                            const eccsi_sakke::utils::OctetString& kpak,
                            const eccsi_sakke::utils::OctetString& pvt,
                            const eccsi_sakke::utils::OctetString& ssk,
                            eccsi_sakke::utils::OctetString& hash_out);

    private:
        /**
         * @brief Returns global static EC_GROUP* (NIST P-256), thread-safe.
         * @throws std::runtime_error on OpenSSL EC_GROUP creation failure
         */
        static const EC_GROUP *getGroup()
        {
            static EC_GROUP *group = []()
            {
                EC_GROUP *g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
                if (!g)
                {
                    LOG_ERROR("Failed to create EC_GROUP");
                    throw std::runtime_error("Failed to create EC_GROUP");
                }
                EC_GROUP_set_asn1_flag(g, OPENSSL_EC_NAMED_CURVE);
                return g;
            }();
            return group;
        }

        /**
         * @brief Returns the generator point of the curve (G).
         * @return EC_POINT* (do not free)
         */
        static const EC_POINT *getGeneratorPoint()
        {
            return EC_GROUP_get0_generator(getGroup());
        }

        /**
         * @brief Returns a duplicated (owned) generator point.
         * @throws std::runtime_error on failure (try/catch in calling code)
         * @return unique_ptr managing a new EC_POINT*
         */
        static std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)> getGeneratorPointDup()
        {
            EC_POINT *pt = EC_POINT_dup(getGeneratorPoint(), getGroup());
            if (!pt)
            {
                LOG_ERROR("G dup fail");
                throw std::runtime_error("G dup fail");
            }
            return {pt, EC_POINT_free};
        }

        /**
         * @brief Converts bytes to BIGNUM (static utility).
         */
        static BIGNUM *toBignum(const eccsi_sakke::utils::OctetString &bytes);

        /**
         * @brief Converts BIGNUM to OctetString, fixed size.
         */
        static eccsi_sakke::utils::OctetString fromBignum(const BIGNUM *bn, size_t size);

        /**
         * @brief Computes HS = hash(G || KPAK || userId || PVT)
         * @param G      Generator point (G)
         * @param kpak   KPAK (public key)
         * @param userId User identifier
         * @param PVT    Private verification token
         * @return HS as OctetString
         */
        static eccsi_sakke::utils::OctetString computeHS(const eccsi_sakke::utils::OctetString &G,
                                                   const eccsi_sakke::utils::OctetString &kpak,
                                                   const eccsi_sakke::utils::OctetString &userId,
                                                   const eccsi_sakke::utils::OctetString &PVT);
        /**
         * @brief Computes HE = hash(HS || r || message)
         * @param HS      Hash of G, KPAK, userId, PVT
         * @param r       Random ephemeral value (32 bytes)
         * @param message Message to sign
         * @return HE as OctetString
         */
        static eccsi_sakke::utils::OctetString computeHE(const eccsi_sakke::utils::OctetString &HS,
                                                   const eccsi_sakke::utils::OctetString &r,
                                                   const eccsi_sakke::utils::OctetString &message);
    };

}
