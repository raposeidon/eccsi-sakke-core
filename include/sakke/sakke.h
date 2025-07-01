/*
 * Copyright (C) 2025 raposeidon
 * Licensed under the Apache License, Version 2.0 (the "License");
*/

#pragma once
#include "eccsisakke_export.h"
#include "utils/OctetString.h"
#include "utils/LoggerMacro.h"
#include "sakke/shahash.h"
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <memory>
#include <stdexcept>

namespace eccsi_sakke::sakke {
/**
 * @class SAKKE
 * @brief Stateless, thread-safe key encapsulation implementation based on NIST P-256 (RFC 6508).
 */
class ECCSISAKKE_API SAKKE
{
public:
    SAKKE() = delete;    // Instantiation is not allowed; use static functions only.
    ~SAKKE() = delete;

    /**
     * @brief SAKKE generateSakkeEncapsulatedData (RFC 6508 Section 6.2.1)
     * @details This function generates a SAKKE payload and shared secret value (SSV) for a given recipient,
     *          using an ephemeral scalar r generated internally. See RFC 6508 for step numbers.
     *
     *  1) Select a random ephemeral integer value for the SSV in the range 0 to 2^n - 1;
     *  2) Compute r = HashToIntegerRange(SSV || b, q, Hash);
     *  3) Compute R_(b,S) = [r]([b]P + Z_S) in E(F_p);
     *  4) Compute the Hint, H:
     *      a) Compute g^r.  Note that g is an element of PF_p[q] represented by an element of F_p.
     *         Thus, in order to calculate g^r, the operation defined in Section 2.1 for calculation of A * B in PF_p[q]
     *         is to be used as part of a square and multiply (or similar) exponentiation algorithm,
     *         rather than the regular F_p operations;
     *      b) Compute H := SSV XOR HashToIntegerRange(g^r, 2^n, Hash);
     *  5) Form the Encapsulated Data (R_(b,S), H), and transmit it to B;
     *  6) Output SSV for use to derive key material for the application to be keyed.
     *
     * Implementation notes:
     * - The z parameter must be provided as an EC point in uncompressed octet string format (0x04 ...).
     * - The output payload is R || H, where R is the uncompressed EC point (0x04 | x | y), and H is the mask.
     *
     * @param recipientId Recipient identifier (OctetString)
     * @param z           SAKKE parameter Z (OctetString, EC point uncompressed format)
     * @param[out] ssv    Output: derived shared secret value (n/8 bytes)
     * @param[out] payload Output: encapsulated payload (R || H, RFC 6508 format)
     * @return true on success, false on failure
     *
     * @code
     *   eccsi_sakke::utils::OctetString ssv, payload;
     *   if (!SAKKE::encapsulate(recipientId, z, ssv, payload)) {
     *       LOG_ERROR("SAKKE encapsulation failed!");
     *   }
     * @endcode
     */
    static bool generateSakkeEncapsulatedData(
        const eccsi_sakke::utils::OctetString &recipientId,
        const eccsi_sakke::utils::OctetString &z,
        eccsi_sakke::utils::OctetString &ssv,
        eccsi_sakke::utils::OctetString &payload);

    /**
     * @brief SAKKE sakke_extractSharedSecret (RFC 6508 Section 6.2.2)
     *
     * @details
     * Extracts the shared secret value (SSV) from a received SAKKE payload.
     *
     * Decapsulation Steps:
     *   1) Parse the Encapsulated Data (R_(b,S), H), extracting R_(b,S) and H.
     *   2) Compute w := <R_(b,S), K_(b,S)>. Note: by bilinearity, w = g^r (in field F_p).
     *      - This implementation typically computes w = g^rsk mod p using modular exponentiation,
     *        as a substitute for pairings in prime field curves (see RFC 6508 Appendix A).
     *   3) Compute SSV = H XOR HashToIntegerRange(w, 2^n, Hash).
     *      - Byte lengths must be matched using zero-padding if necessary.
     *   4) Compute r = HashToIntegerRange(SSV || b, q, Hash),
     *      where b = HashToIntegerRange(recipientId, q, Hash).
     *   5) Compute TEST = [r]([b]P + Z_S) in E(F_p). If TEST != R_(b,S), the SSV is invalid and MUST NOT be used.
     *   6) Output the SSV for key derivation in the application.
     *
     * Implementation notes:
     * - The recipientId parameter is used directly to derive b (as in RFC 6508).
     * - The rsk (Receiver Secret Key) must be provisioned securely by the KMS.
     * - The rsk parameter is passed as an OctetString and must be converted to BIGNUM using BN_bin2bn.
     * - The z parameter must be provided as an EC point in uncompressed octet string format (0x04 ...).
     * - All EC/BN operations must use secure memory and proper error handling.
     *
     * @param recipientId   Recipient identifier (OctetString)
     * @param rsk           Receiver Secret Key (RSK, OctetString; must be converted to BIGNUM)
     * @param z             SAKKE parameter Z (OctetString, EC point uncompressed format)
     * @param payload       Encapsulated payload (R || H, as produced by encapsulation)
     * @param[out] ssv      [output] Extracted Shared Secret Value (SSV, n/8 bytes)
     * @return true on success, false on failure (failure is logged via LOG_ERROR)
     *
     * @code
     *   eccsi_sakke::utils::OctetString ssv;
     *   if (!SAKKE::decapsulate(recipientId, rsk, z, payload, ssv)) {
     *       LOG_ERROR("SAKKE decapsulation failed!");
     *   }
     * @endcode
     */
    static bool sakke_extractSharedSecret(
        const eccsi_sakke::utils::OctetString &recipientId,
        const eccsi_sakke::utils::OctetString &rsk, // Receiver Secret Key
        const eccsi_sakke::utils::OctetString &z,
        const eccsi_sakke::utils::OctetString &payload,
        eccsi_sakke::utils::OctetString &ssv_out);


    /**
     * @brief Verifies the Receiver Secret Key (RSK) as required by RFC 6508 Section 6.1.2.
     *
     * This function validates the RSK provided by the KMS for the given user by checking
     * the equation:
     *    < [a]P + Z, K_(a,T) > == g
     * where:
     *   - [a]P: Scalar multiplication of base point P by user identifier 'a'
     *   - Z:    Community/parameter-specific EC point
     *   - K_(a,T): The user's Receiver Secret Key (RSK), interpreted as an EC point
     *   - g:    Generator value from the parameter set (RFC 6509 Appendix A)
     *   - '< , >': Pairing operation as specified in SAKKE
     * 
     * This check is MANDATORY for all SAKKE-compliant implementations (RFC 6508 6.1.2, paragraph 2).
     * If the check fails, the caller MUST revoke the keyset for this user.
     *
     * @param[in] user_id   The user's identifier as an OctetString (interpreted as a big-endian integer).
     * @param[in] z         The Z parameter for the community or parameter set, as an EC point (OctetString, uncompressed form).
     * @param[in] RSK       The Receiver Secret Key to be validated, as an EC point (OctetString, uncompressed form).
     *
     * @return true if RSK is valid; false otherwise (parse error, on-curve check fail, or validation fail).
     *
     * @note This implements RFC 6508 Section 6.1.2, paragraph 2.
     * @see https://datatracker.ietf.org/doc/html/rfc6508#section-6.1.2
     */
    static bool validateRSK(
        const eccsi_sakke::utils::OctetString& user_id,
        const eccsi_sakke::utils::OctetString& z,
        const eccsi_sakke::utils::OctetString& RSK);

private:
    /**
     * @brief Print current SAKKE parameter set curve info.
     * Used for debugging and validation purposes.
     */
    static const void printCurveInfo(int param_set = 1);

    /**
     * @brief Hash function wrapper with fixed output length.
     * @param input     Input byte vector to hash
     * @param hashlen   Output hash length (bytes)
     * @return          Hashed output as byte vector
     */
    static std::vector<unsigned char> hashfn(const std::vector<unsigned char> &input, unsigned int hashlen);

    /**
     * @brief Hashes input string to integer in the range [0, n-1].
     * Used for scalar derivation in SAKKE steps.
     * @param s         Input string
     * @param n         Upper bound (exclusive)
     * @param hashlen   Hash output length in bytes
     * @return          Resulting integer value
     */
    static uint32_t HashToIntegerRange(const std::string &s, unsigned int n, unsigned int hashlen = SHA256_DIGEST_LENGTH);

    /**
     * @brief Performs scalar exponentiation of elliptic curve points in the field F_p.
     * @param p         Prime modulus
     * @param result_x  Output X coordinate
     * @param result_y  Output Y coordinate
     * @param point_x   Input point X
     * @param point_y   Input point Y
     * @param n         Scalar
     * @return          True on success, false on failure
     */
    static bool sakke_pointExponent(const BIGNUM *p, BIGNUM *result_x, BIGNUM *result_y,
                                    const BIGNUM *point_x, const BIGNUM *point_y, const BIGNUM *n);

    /**
     * @brief Computes TL pairing for SAKKE (see RFC 6508 Appendix A).
     * @param w_bn      Output pairing value (as BIGNUM)
     * @param R_point   Encapsulated EC point R
     * @param rsk_point Receiver secret key point
     * @param ec_group  Elliptic curve group
     * @param p_bn      Curve prime
     * @param q_bn      Curve order
     * @param ctx       BN_CTX context
     * @return          True on success, false on failure
     */
    static bool sakke_computeTLPairing(BIGNUM *w_bn, const EC_POINT *R_point, const EC_POINT *rsk_point, const EC_GROUP *ec_group,
                                        const BIGNUM *p_bn, const BIGNUM *q_bn, BN_CTX *ctx);

    /**
     * @brief Computes square of an EC point in F_p.
     * @param p         Prime modulus
     * @param result_x  Output X coordinate
     * @param result_y  Output Y coordinate
     * @param point_x   Input point X
     * @param point_y   Input point Y
     * @param ctx       BN_CTX context
     */
    static void sakke_pointSquare(const BIGNUM *p, BIGNUM *result_x, BIGNUM *result_y, const BIGNUM *point_x, const BIGNUM *point_y, BN_CTX *ctx);

    /**
     * @brief Multiplies two EC points in F_p.
     * @param p             Prime modulus
     * @param result_x      Output X coordinate
     * @param result_y      Output Y coordinate
     * @param point_1_x     First input X
     * @param point_1_y     First input Y
     * @param point_2_x     Second input X
     * @param point_2_y     Second input Y
     * @param ctx           BN_CTX context
     */
    static void sakke_pointsMultiply(const BIGNUM *p, BIGNUM *result_x, BIGNUM *result_y, const BIGNUM *point_1_x, const BIGNUM *point_1_y,
                                        const BIGNUM *point_2_x, const BIGNUM *point_2_y, BN_CTX *ctx);

    /**
     * @brief Multiplies an EC point by a scalar in F_p.
     * @param p             Prime modulus
     * @param result_x      Output X coordinate
     * @param result_y      Output Y coordinate
     * @param point_x       Input point X
     * @param point_y       Input point Y
     * @param multiplier    Scalar multiplier
     * @param ctx           BN_CTX context
     */
    static void sakke_pointMultiply(const BIGNUM *p, BIGNUM *result_x, BIGNUM *result_y, const BIGNUM *point_x, const BIGNUM *point_y,
                                    const BIGNUM *multiplier, BN_CTX *ctx);

    /**
     * @brief Adds two EC points in F_p.
     * @param p             Prime modulus
     * @param result_x      Output X coordinate
     * @param result_y      Output Y coordinate
     * @param point_1_x     First input X
     * @param point_1_y     First input Y
     * @param point_2_x     Second input X
     * @param point_2_y     Second input Y
     * @param ctx           BN_CTX context
     */
    static void sakke_pointsAdd(const BIGNUM *p, BIGNUM *result_x, BIGNUM *result_y, const BIGNUM *point_1_x, const BIGNUM *point_1_y,
                                const BIGNUM *point_2_x, const BIGNUM *point_2_y, BN_CTX *ctx);

private:
    // SHA-based hash for integer derivation
    static eccsi_sakke::sakke::SHAHash hashToIntegerRangeSHA;
};

}
