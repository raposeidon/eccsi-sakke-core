/*
 * Copyright (C) 2025 raposeidon
 * Licensed under the Apache License, Version 2.0 (the "License");
*/
// This file implements the SAKKE (Scalable Attribute-based Key Encryption) protocol
// as defined in RFC 6508, providing functions for encapsulation and decapsulation
// of SAKKE payloads, as well as mathematical operations on elliptic curves
// and bilinear pairings. It includes functions for generating SAKKE encapsulated data,
// extracting shared secrets, and performing point multiplications and pairings
// on elliptic curves using OpenSSL's BIGNUM and EC_POINT structures.
// The implementation is designed to be efficient and secure, leveraging OpenSSL's
// cryptographic primitives while providing a high-level interface for SAKKE operations.

#define LOG_MODULE "SAKKE"
#include "sakke/sakke.h"
#include "sakke/SakkeParameterSet.h"
#include "sakke/SAkkeGroupManager.h"
#include "utils/LoggerMacro.h"
#include "utils/Random.h"
#include "utils/EcPointParser.h"
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <vector>
#include <mutex>
#include <cmath>
#include <iomanip>

using eccsi_sakke::utils::OctetString;
namespace eccsi_sakke::sakke
{
    std::mutex sakke_mutex;

    void const SAKKE::printCurveInfo(int param_set)
    {
        auto group_and_generator = SakkeGroupManager::getInstance().getGroup(param_set);
        if (!group_and_generator.first)
        {
            LOG_DEBUG("Failed to get SAKKE parameter set 1 group");
            return;
        }

        BN_CTX *ctx = BN_CTX_new();
        BIGNUM *p = BN_new(), *a = BN_new(), *b = BN_new();
        if (EC_GROUP_get_curve_GFp(group_and_generator.first, p, a, b, ctx))
        {
            // 실제 값
            char *p_str = BN_bn2hex(p);

            BIGNUM *p_minus_x = BN_dup(p);
            int minus_a = 0;
            bool a_is_negative = false;

            for (int x = 1; x <= 20; ++x)
            {
                BN_copy(p_minus_x, p);
                BN_sub_word(p_minus_x, x);
                if (BN_cmp(a, p_minus_x) == 0)
                {
                    minus_a = x;
                    a_is_negative = true;
                    break;
                }
            }

            std::string a_str;
            if (a_is_negative)
            {
                std::ostringstream oss;
                oss << "-" << minus_a;
                a_str = oss.str();
            }
            else
            {
                char *a_dec = BN_bn2dec(a);
                a_str = a_dec;
                OPENSSL_free(a_dec);
            }

            std::string b_str = BN_is_zero(b) ? "0" : [](const BIGNUM *b)
            {
                char *b_dec = BN_bn2dec(b);
                std::string res(b_dec);
                OPENSSL_free(b_dec);
                return res;
            }(b);

            LOG_DEBUG("SAKKE Curve (Set ", param_set, "): y^2 = x^3 + (", a_str, ")x + (", b_str, ") mod (", p_str, ")");

            BN_free(p_minus_x);
        }
        BN_free(p);
        BN_free(a);
        BN_free(b);
        BN_CTX_free(ctx);
    }

    bool SAKKE::sakke_pointExponent(const BIGNUM *p, BIGNUM *result_x, BIGNUM *result_y,
                                    const BIGNUM *point_x, const BIGNUM *point_y, const BIGNUM *n)
    {
        BN_CTX *ctx = BN_CTX_new();
        if (!ctx)
        {
            LOG_ERROR("BN_CTX_new failed!");
            return false;
        }

        if (!BN_is_zero(n))
        {
            BN_copy(result_x, point_x);
            BN_copy(result_y, point_y);

            int N = BN_num_bits(n) - 1;
            for (; N != 0; --N)
            {
                sakke_pointSquare(p, result_x, result_y, result_x, result_y, ctx);
                if (BN_is_bit_set(n, N - 1))
                {
                    sakke_pointsMultiply(p, result_x, result_y, result_x, result_y, point_x, point_y, ctx);
                }
            }
            BN_CTX_free(ctx);
            return true;
        }
        BN_CTX_free(ctx);
        return false;
    }

    // SAKKE pairing-like computation in C++
    // Implements TL-pairing alternative using jim-b compatible structure
    bool SAKKE::sakke_computeTLPairing(BIGNUM *w_bn, const EC_POINT *R_point,
                                       const EC_POINT *rsk_point, const EC_GROUP *ec_group,
                                       const BIGNUM *p_bn, const BIGNUM *q_bn, BN_CTX *ctx)
    {
        BN_CTX_start(ctx);
        
        BIGNUM *q_minus_one = BN_CTX_get(ctx);
        BIGNUM *Vx = BN_CTX_get(ctx), *Vy = BN_CTX_get(ctx);
        BIGNUM *Rx = BN_CTX_get(ctx), *Ry = BN_CTX_get(ctx);
        BIGNUM *RSKx = BN_CTX_get(ctx), *RSKy = BN_CTX_get(ctx);
        BIGNUM *Cx = BN_CTX_get(ctx), *Cy = BN_CTX_get(ctx);
        BIGNUM *Qx = BN_CTX_get(ctx), *Qy = BN_CTX_get(ctx);
        BIGNUM *tmp1 = BN_CTX_get(ctx), *tmp2 = BN_CTX_get(ctx), *tmp3 = BN_CTX_get(ctx);
        BIGNUM *T_x1 = BN_CTX_get(ctx), *T_x2 = BN_CTX_get(ctx);
        BIGNUM *BN_TWO = BN_CTX_get(ctx), *BN_THREE = BN_CTX_get(ctx);

        if (!T_x2)
        {
            LOG_ERROR("BN_CTX_get failed (out of memory)");
            BN_CTX_end(ctx);
            return false;
        }

        BN_set_word(BN_TWO, 2);
        BN_set_word(BN_THREE, 3);

        BN_sub(q_minus_one, q_bn, BN_value_one());
        EC_POINT_get_affine_coordinates_GFp(ec_group, R_point, Rx, Ry, ctx);
        EC_POINT_get_affine_coordinates_GFp(ec_group, rsk_point, RSKx, RSKy, ctx);
        BN_copy(Cx, Rx);
        BN_copy(Cy, Ry);
        BN_copy(Qx, RSKx);
        BN_copy(Qy, RSKy);

        int N = BN_num_bits(q_minus_one) - 1;
        BN_one(Vx);
        BN_zero(Vy);

        for (; N != 0; --N)
        {
            // (Vx, Vy) = (Vx, Vy)^2
            sakke_pointSquare(p_bn, Vx, Vy, Vx, Vy, ctx);

            // T_x1 = ((Cx^2 mod p - 1) * 3 * (Qx + Cx) mod p - 2 * Cy^2 mod p) mod p
            BN_exp(tmp1, Cx, BN_TWO, ctx);      // tmp1 = Cx^2
            BN_nnmod(tmp1, tmp1, p_bn, ctx);    // tmp1 = Cx^2 mod p
            BN_sub(tmp1, tmp1, BN_value_one()); // tmp1 = Cx^2 - 1
            BN_mul(tmp1, tmp1, BN_THREE, ctx);  // tmp1 = (Cx^2 - 1) * 3

            BN_add(tmp2, Qx, Cx); // tmp2 = Qx + Cx
            BN_mul(tmp1, tmp1, tmp2, ctx);
            BN_nnmod(tmp1, tmp1, p_bn, ctx);

            BN_exp(tmp2, Cy, BN_TWO, ctx); // tmp2 = Cy^2
            BN_nnmod(tmp2, tmp2, p_bn, ctx);
            BN_mul(tmp2, tmp2, BN_TWO, ctx); // tmp2 = 2 * Cy^2

            BN_sub(tmp1, tmp1, tmp2); // T_x1 = tmp1 - tmp2
            BN_nnmod(T_x1, tmp1, p_bn, ctx);

            // T_x2 = (2 * Cy * Qy) mod p
            BN_mul(tmp1, Cy, BN_TWO, ctx);
            BN_mul(tmp1, tmp1, Qy, ctx);
            BN_nnmod(T_x2, tmp1, p_bn, ctx);

            // (Vx, Vy) = (Vx, Vy) * (T_x1, T_x2)
            sakke_pointsMultiply(p_bn, Vx, Vy, Vx, Vy, T_x1, T_x2, ctx);

            // (Cx, Cy) = 2 * (Cx, Cy)
            sakke_pointMultiply(p_bn, Cx, Cy, Cx, Cy, BN_TWO, ctx);

            if (BN_is_bit_set(q_minus_one, N - 1))
            {
                // T_x1 = ((Qx + Rx) * Cy - (Qx + Cx) * Ry) mod p
                BN_add(tmp1, Qx, Rx);
                BN_mul(tmp1, tmp1, Cy, ctx);
                BN_add(tmp2, Qx, Cx);
                BN_mul(tmp2, tmp2, Ry, ctx);
                BN_sub(tmp1, tmp1, tmp2);
                BN_nnmod(T_x1, tmp1, p_bn, ctx);

                // T_x2 = (Cx - Rx) * Qy mod p
                BN_sub(tmp1, Cx, Rx);
                BN_mul(tmp1, tmp1, Qy, ctx);
                BN_nnmod(T_x2, tmp1, p_bn, ctx);

                sakke_pointsMultiply(p_bn, Vx, Vy, Vx, Vy, T_x1, T_x2, ctx);
                sakke_pointsAdd(p_bn, Cx, Cy, Rx, Ry, Cx, Cy, ctx);
            }
        }

        // Final two squarings
        sakke_pointSquare(p_bn, Vx, Vy, Vx, Vy, ctx);
        sakke_pointSquare(p_bn, Vx, Vy, Vx, Vy, ctx);

        // w = Vy / Vx mod p
        if (!BN_mod_inverse(w_bn, Vx, p_bn, ctx))
        {
            BN_CTX_end(ctx);
            return false;
        }
        BN_mul(w_bn, w_bn, Vy, ctx);
        BN_nnmod(w_bn, w_bn, p_bn, ctx);

        BN_CTX_end(ctx);

        return true;
    }

    void SAKKE::sakke_pointSquare(const BIGNUM *p, BIGNUM *result_x, BIGNUM *result_y,
                                  const BIGNUM *point_x, const BIGNUM *point_y, BN_CTX *ctx)
    {
        BIGNUM *tmp_Ax1 = BN_CTX_get(ctx);
        BIGNUM *tmp_Ax2 = BN_CTX_get(ctx);
        BIGNUM *tmp_Bx1 = BN_CTX_get(ctx);
        BIGNUM *tmp_Bx2 = BN_CTX_get(ctx);
        BIGNUM *two = BN_CTX_get(ctx);

        BN_copy(tmp_Ax1, point_x);
        BN_copy(tmp_Ax2, point_y);
        BN_add(tmp_Bx1, point_x, point_y);
        BN_sub(tmp_Bx2, point_x, point_y);

        BN_mul(result_x, tmp_Bx1, tmp_Bx2, ctx);
        BN_nnmod(result_x, result_x, p, ctx);

        BN_mul(result_y, tmp_Ax1, tmp_Ax2, ctx);
        BN_set_word(two, 2);
        BN_mul(result_y, result_y, two, ctx);
        BN_nnmod(result_y, result_y, p, ctx);
    }

    void SAKKE::sakke_pointsMultiply(const BIGNUM *p, BIGNUM *result_x, BIGNUM *result_y,
                                     const BIGNUM *point_1_x, const BIGNUM *point_1_y,
                                     const BIGNUM *point_2_x, const BIGNUM *point_2_y, BN_CTX *ctx)
    {
        BIGNUM *res_x = BN_CTX_get(ctx);
        BIGNUM *res_y = BN_CTX_get(ctx);
        BIGNUM *tmp = BN_CTX_get(ctx);

        BN_mul(res_x, point_1_x, point_2_x, ctx);
        BN_mul(tmp, point_1_y, point_2_y, ctx);
        BN_sub(res_x, res_x, tmp);
        BN_nnmod(res_x, res_x, p, ctx);

        BN_mul(res_y, point_1_x, point_2_y, ctx);
        BN_mul(tmp, point_1_y, point_2_x, ctx);
        BN_add(res_y, res_y, tmp);
        BN_nnmod(res_y, res_y, p, ctx);

        BN_copy(result_x, res_x);
        BN_copy(result_y, res_y);
    }

    void SAKKE::sakke_pointMultiply(const BIGNUM *p, BIGNUM *result_x, BIGNUM *result_y,
                                    const BIGNUM *point_x, const BIGNUM *point_y,
                                    const BIGNUM *multiplier, BN_CTX *ctx)
    {
        BN_CTX_start(ctx);
        BIGNUM *lambda = BN_CTX_get(ctx);
        BIGNUM *lambda_sq = BN_CTX_get(ctx);
        BIGNUM *EAT1 = BN_CTX_get(ctx);
        BIGNUM *EARx = BN_CTX_get(ctx);
        BIGNUM *EARy = BN_CTX_get(ctx);
        BIGNUM *two = BN_CTX_get(ctx);
        BIGNUM *three = BN_CTX_get(ctx);

        BN_set_word(two, 2);
        BN_set_word(three, 3);

        BN_exp(lambda, point_x, two, ctx); // lambda = point_x^2
        BN_nnmod(lambda, lambda, p, ctx);
        BN_sub(lambda, lambda, BN_value_one()); // lambda = point_x^2 - 1
        BN_mul(lambda, lambda, three, ctx);     // lambda *= 3

        BN_mul(EAT1, point_y, two, ctx);
        BN_mod_inverse(EAT1, EAT1, p, ctx);

        BN_mul(lambda, lambda, EAT1, ctx);
        BN_nnmod(lambda, lambda, p, ctx);

        BN_exp(lambda_sq, lambda, two, ctx);
        BN_nnmod(lambda_sq, lambda_sq, p, ctx);

        BN_mul(EAT1, point_x, two, ctx); // EAT1 = 2 * point_x
        BN_sub(EARx, lambda_sq, EAT1);   // EARx = lambda^2 - 2*point_x
        BN_nnmod(EARx, EARx, p, ctx);

        BN_sub(EARy, EAT1, lambda_sq);
        BN_add(EARy, EARy, point_x);
        BN_mul(EARy, EARy, lambda, ctx);
        BN_nnmod(EARy, EARy, p, ctx);
        BN_sub(EARy, EARy, point_y);
        BN_nnmod(EARy, EARy, p, ctx);

        BN_copy(result_x, EARx);
        BN_copy(result_y, EARy);

        BN_CTX_end(ctx);
    }

    void SAKKE::sakke_pointsAdd(const BIGNUM *p, BIGNUM *result_x, BIGNUM *result_y,
                                const BIGNUM *point_1_x, const BIGNUM *point_1_y,
                                const BIGNUM *point_2_x, const BIGNUM *point_2_y,
                                BN_CTX *ctx)
    {
        BN_CTX_start(ctx);
        BIGNUM *lambda = BN_CTX_get(ctx);
        BIGNUM *lambda_sq = BN_CTX_get(ctx);
        BIGNUM *EAT1 = BN_CTX_get(ctx);
        BIGNUM *EARx = BN_CTX_get(ctx);
        BIGNUM *EARy = BN_CTX_get(ctx);
        BIGNUM *two = BN_CTX_get(ctx);
        BIGNUM *tmp = BN_CTX_get(ctx);

        BN_set_word(two, 2);

        BN_sub(lambda, point_1_y, point_2_y);
        BN_sub(EAT1, point_1_x, point_2_x);
        if (!BN_mod_inverse(EAT1, EAT1, p, ctx))
        {
            LOG_ERROR("[sakke_pointsAdd] BN_mod_inverse failed!");
            BN_CTX_end(ctx);
            return;
        }

        BN_mul(lambda, lambda, EAT1, ctx);
        BN_nnmod(lambda, lambda, p, ctx);

        BN_exp(lambda_sq, lambda, two, ctx);
        BN_nnmod(lambda_sq, lambda_sq, p, ctx);

        BN_sub(EARx, lambda_sq, point_2_x);
        BN_sub(EARx, EARx, point_1_x);
        BN_nnmod(EARx, EARx, p, ctx);

        BN_sub(EARy, point_1_x, lambda_sq);
        BN_mul(tmp, point_2_x, two, ctx);
        BN_add(EARy, EARy, tmp);

        BN_mul(EARy, EARy, lambda, ctx);
        BN_nnmod(EARy, EARy, p, ctx);
        BN_sub(EARy, EARy, point_2_y);
        BN_nnmod(EARy, EARy, p, ctx);

        BN_copy(result_x, EARx);
        BN_copy(result_y, EARy);

        BN_CTX_end(ctx);
    }

    bool SAKKE::generateSakkeEncapsulatedData(const OctetString &recipientId,
                                              const OctetString &z,
                                              OctetString &ssv,
                                              OctetString &payload)
    {
        std::lock_guard<std::mutex> lock(sakke_mutex);
        const SakkeParameterSet &param = sakke_param_set_1();
        auto group_and_generator = SakkeGroupManager::getInstance().getGroup(1);
        EC_GROUP *group = group_and_generator.first;
        EC_POINT *basePoint = group_and_generator.second; // Base point P
        if (!group || !basePoint)
            return false;

        using BN_ptr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
        using EC_POINT_ptr = std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>;
        using BN_CTX_ptr = std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;
        BN_CTX_ptr ctx(BN_CTX_new(), BN_CTX_free);
        if (!ctx)
            return false;

        // Parameters
        BIGNUM *raw_p = nullptr;
        BN_hex2bn(&raw_p, param.p.c_str());
        BIGNUM *raw_q = nullptr;
        BN_hex2bn(&raw_q, param.q.c_str());
        BIGNUM *raw_g = nullptr;
        BN_hex2bn(&raw_g, param.g.c_str());
        BN_ptr p(raw_p, BN_free), q(raw_q, BN_free), g(raw_g, BN_free);

        /********************************************************************
         step 1) Select a random ephemeral integer value for the SSV
                in the range 0 to 2^n - 1;
        *********************************************************************/
        if (ssv.size() == 0)
            ssv = OctetString(utils::generateRandomR(param.n_bits / 8));

        LOG_DEBUG("generateSakke ssv: ", ssv.toHexString());

        /********************************************************************
         step 2) Compute r = HashToIntegerRange( SSV || b, q, Hash );
        *********************************************************************/
        OctetString r_input(ssv);
        r_input.append(recipientId);

        LOG_DEBUG("generateSakke ssv|b: ", r_input.toHexString());

        BIGNUM *raw_r = BN_new();
        if (!hashToIntegerRangeSHA.hashToIntegerRangeSHA(raw_r, r_input.bytes().data(), r_input.bytes().size(), q.get(), SHAHash::SHA256))
        {
            LOG_ERROR("generateSakke Failed to generate r ");
            return false;
        }
        BN_ptr r(raw_r, BN_free);

        char *r_hex = BN_bn2hex(r.get());
        if (!r_hex)
            throw std::runtime_error("BN_bn2hex failed");
        LOG_DEBUG("generateSakke r:  ", r_hex);
        OPENSSL_free(r_hex);

        /********************************************************************
         step 3) Compute R_(b,S) = [r]([b]P + Z_S) in E(F_p);
            Rewrite to use OpenSSL vector scale and sum (EC_POINTs_mul).
            Note that P has been set as the base-point in E_j so only Z and
            its scalar are placed in the vector.  Note also that the storage
            used for Z is reused for the result Rb.

            Compute R_(b,S) = [r][b]P + [r]Z_S
        *********************************************************************/
        EC_POINT_ptr Z_S(nullptr, EC_POINT_free);
        try {
            Z_S = utils::EcPointParser::fromZ(z.toHexString(), group);
        } catch (const std::exception& e) {
            LOG_DEBUG("generateSakke error load Z point.");
            return false;
        }

        // 1. rb = r * b
        BN_ptr rb(BN_new(), BN_free);
        BN_ptr b(BN_new(), BN_free);
        BN_bin2bn(recipientId.bytes().data(), recipientId.bytes().size(), b.get());
        if (!BN_mul(rb.get(), r.get(), b.get(), ctx.get()))
        {
            throw std::runtime_error("BN_mul failed for r * b");
        }
        // 2. array
        const EC_POINT *points[2] = {basePoint, Z_S.get()};
        const BIGNUM *scalars[2] = {rb.get(), r.get()};

        // 3. R_(b,S)
        EC_POINT_ptr R_bS(EC_POINT_new(group), EC_POINT_free);
        EC_POINTs_mul(group, R_bS.get(), nullptr, 2, points, scalars, ctx.get());

        // 4. R_bs coordinates(x, y)
        BN_ptr Rbx(BN_new(), BN_free), Rby(BN_new(), BN_free);
        EC_POINT_get_affine_coordinates_GFp(group, R_bS.get(), Rbx.get(), Rby.get(), ctx.get());

        char *rx_hex = BN_bn2hex(Rbx.get());
        if (!rx_hex)
            throw std::runtime_error("BN_bn2hex failed");
        LOG_DEBUG(" generateSakke Rbx:  ", rx_hex);
        OPENSSL_free(rx_hex);
        char *ry_hex = BN_bn2hex(Rby.get());
        if (!ry_hex)
            throw std::runtime_error("BN_bn2hex failed");
        LOG_DEBUG(" generateSakke Rby:  ", ry_hex);
        OPENSSL_free(ry_hex);

        /********************************************************************
         Step 4) Compute the Hint, H;
        *********************************************************************/

        // 4.a) Compute g^r
        BN_ptr g_pow_r(BN_new(), BN_free);
        BN_ptr result_x_bn(BN_new(), BN_free), result_y_bn(BN_new(), BN_free);

        // Calculate the pairing-based exponentiation: result = g^r
        // (result_x_bn and result_y_bn will hold the x and y coordinates of g^r)
        if (!sakke_pointExponent(p.get(), result_x_bn.get(), result_y_bn.get(),
                                 const_cast<BIGNUM *>(BN_value_one()), g.get(), r.get()))
        {
            LOG_ERROR("generateSakke call to point exponent failed!");
            return false;
        }

        // Compute (g^r mod p), using the x coordinate
        if (!BN_mod(g_pow_r.get(), result_x_bn.get(), p.get(), ctx.get()))
        {
            LOG_ERROR("generateSakke result_x mod p' failed!");
            return false;
        }

        // Compute the modular inverse: (g^r mod p)^(-1)
        if (!BN_mod_inverse(g_pow_r.get(), g_pow_r.get(), p.get(), ctx.get()))
        {
            LOG_ERROR("generateSakke BN_mod_inverse failed!");
            return false;
        }

        // Multiply the modular inverse with the y coordinate: (g^r mod p)^(-1) * y
        if (!BN_mul(g_pow_r.get(), g_pow_r.get(), result_y_bn.get(), ctx.get()))
        {
            LOG_ERROR("generateSakke g^r * result_y failed!");
            return false;
        }

        // Final modular reduction: (g^r * y) mod p
        if (!BN_mod(g_pow_r.get(), g_pow_r.get(), p.get(), ctx.get()))
        {
            LOG_ERROR("generateSakke g^r mod p failed!");
            return false;
        }

        // 4.b) Compute H := SSV XOR HashToIntegerRange( g^r, 2^n, Hash );
        BN_ptr two_to_power_n_bn(BN_new(), BN_free);
        // Prepare 2^n as the mask upper bound
        BN_set_bit(two_to_power_n_bn.get(), param.n_bits);

        size_t g_pow_r_len = BN_num_bytes(g_pow_r.get());
        if (g_pow_r_len == 0)
        {
            LOG_ERROR("generateSakke g_pow_r_len is 0!");
            return true;
        }
        std::vector<uint8_t> g_pow_r_bytes(g_pow_r_len);
        // Export g^r to a byte array
        if (!BN_bn2bin(g_pow_r.get(), g_pow_r_bytes.data()))
        {
            LOG_ERROR("generateSakke g_pow_r incorrect length!");
            return true;
        }

        // Generate the mask value: mask = HashToIntegerRange(g^r, 2^n, SHA-256)
        BIGNUM *raw_mask = BN_new();
        if (!hashToIntegerRangeSHA.hashToIntegerRangeSHA(
                raw_mask, g_pow_r_bytes.data(), g_pow_r_bytes.size(),
                two_to_power_n_bn.get(), SHAHash::SHA256))
        {
            LOG_ERROR("generateSakke Failed to generate mask");
            return false;
        }
        BN_ptr mask(raw_mask, BN_free);

        // For debugging: output mask in hex format
        char *mask_hex = BN_bn2hex(mask.get());
        if (!mask_hex)
            throw std::runtime_error("BN_bn2hex failed");
        LOG_DEBUG("generateSakke mask: ", mask_hex);
        OPENSSL_free(mask_hex);

        // Convert the SSV (shared secret value) to BIGNUM for XOR operation
        BN_ptr H(BN_new(), BN_free);
        H.reset(BN_bin2bn(ssv.bytes().data(), ssv.bytes().size(), nullptr));

        // Bitwise XOR: H = SSV XOR mask (as BIGNUMs, bit-by-bit)
        size_t count = std::max(BN_num_bits(H.get()), BN_num_bits(mask.get()));
        for (; count > 0; --count)
        {
            // The loop goes from highest bit down to 1
            // If the bits are different, set the bit; if they are the same, clear the bit
            if ((BN_is_bit_set(H.get(), count - 1)) ^ (BN_is_bit_set(mask.get(), count - 1)))
            {
                BN_set_bit(H.get(), count - 1);
            }
            else
            {
                BN_clear_bit(H.get(), count - 1);
            }
        }

        // For debugging: output mask in hex format
        char *H_hex = BN_bn2hex(H.get());
        if (!H_hex)
            throw std::runtime_error("BN_bn2hex failed");
        LOG_DEBUG("generateSakke H: ", H_hex);
        OPENSSL_free(H_hex);

        /********************************************************************
         Step 5) Form the Encapsulated Data ( R_(b,S), H ),
         and transmit it to B;
        *********************************************************************/
        // Calculate total length: 2 * coord size (for Rbx, Rby) + hint size + 1 byte for 0x04 prefix
        int coord_size = (EC_GROUP_get_degree(group) + 7) / 8;
        int hint_size = param.n_bits / 8;
        size_t encapsulated_data_len = (coord_size * 2) + hint_size + 1;

        // Initialize the payload buffer to the total length, filled with zeros (for padding)
        payload.bytes().resize(encapsulated_data_len, 0);

        // The first byte is always 0x04, indicating uncompressed EC point format
        payload.bytes()[0] = 0x04;

        // -----
        // Add Rbx (X coordinate of R_(b,S))
        // If the value is shorter than COORD_SIZE, pad with zeros on the left
        size_t offset = (coord_size - BN_num_bytes(Rbx.get())) + 1;
        if (!BN_bn2bin(Rbx.get(), payload.bytes().data() + offset))
        {
            LOG_ERROR("generateSakke copy of Rb_x to encapsulated data failed!");
            return false;
        }
        else
        {
            // -----
            // Add Rby (Y coordinate)
            // Pad with zeros on the left if needed, immediately after X
            offset = coord_size + (coord_size - BN_num_bytes(Rby.get())) + 1;
            if (!BN_bn2bin(Rby.get(), payload.bytes().data() + offset))
            {
                LOG_ERROR("generateSakke copy of Ry to encapsulated data failed!");
                return false;
            }
            else
            {
                // -----
                // Add H (Hint value)
                // Pad with zeros on the left if needed, immediately after Y
                offset = (coord_size * 2) + (hint_size - BN_num_bytes(H.get())) + 1;
                if (!BN_bn2bin(H.get(), payload.bytes().data() + offset))
                {
                    LOG_ERROR("generateSakke copy of Hint to encapsulated data failed!");
                    return false;
                }
            }
        }

        return true;
    }

    // RFC 6508 Section 6.2.2 - SAKKE Decapsulation Procedure
    bool SAKKE::sakke_extractSharedSecret(
        const OctetString &recipientId,
        const OctetString &rsk, // Receiver's secret key (K_b)
        const OctetString &z,
        const OctetString &payload,
        OctetString &ssv_out)
    {
        std::lock_guard<std::mutex> lock(sakke_mutex);
        const SakkeParameterSet &param = sakke_param_set_1();
        auto group_and_generator = SakkeGroupManager::getInstance().getGroup(1);
        EC_GROUP *group = group_and_generator.first;
        EC_POINT *P = group_and_generator.second; // Base point P
        if (!group || !P)
            return false;

        using BN_ptr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
        using EC_POINT_ptr = std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>;
        using BN_CTX_ptr = std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;
        BN_CTX_ptr ctx(BN_CTX_new(), BN_CTX_free);
        if (!ctx)
            return false;

        // Load SAKKE parameters
        BIGNUM *raw_p = nullptr;
        BN_hex2bn(&raw_p, param.p.c_str());
        BIGNUM *raw_q = nullptr;
        BN_hex2bn(&raw_q, param.q.c_str());
        BN_ptr p(raw_p, BN_free), q(raw_q, BN_free);

        /********************************************************************
         Step 1) Parse Encapsulated Data into R_(b,S) and H
        *********************************************************************/
        size_t Rlen = 0;
        if (param.iana == 1)
        {
            int curve_bits = EC_GROUP_get_degree(group);
            size_t coord_size = (curve_bits + 7) / 8;
            Rlen = 1 + 2 * coord_size; // 0x04 + X + Y (uncompressed point)
        }
        else
        {
            Rlen = EC_POINT_point2oct(group, P, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, ctx.get());
        }
        size_t Rb_octet_count = param.n_bits / 8;

        LOG_DEBUG("extractsakke SED.size(): ", payload.size());
        LOG_DEBUG("extractsakke Rb_octet_count: ", Rb_octet_count);

        if (payload.bytes().size() <= Rlen)
            throw std::runtime_error("Payload too short");

        OctetString R_data = payload.slice(0, Rlen);
        OctetString H_data = payload.slice(Rlen, Rb_octet_count);

        LOG_DEBUG("extractsakke [Rb] : ", R_data.toHexString());
        LOG_DEBUG("extractsakke H_octets: ", H_data.toHexString());

        /********************************************************************
         Step 2) Compute w := < R_(b,S), K_(b,S) >.
                Note that by bilinearity, w = g^r;
        *********************************************************************/
        // 1. Restore the encapsulated point R_(b,S) from octet string to EC_POINT
        EC_POINT_ptr R(EC_POINT_new(group), EC_POINT_free);
        if (!EC_POINT_oct2point(group, R.get(), R_data.bytes().data(), R_data.bytes().size(), ctx.get()))
        {
            LOG_DEBUG("extractsakke error load R point.");
            return false;
        }

        // 2. Restore the recipient's secret key (RSK, K_(b,S)) as an EC_POINT on the curve
        EC_POINT_ptr rsk_point(nullptr, EC_POINT_free);
        try {
            rsk_point = utils::EcPointParser::fromRSK(rsk.toHexString(), group);
        } catch (const std::exception& e) {
            LOG_DEBUG("extractsakke error load rsk point.");
            return false;
        }

        // 3. Compute the bilinear pairing: w := <R_(b,S), K_(b,S)>
        //    In SAKKE, due to bilinearity, this is mathematically equivalent to w = g^r.
        //    The pairing result is returned as a BIGNUM (raw_w).
        BIGNUM *raw_w = BN_new();
        if (!sakke_computeTLPairing(raw_w, R.get(), rsk_point.get(), group, p.get(), q.get(), ctx.get()))
        {
            LOG_DEBUG("extractsakke computeTLPairing fail.");
            return false;
        }
        BN_ptr w(raw_w, BN_free);

        // 4. Convert the pairing result w into a byte array for further use (e.g., as mask)
        std::vector<uint8_t> w_bytes(BN_num_bytes(w.get()));
        BN_bn2bin(w.get(), w_bytes.data());
        OctetString w_octet(w_bytes);

        // 5. (Debug) Output the value of w as a hex string for verification
        LOG_DEBUG("extractsakke W:", w_octet.toHexString());

        /********************************************************************
         Step 3) Compute SSV = H XOR HashToIntegerRange( w, 2^n, Hash );
        *********************************************************************/
        BIGNUM *twoToN = BN_new();
        BN_set_bit(twoToN, param.n_bits);

        BIGNUM *raw_mask = BN_new();
        if (!hashToIntegerRangeSHA.hashToIntegerRangeSHA(raw_mask, w_bytes.data(), w_bytes.size(), twoToN, SHAHash::SHA256))
        {
            LOG_ERROR("extractsakke Failed to generate b");
            return false;
        }
        BN_ptr mask(raw_mask, BN_free);

        char *mask_hex = BN_bn2hex(mask.get());
        if (!mask_hex)
            throw std::runtime_error("BN_bn2hex failed");
        LOG_DEBUG("extractsakke mask :  ", mask_hex);
        OPENSSL_free(mask_hex);

        std::vector<uint8_t> mask_vec(Rb_octet_count, 0x00);
        std::vector<uint8_t> H_vec(Rb_octet_count, 0x00);

        // BN_bn2bin은 앞쪽 0 패딩 없음. 뒤에 맞춰서 복사
        int mask_len = BN_num_bytes(mask.get());
        BN_bn2bin(mask.get(), mask_vec.data() + (Rb_octet_count - mask_len));

        size_t H_len = H_data.bytes().size();
        memcpy(H_vec.data() + (Rb_octet_count - H_len), H_data.bytes().data(), H_len);

        for (size_t i = 0; i < Rb_octet_count; ++i)
            H_vec[i] ^= mask_vec[i];
        OctetString ssv(H_vec);
        LOG_DEBUG("extractsakke SSV result: ", ssv.toHexString());

        /********************************************************************
         Step 4) Compute r = HashToIntegerRange( SSV || b, q, Hash );
        *********************************************************************/
        BN_ptr b(BN_new(), BN_free);
        BN_bin2bn(recipientId.bytes().data(), recipientId.bytes().size(), b.get());
        OctetString ssv_with_id(ssv);
        ssv_with_id.append(recipientId);
        LOG_DEBUG("extractsakke ssv_with_id: ", ssv_with_id.toHexString());

        BIGNUM *raw_r = BN_new();
        if (!hashToIntegerRangeSHA.hashToIntegerRangeSHA(raw_r, ssv_with_id.bytes().data(), ssv_with_id.bytes().size(), q.get(), SHAHash::SHA256))
        {
            LOG_ERROR("extractsakke Failed to generate b");
            return false;
        }
        BN_ptr r(raw_r, BN_free);

        char *r_hex = BN_bn2hex(r.get());
        if (!r_hex)
            throw std::runtime_error("BN_bn2hex failed");
        LOG_DEBUG("extractsakke r :  ", r_hex);
        OPENSSL_free(r_hex);

        /********************************************************************
         Step 5) Compute TEST = [r]([b]P + Z_S) in E(F_p).
                If TEST does not equal R_(b,S), then B MUST NOT use the SSV
                to derive key material;
        *********************************************************************/
        EC_POINT_ptr Z_pt(EC_POINT_new(group), EC_POINT_free);
        if (!EC_POINT_oct2point(group, Z_pt.get(), z.bytes().data(), z.bytes().size(), ctx.get()))
            return false;

        EC_POINT_ptr bP(EC_POINT_new(group), EC_POINT_free);
        EC_POINT_mul(group, bP.get(), nullptr, P, b.get(), ctx.get());

        EC_POINT_ptr Q(EC_POINT_new(group), EC_POINT_free);
        EC_POINT_add(group, Q.get(), bP.get(), Z_pt.get(), ctx.get());

        EC_POINT_ptr R_check(EC_POINT_new(group), EC_POINT_free);
        EC_POINT_mul(group, R_check.get(), nullptr, Q.get(), r.get(), ctx.get());

        // (R_bS의 x, y)
        BN_ptr Testx(BN_new(), BN_free), Testy(BN_new(), BN_free);
        EC_POINT_get_affine_coordinates_GFp(group, R_check.get(), Testx.get(), Testy.get(), ctx.get());
        char *Testx_hex = BN_bn2hex(Testx.get());
        if (!Testx_hex)
            throw std::runtime_error("BN_bn2hex failed");
        LOG_DEBUG(" generateSakke Testx:  ", Testx_hex);
        OPENSSL_free(Testx_hex);
        char *Testy_hex = BN_bn2hex(Testy.get());
        if (!Testy_hex)
            throw std::runtime_error("BN_bn2hex failed");
        LOG_DEBUG(" generateSakke Testy:  ", Testy_hex);
        OPENSSL_free(Testy_hex);

        // --- Step 5: Validate
        if (EC_POINT_cmp(group, R_check.get(), R.get(), ctx.get()) != 0)
        {
            return false; // Invalid R value
        }

        ssv_out = ssv;
        return true;
    }

    // RFC 6508 Section 6.1.2 (paragraph 2)
    bool SAKKE::validateRSK(
    const OctetString& user_id,
    const OctetString& z,
    const OctetString& RSK)
    {
        using BN_ptr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
        using EC_POINT_ptr = std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>;
        using BN_CTX_ptr = std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;

        // 1. Prepare SAKKE parameter set and EC group
        const SakkeParameterSet& param = sakke_param_set_1();
        auto[group, P] = SakkeGroupManager::getInstance().getGroup(1);
        if (!group || !P) {
            LOG_ERROR("validateRSK: Curve group or base point is null");
            return false;
        }

        BN_CTX_ptr ctx(BN_CTX_new(), BN_CTX_free);
        if (!ctx){
            LOG_ERROR("validateRSK: BN_CTX_new failed");
            return false;
        }

        // 2. Convert user_id to BIGNUM (a)
        BIGNUM* a_raw = BN_bin2bn(user_id.bytes().data(), user_id.size(), nullptr);
        if (!a_raw) {
            LOG_ERROR("validateRSK: Failed to convert user_id to BIGNUM");
            return false;
		}
		BN_ptr a_bn(a_raw, BN_free);

        // 3. Restore RSK as EC_POINT
        EC_POINT_ptr rsk_point(nullptr, EC_POINT_free);
        try {
            rsk_point = utils::EcPointParser::fromRSK(RSK.toHexString(), group);
        } catch (const std::exception& e) {
            LOG_ERROR("validateRSK: Failed to parse RSK: ", e.what());
            return false;
        }

        // 4. Restore Z point
        EC_POINT_ptr Z_point(nullptr, EC_POINT_free);
        try {
            Z_point = utils::EcPointParser::fromZ(z.toHexString(), group);
        } catch (const std::exception& e) {
            LOG_ERROR("validateRSK: Failed to parse Z: ", e.what());
            return false;
        }

        // 5. Calculate [a]P + Z
        EC_POINT_ptr aP_plus_Z(EC_POINT_new(group), EC_POINT_free);
        EC_POINT_ptr aP(EC_POINT_new(group), EC_POINT_free);

        if (!aP || !aP_plus_Z) {
            LOG_ERROR("validateRSK: EC_POINT allocation failed");
            return false;
        }

        if (1 != EC_POINT_mul(group, aP.get(), nullptr, P, a_bn.get(), ctx.get())) {
            LOG_ERROR("validateRSK: EC_POINT_mul([a]P) failed");
            return false;
        }

        if (1 != EC_POINT_add(group, aP_plus_Z.get(), aP.get(), Z_point.get(), ctx.get())) {
            LOG_ERROR("validateRSK: EC_POINT_add([a]P + Z) failed");
            return false;
        }

        // 6. Compute pairing < [a]P + Z, K_(a,T) >
        BIGNUM* p_raw = nullptr;BN_hex2bn(&p_raw, param.p.c_str());
        BIGNUM* q_raw = nullptr; BN_hex2bn(&q_raw, param.q.c_str());
		BN_ptr p_bn(p_raw, BN_free);
        BN_ptr q_bn(q_raw, BN_free);
		BN_ptr result(BN_new(), BN_free);

        bool pairing_ok = sakke_computeTLPairing(
            result.get(),
            aP_plus_Z.get(),
            rsk_point.get(),
            group,
            p_bn.get(),
            q_bn.get(),
            ctx.get()
        );
        if (!pairing_ok) {
            LOG_ERROR("validateRSK: sakke_computeTLPairing failed");
            return false;
        }

        // 7. Compare result with generator g
        BIGNUM* g_raw = nullptr; BN_hex2bn(&g_raw, param.g.c_str());
		BN_ptr g_bn(g_raw, BN_free);
        int cmp = BN_cmp(result.get(), g_bn.get());

        if (cmp == 0) {
            LOG_DEBUG("validateRSK: <[a]P+Z, RSK> == g, VALID!");
            return true;
        } else {
            LOG_ERROR("validateRSK: <[a]P+Z, RSK> != g, RSK VALIDATION FAILED! Caller MUST revoke keyset.");
            return false;
        }
    }
}
