/*
 * Copyright (C) 2025 raposeidon
 * Licensed under the Apache License, Version 2.0 (the "License");
*/

// This file implements the ECCSI (Elliptic Curve Cryptography Signature Interface) protocol
// as defined in RFC 6507, providing functions for signing and verifying messages
// using elliptic curve cryptography. It includes functions for converting between
// BIGNUM and OctetString representations, computing hash values, and performing
// elliptic curve operations using OpenSSL's BIGNUM and EC_POINT structures.

#define LOG_MODULE "ECCSI"
#include "eccsi/eccsi.h"
#include "utils/LoggerMacro.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cstring>

namespace eccsi_sakke::eccsi {

BIGNUM *ECCSI::toBignum(const eccsi_sakke::utils::OctetString &bytes)
{
    return BN_bin2bn(bytes.bytes().data(), bytes.size(), nullptr);
}

eccsi_sakke::utils::OctetString ECCSI::fromBignum(const BIGNUM *bn, size_t size)
{
    std::vector<uint8_t> buf(size, 0);
    BN_bn2binpad(bn, buf.data(), static_cast<int>(size));
    return eccsi_sakke::utils::OctetString(buf);
}

eccsi_sakke::utils::OctetString ECCSI::computeHS(
    const eccsi_sakke::utils::OctetString &G,
    const eccsi_sakke::utils::OctetString &KPAK,
    const eccsi_sakke::utils::OctetString &userId,
    const eccsi_sakke::utils::OctetString &PVT)
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx)
    {
        LOG_ERROR("EVP_MD_CTX_new failed in computeHS");
        return {};
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;

    int ok = 1;
    ok &= EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
    ok &= EVP_DigestUpdate(mdctx, G.bytes().data(), G.size());
    ok &= EVP_DigestUpdate(mdctx, KPAK.bytes().data(), KPAK.size());
    ok &= EVP_DigestUpdate(mdctx, userId.bytes().data(), userId.size());
    ok &= EVP_DigestUpdate(mdctx, PVT.bytes().data(), PVT.size());

    if (!ok || EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1)
    {
        LOG_ERROR("EVP_Digest operation failed in computeHS");
        EVP_MD_CTX_free(mdctx);
        return {};
    }

    EVP_MD_CTX_free(mdctx);

    return eccsi_sakke::utils::OctetString(
        std::vector<uint8_t>(hash, hash + hash_len));
}

eccsi_sakke::utils::OctetString ECCSI::computeHE(
    const eccsi_sakke::utils::OctetString &HS,
    const eccsi_sakke::utils::OctetString &r,
    const eccsi_sakke::utils::OctetString &message)
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx)
    {
        LOG_ERROR("EVP_MD_CTX_new failed in computeHE");
        return {};
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;

    int ok = 1;
    ok &= EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
    ok &= EVP_DigestUpdate(mdctx, HS.bytes().data(), HS.size());
    ok &= EVP_DigestUpdate(mdctx, r.bytes().data(), r.size());
    ok &= EVP_DigestUpdate(mdctx, message.bytes().data(), message.size());

    if (!ok || EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1)
    {
        LOG_ERROR("EVP_Digest operation failed in computeHE");
        EVP_MD_CTX_free(mdctx);
        return {};
    }

    EVP_MD_CTX_free(mdctx);

    return eccsi_sakke::utils::OctetString(
        std::vector<uint8_t>(hash, hash + hash_len));
}

bool ECCSI::sign(const eccsi_sakke::utils::OctetString &message,
                    const eccsi_sakke::utils::OctetString &userId,
                    const eccsi_sakke::utils::OctetString &pvt,
                    const eccsi_sakke::utils::OctetString &ssk,
                    const eccsi_sakke::utils::OctetString &kpak,
                    eccsi_sakke::utils::OctetString &signature,
                    bool useTestVector)
{
    LOG_INFO("ECCSI::sign() called");

    using BN_ptr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
    using EC_POINT_ptr = std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>;
    using BN_CTX_ptr = std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;

    BN_CTX_ptr ctx(BN_CTX_new(), BN_CTX_free);
    if (!ctx)
    {
        LOG_ERROR("Failed to create BN_CTX");
        return false;
    }

    // (Step 0) Get curve order q
    BN_ptr q(BN_new(), BN_free);
    if (!q || !EC_GROUP_get_order(getGroup(), q.get(), ctx.get()))
    {
        LOG_ERROR("Failed to allocate or get curve order q");
        return false;
    }

    // (Step 1) Choose a random (ephemeral) non-zero value j in F_q
    BN_ptr j(BN_new(), BN_free);

    if (useTestVector) // useTestVector: test mode?
    {
        BIGNUM *new_j = nullptr;
        // RFC data (e.g: 0x34567)
        if (!BN_hex2bn(&new_j, "34567"))
        {
            LOG_ERROR("BN_hex2bn failed");
            return false;
        }
        j.reset(new_j);
        if (BN_is_zero(j.get()) || BN_cmp(j.get(), q.get()) >= 0)
        {
            LOG_ERROR("Test vector j out of range");
            return false;
        }
    }
    else
    {
        const int order_bits  = BN_num_bits(q.get());
        const int order_bytes = (order_bits + 7) / 8;
        std::vector<unsigned char> buf(static_cast<size_t>(order_bytes));

        int ok = 1;
        do
        {
            if (RAND_bytes(buf.data(), order_bytes) != 1)
            {
                LOG_ERROR("RAND_bytes failed when generating j");
                return false;
            }

            if (!BN_bin2bn(buf.data(), order_bytes, j.get()))
            {
                LOG_ERROR("BN_bin2bn failed when generating j");
                return false;
            }

            // j = j mod q
            if (!BN_mod(j.get(), j.get(), q.get(), ctx.get()))
            {
                LOG_ERROR("BN_mod failed when reducing j modulo q");
                return false;
            }

            ok = !BN_is_zero(j.get());
        } while (!ok);
    }

    // (Step 2) Compute J = [j]G and set r = Jx
    EC_POINT_ptr J(EC_POINT_new(getGroup()), EC_POINT_free);
    if (!J || !EC_POINT_mul(getGroup(), J.get(), nullptr, getGeneratorPoint(), j.get(), ctx.get()))
    {
        LOG_ERROR("EC_POINT_mul: J = [j]G failed");
        return false;
    }
    BN_ptr Jx(BN_new(), BN_free);
    BN_ptr Jy(BN_new(), BN_free);
    if (!Jx || !Jy || !EC_POINT_get_affine_coordinates(getGroup(), J.get(), Jx.get(), Jy.get(), ctx.get()))
    {
        LOG_ERROR("Failed to get affine coordinates of J");
        return false;
    }

    eccsi_sakke::utils::OctetString r = fromBignum(Jx.get(), 32);

    char *Jx_hex = BN_bn2hex(Jx.get());
    if (!Jx_hex)
        throw std::runtime_error("BN_bn2hex failed");
    char *Jy_hex = BN_bn2hex(Jy.get());
    if (!Jy_hex)
        throw std::runtime_error("BN_bn2hex failed");
    LOG_DEBUG("sign J: 04", Jx_hex, Jy_hex);
    OPENSSL_free(Jx_hex);
    OPENSSL_free(Jy_hex);
    LOG_DEBUG("sign r: ", r.toHexString());

    // (Step 3) Compute HS = hash(G || KPAK || userId || PVT)
    std::vector<uint8_t> g_buf(65);
    if (EC_POINT_point2oct(getGroup(), getGeneratorPoint(), POINT_CONVERSION_UNCOMPRESSED,
                            g_buf.data(), g_buf.size(), ctx.get()) != 65)
    {
        LOG_ERROR("Failed to convert G_point to octet");
        return false;
    }
    eccsi_sakke::utils::OctetString G(g_buf);
    eccsi_sakke::utils::OctetString HS = computeHS(G, kpak, userId, pvt);

    // (Step 4) Compute HE = hash(HS || r || message)
    eccsi_sakke::utils::OctetString HE = computeHE(HS, r, message);

    // (Step 5) Compute denominator: denom = HE + r * SSK mod q
    BN_ptr he(toBignum(HE), BN_free);
    BN_ptr r_bn(BN_dup(Jx.get()), BN_free);
    BN_ptr ssk_bn(toBignum(ssk), BN_free);
    if (!he || !r_bn || !ssk_bn)
    {
        LOG_ERROR("Failed to convert to BIGNUM for HE, r, or SSK");
        return false;
    }
    BN_ptr r_mul_ssk(BN_new(), BN_free);
    BN_ptr denom(BN_new(), BN_free);
    if (!r_mul_ssk || !denom)
    {
        LOG_ERROR("Failed to allocate r_mul_ssk or denom");
        return false;
    }
    if (!BN_mod_mul(r_mul_ssk.get(), r_bn.get(), ssk_bn.get(), q.get(), ctx.get()))
    {
        LOG_ERROR("BN_mod_mul: r*SSK mod q failed");
        return false;
    }
    if (!BN_mod_add(denom.get(), he.get(), r_mul_ssk.get(), q.get(), ctx.get()))
    {
        LOG_ERROR("BN_mod_add: HE + r*SSK mod q failed");
        return false;
    }
    if (BN_is_zero(denom.get()))
    {
        LOG_ERROR("Denominator is zero: cannot sign (HE + r*SSK == 0)");
        return false;
    }

    // (Step 6) Compute s = ((HE + r*SSK)^-1 * j) mod q
    BN_ptr denom_inv(BN_mod_inverse(nullptr, denom.get(), q.get(), ctx.get()), BN_free);
    BN_ptr s(BN_new(), BN_free);
    if (!denom_inv || !s)
    {
        LOG_ERROR("Failed to allocate or invert denom for s");
        return false;
    }
    if (!BN_mod_mul(s.get(), denom_inv.get(), j.get(), q.get(), ctx.get()))
    {
        LOG_ERROR("BN_mod_mul: s = denom^-1 * j mod q failed");
        return false;
    }

    // (Step 7) If s > N bytes, set s = q - s (see RFC 6507 Sec 5.2.1 Step 6)
    if (BN_num_bytes(s.get()) > 32)
    {
        BN_sub(s.get(), q.get(), s.get());
    }

    // (Step 8) Output the signature: SIG = r || s || PVT (RFC 6507 Section 5.2.1 Step 7)
    eccsi_sakke::utils::OctetString r_oct = fromBignum(r_bn.get(), 32);
    eccsi_sakke::utils::OctetString s_oct = fromBignum(s.get(), 32);

    signature = r_oct;
    signature.append(s_oct);
    signature.append(pvt);

    LOG_INFO("ECCSI signature generation succeeded!");
    return true;
}

bool ECCSI::verify(const eccsi_sakke::utils::OctetString &message,
                    const eccsi_sakke::utils::OctetString &signature,
                    const eccsi_sakke::utils::OctetString &userId,
                    const eccsi_sakke::utils::OctetString &kpak)
{
    LOG_INFO("ECCSI::verify() called");
    // (Step 0) Check signature length (RFC 6507: r(32) + s(32) + PVT(65))
    if (signature.size() < (32 + 32 + 65))
    {
        LOG_ERROR("Invalid signature length: %zu", signature.size());
        return false;
    }

    using BN_ptr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
    using EC_POINT_ptr = std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>;
    using BN_CTX_ptr = std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;
    BN_CTX_ptr ctx(BN_CTX_new(), BN_CTX_free);
    if (!ctx)
    {
        LOG_ERROR("Failed to create BN_CTX");
        return false;
    }

    // Parse signature into r, s, PVT
    eccsi_sakke::utils::OctetString r = signature.slice(0, 32);
    eccsi_sakke::utils::OctetString s = signature.slice(32, 32);
    eccsi_sakke::utils::OctetString pvt = signature.slice(64, 65);

    // (Step 1) Convert r and s to BIGNUM
    BN_ptr r_bn(toBignum(r), BN_free);
    BN_ptr s_bn(toBignum(s), BN_free);
    if (!r_bn || !s_bn)
    {
        LOG_ERROR("Failed to convert r or s to BIGNUM");
        return false;
    }

    // (Step 2) Compute HS = hash(G || KPAK || userId || PVT)
    std::vector<uint8_t> g_buf(65);
    if (EC_POINT_point2oct(getGroup(), getGeneratorPoint(), POINT_CONVERSION_UNCOMPRESSED,
                            g_buf.data(), g_buf.size(), ctx.get()) != 65)
    {
        LOG_ERROR("Failed to convert G_point to octet");
        return false;
    }
    eccsi_sakke::utils::OctetString G(g_buf);

    eccsi_sakke::utils::OctetString HS = computeHS(G, kpak, userId, pvt);
    BN_ptr hs_bn(toBignum(HS), BN_free);
    if (!hs_bn)
    {
        LOG_ERROR("Failed to convert HS to BIGNUM");
        return false;
    }

    // (Step 3) Compute HE = hash(HS || r || message)
    eccsi_sakke::utils::OctetString HE = computeHE(HS, r, message);
    BN_ptr he_bn(toBignum(HE), BN_free);
    if (!he_bn)
    {
        LOG_ERROR("Failed to convert HE to BIGNUM");
        return false;
    }

    // (Step 4) Restore PVT as EC_POINT, check on curve (optional)
    EC_POINT_ptr PVT_point(EC_POINT_new(getGroup()), EC_POINT_free);
    if (!PVT_point || !EC_POINT_oct2point(getGroup(), PVT_point.get(), pvt.bytes().data(), pvt.size(), ctx.get()))
    {
        LOG_ERROR("Failed to convert PVT to EC_POINT");
        return false;
    }
    // (Optional: Curve check) if (!EC_POINT_is_on_curve(getGroup(), PVT_point.get(), ctx.get())) { ... }

    // (Step 5) Compute Y = [HS]PVT + KPAK
    EC_POINT_ptr Y(EC_POINT_new(getGroup()), EC_POINT_free);
    if (!Y || !EC_POINT_mul(getGroup(), Y.get(), nullptr, PVT_point.get(), hs_bn.get(), ctx.get()))
    {
        LOG_ERROR("EC_POINT_mul: [HS]PVT failed");
        return false;
    }
    EC_POINT_ptr KPAK_point(EC_POINT_new(getGroup()), EC_POINT_free);
    if (!KPAK_point || !EC_POINT_oct2point(getGroup(), KPAK_point.get(), kpak.bytes().data(), kpak.size(), ctx.get()))
    {
        LOG_ERROR("Failed to convert KPAK to EC_POINT");
        return false;
    }
    if (!EC_POINT_add(getGroup(), Y.get(), Y.get(), KPAK_point.get(), ctx.get()))
    {
        LOG_ERROR("EC_POINT_add: Y = [HS]PVT + KPAK failed");
        return false;
    }

    // (Step 6) Compute J = [s]([HE]G + [r]Y)
    EC_POINT_ptr HEG(EC_POINT_new(getGroup()), EC_POINT_free);
    EC_POINT_ptr rY(EC_POINT_new(getGroup()), EC_POINT_free);
    EC_POINT_ptr sum(EC_POINT_new(getGroup()), EC_POINT_free);
    EC_POINT_ptr J(EC_POINT_new(getGroup()), EC_POINT_free);

    if (!HEG || !rY || !sum || !J)
    {
        LOG_ERROR("Failed to allocate temporary EC_POINTs");
        return false;
    }
    // [HE]G
    if (!EC_POINT_mul(getGroup(), HEG.get(), nullptr, getGeneratorPoint(), he_bn.get(), ctx.get()))
    {
        LOG_ERROR("EC_POINT_mul: [HE]G failed");
        return false;
    }
    // [r]Y
    if (!EC_POINT_mul(getGroup(), rY.get(), nullptr, Y.get(), r_bn.get(), ctx.get()))
    {
        LOG_ERROR("EC_POINT_mul: [r]Y failed");
        return false;
    }
    // ([HE]G + [r]Y)
    if (!EC_POINT_add(getGroup(), sum.get(), HEG.get(), rY.get(), ctx.get()))
    {
        LOG_ERROR("EC_POINT_add: sum = [HE]G + [r]Y failed");
        return false;
    }
    // J = [s]sum
    if (!EC_POINT_mul(getGroup(), J.get(), nullptr, sum.get(), s_bn.get(), ctx.get()))
    {
        LOG_ERROR("EC_POINT_mul: J = [s]sum failed");
        return false;
    }

    // (Step 7) Check Jx == r mod p, and Jx != 0
    BN_ptr Jx(BN_new(), BN_free);
    BN_ptr Jy(BN_new(), BN_free);
    if (!Jx || !Jy || !EC_POINT_get_affine_coordinates(getGroup(), J.get(), Jx.get(), Jy.get(), ctx.get()))
    {
        LOG_ERROR("Failed to get affine coordinates of J");
        return false;
    }
    BN_ptr p(BN_new(), BN_free);
    if (!p || !EC_GROUP_get_curve(getGroup(), p.get(), nullptr, nullptr, ctx.get()))
    {
        LOG_ERROR("Failed to get curve parameter p");
        return false;
    }

    BN_mod(Jx.get(), Jx.get(), p.get(), ctx.get());
    BN_mod(r_bn.get(), r_bn.get(), p.get(), ctx.get());

    // Signature is valid if Jx == r mod p and Jx != 0
    bool result = (BN_cmp(Jx.get(), r_bn.get()) == 0 && !BN_is_zero(Jx.get()));
    if (result)
    {
        LOG_INFO("ECCSI signature verification succeeded!");
    }
    else
    {
        LOG_ERROR("ECCSI signature verification failed (Jx mismatch)");
    }

    return result;
}

bool ECCSI::validateSSK(
    const eccsi_sakke::utils::OctetString& user_id,
    const eccsi_sakke::utils::OctetString& kpak,
    const eccsi_sakke::utils::OctetString& pvt,
    const eccsi_sakke::utils::OctetString& ssk,
    eccsi_sakke::utils::OctetString& hash_out)
{
    LOG_INFO("ECCSI::validateSSK() called");

    using BN_ptr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
    using EC_POINT_ptr = std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>;
    using BN_CTX_ptr = std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;
    BN_CTX_ptr ctx(BN_CTX_new(), BN_CTX_free);
    if (!ctx)
    {
        LOG_ERROR("Failed to create BN_CTX");
        return false;
    }

    // (Step 1) Parse PVT, KPAK as EC_POINTs, and SSK as scalar
    EC_POINT_ptr PVT_point(EC_POINT_new(getGroup()), EC_POINT_free);
    if (!PVT_point || !EC_POINT_oct2point(getGroup(), PVT_point.get(), pvt.bytes().data(), pvt.size(), ctx.get()))
    {
        LOG_ERROR("Failed to convert PVT to EC_POINT");
        return false;
    }
    if (!EC_POINT_is_on_curve(getGroup(), PVT_point.get(), ctx.get()))
    {
        LOG_ERROR("PVT point is not on the curve");
        return false;
    }

    EC_POINT_ptr KPAK_point(EC_POINT_new(getGroup()), EC_POINT_free);
    if (!KPAK_point || !EC_POINT_oct2point(getGroup(), KPAK_point.get(), kpak.bytes().data(), kpak.size(), ctx.get()))
    {
        LOG_ERROR("Failed to convert KPAK to EC_POINT");
        return false;
    }

    BN_ptr ssk_bn(BN_bin2bn(ssk.bytes().data(), ssk.size(), nullptr), BN_free);
    if (!ssk_bn)
    {
        LOG_ERROR("Failed to parse SSK as BIGNUM");
        return false;
    }

    // (Step 2) Compute G (generator) as octet string
    std::vector<uint8_t> g_buf(65);
    if (EC_POINT_point2oct(getGroup(), getGeneratorPoint(), POINT_CONVERSION_UNCOMPRESSED,
                           g_buf.data(), g_buf.size(), ctx.get()) != 65)
    {
        LOG_ERROR("Failed to convert G_point to octet");
        return false;
    }
    eccsi_sakke::utils::OctetString G(g_buf);

    // (Step 3) Compute HS = hash(G || KPAK || user_id || PVT)
    eccsi_sakke::utils::OctetString HS = computeHS(G, kpak, user_id, pvt);
    hash_out = HS;
    BN_ptr hs_bn(toBignum(HS), BN_free);
    if (!hs_bn)
    {
        LOG_ERROR("Failed to convert HS to BIGNUM");
        return false;
    }

    // (Step 4) Compute LHS = [HS]PVT + KPAK
    EC_POINT_ptr LHS(EC_POINT_new(getGroup()), EC_POINT_free);
    if (!LHS || !EC_POINT_mul(getGroup(), LHS.get(), nullptr, PVT_point.get(), hs_bn.get(), ctx.get()))
    {
        LOG_ERROR("EC_POINT_mul: [HS]PVT failed");
        return false;
    }
    if (!EC_POINT_add(getGroup(), LHS.get(), LHS.get(), KPAK_point.get(), ctx.get()))
    {
        LOG_ERROR("EC_POINT_add: [HS]PVT + KPAK failed");
        return false;
    }

    // (Step 5) Compute RHS = [SSK]G
    EC_POINT_ptr RHS(EC_POINT_new(getGroup()), EC_POINT_free);
    if (!RHS || !EC_POINT_mul(getGroup(), RHS.get(), nullptr, getGeneratorPoint(), ssk_bn.get(), ctx.get()))
    {
        LOG_ERROR("EC_POINT_mul: [SSK]G failed");
        return false;
    }

    // (Step 6) Compare LHS and RHS
    bool result = (EC_POINT_cmp(getGroup(), LHS.get(), RHS.get(), ctx.get()) == 0);

    if (result)
    {
        LOG_INFO("ECCSI SSK validation succeeded (LHS == RHS)");
    }
    else
    {
        LOG_ERROR("ECCSI SSK validation failed (LHS != RHS)");
    }

    return result;
}

}

