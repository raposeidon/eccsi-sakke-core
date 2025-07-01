/*
 * Copyright (C) 2025 raposeidon
 * Licensed under the Apache License, Version 2.0 (the "License");
*/

/*************************************************************************
 * @file demo.cpp
 * @brief 
 *
 *************************************************************************/

#include "utils/OctetString.h"
#include "utils/LoggerMacro.h"
#include "eccsi/eccsi.h"
#include "sakke/sakke.h"
#include "utils/Random.h"
#include <string>
#include <vector>

using namespace eccsi_sakke::utils;
using namespace eccsi_sakke::eccsi;
using namespace eccsi_sakke::sakke;

int main()
{
    Logger::setOutput(defaultLogOutput);
    LOG_INFO("Testing ECCSI Signature Generation and Verification...");
    // 1. ID 등 데이터 준비
    OctetString signer_id = OctetString::fromHex(std::string("323031312D30320074656C3A2B34343737303039303031323300"));
    LOG_DEBUG("User ID: " + signer_id.printableString());

    // 2. 메시지 생성
    OctetString message = OctetString::fromHex(std::string("6D65737361676500"));
    LOG_DEBUG("message: " + message.toHexString());

    // 3. Key
    std::string KPAK_str = "04"
                           "50D4670B DE75244F 28D2838A 0D25558A"
                           "7A72686D 4522D4C8 273FB644 2AEBFA93"
                           "DBDD3755 1AFD263B 5DFD617F 3960C65A"
                           "8C298850 FF99F203 66DCE7D4 367217F4";
    OctetString KPAK = OctetString::fromHex(KPAK_str);

    std::string PVT_str = "04"
                          "758A1427 79BE89E8 29E71984 CB40EF75"
                          "8CC4AD77 5FC5B9A3 E1C8ED52 F6FA36D9"
                          "A79D2476 92F4EDA3 A6BDAB77 D6AA6474"
                          "A464AE49 34663C52 65BA7018 BA091F79";
    OctetString PVT = OctetString::fromHex(PVT_str);

    std::string SSK_str = "23F374AE 1F4033F3 E9DBDDAA EF20F4CF"
                          "0B86BBD5 A138A5AE 9E7E006B 34489A0D";
    OctetString SSK = OctetString::fromHex(SSK_str);

    // 4. 서명
    OctetString signature;
    bool tmp_res = false;
    tmp_res = ECCSI::sign(
        message,
        signer_id,
        PVT,  // 공개 파생점
        SSK,  // 서명 비밀키
        KPAK, // KPAK (커뮤니티 공개키)
        signature, true);

    if (tmp_res)
    {
        LOG_INFO("Sig: ", signature.toHexString());
        bool verify_result = ECCSI::verify(
            message,
            signature,
            signer_id,
            KPAK);

        if (verify_result)
            LOG_INFO("ECCSI Signature verification succeeded!");
    }
    OctetString bob_id = OctetString::fromHex(std::string("323031312D30320074656C3A2B34343737303039303031323300"));
    LOG_DEBUG("Bob's User ID: " + bob_id.printableString());
    std::string Zx_str =
        "5958EF1B 1679BF09 9B3A030D F255AA6A"
        "23C1D8F1 43D4D23F 753E69BD 27A832F3"
        "8CB4AD53 DDEF4260 B0FE8BB4 5C4C1FF5"
        "10EFFE30 0367A37B 61F701D9 14AEF097"
        "24825FA0 707D61A6 DFF4FBD7 273566CD"
        "DE352A0B 04B7C16A 78309BE6 40697DE7"
        "47613A5F C195E8B9 F328852A 579DB8F9"
        "9B1D0034 479EA9C5 595F47C4 B2F54FF2";
    OctetString Zx = OctetString::fromHex(Zx_str);
    LOG_DEBUG("Zx: " + Zx.toHexString());

    std::string Zy_str =
        "1508D375 14DCF7A8 E143A605 8C09A6BF"
        "2C9858CA 37C25806 5AE6BF75 32BC8B5B"
        "63383866 E0753C5A C0E72709 F8445F2E"
        "6178E065 857E0EDA 10F68206 B63505ED"
        "87E534FB 2831FF95 7FB7DC61 9DAE6130"
        "1EEACC2F DA3680EA 4999258A 833CEA8F"
        "C67C6D19 487FB449 059F26CC 8AAB655A"
        "B58B7CC7 96E24E9A 39409575 4F5F8BAE";
    OctetString Zy = OctetString::fromHex(Zy_str);
    LOG_DEBUG("Zy: " + Zy.toHexString());

    OctetString Z = OctetString::fromHex("04");
    Z.append(Zx);
    Z.append(Zy);
    LOG_DEBUG("Z: " + Z.toHexString());

    OctetString ssv = OctetString::fromHex("12345678 9ABCDEF0 12345678 9ABCDEF0");
    OctetString payload;

    bool encapsulate_result = SAKKE::generateSakkeEncapsulatedData(
        bob_id, Z, ssv, payload);

    if (!encapsulate_result)
    {
        LOG_ERROR("SAKKE Encapsulation failed!");
        return 1;
    }

    LOG_INFO("SAKKE Encapsulated SSV: " + ssv.toHexString());
    LOG_INFO("SAKKE Encapsulated Payload: " + payload.toHexString());

    std::string Kbx_str =
        "93AF67E5 007BA6E6 A80DA793 DA300FA4"
        "B52D0A74 E25E6E7B 2B3D6EE9 D18A9B5C"
        "5023597B D82D8062 D3401956 3BA1D25C"
        "0DC56B7B 979D74AA 50F29FBF 11CC2C93"
        "F5DFCA61 5E609279 F6175CEA DB00B58C"
        "6BEE1E7A 2A47C4F0 C456F052 59A6FA94"
        "A634A40D AE1DF593 D4FECF68 8D5FC678"
        "BE7EFC6D F3D68353 25B83B2C 6E69036B";
    OctetString Kbx = OctetString::fromHex(Kbx_str);
    LOG_DEBUG("Kbx: " + Kbx.toHexString());

    std::string Kby_str =
        "155F0A27 241094B0 4BFB0BDF AC6C670A"
        "65C325D3 9A069F03 659D44CA 27D3BE8D"
        "F311172B 55416018 1CBE94A2 A783320C"
        "ED590BC4 2644702C F371271E 496BF20F"
        "588B78A1 BC01ECBB 6559934B DD2FB65D"
        "2884318A 33D1A42A DF5E33CC 5800280B"
        "28356497 F87135BA B9612A17 26042440"
        "9AC15FEE 996B744C 33215123 5DECB0F5";
    OctetString Kby = OctetString::fromHex(Kby_str);
    LOG_DEBUG("Kby: " + Kby.toHexString());

    OctetString rsk = OctetString::fromHex("04");
    rsk.append(Kbx);
    rsk.append(Kby);
    LOG_DEBUG("rsk: " + rsk.toHexString());

    auto res = SAKKE::validateRSK(bob_id, Z, rsk);

    OctetString extract_ssv;

    encapsulate_result = SAKKE::sakke_extractSharedSecret(
        bob_id, rsk, Z, payload, extract_ssv);

    if (encapsulate_result)
    {
        LOG_INFO("SAKKE Extract SSV: " + extract_ssv.toHexString());
    }
    else
    {
        LOG_ERROR("SAKKE Extract failed!");
        return 1;
    }
    return 0;
}
