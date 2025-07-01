/*
 * Copyright (C) 2025 raposeidon
 * Licensed under the Apache License, Version 2.0 (the "License");
*/

#include "utils/LoggerMacro.h"
#include "sakke/SakkeParameterSet.h"
#include <sstream>
#include <iomanip>
#include <mutex>

namespace eccsi_sakke::sakke {
// SAKKE Parameter Set 1 (RFC 6509 Appendix A, IANA = 1)
// This parameter set is used for SAKKE encapsulation and decapsulation.

const SakkeParameterSet&    sakke_param_set_1() {
    static SakkeParameterSet params {
  /*iana*/ 1,

  /* n  */ 128,

  /* p  */ "997ABB1F0A563FDA65C61198DAD0657A"
           "416C0CE19CB48261BE9AE358B3E01A2E"
           "F40AAB27E2FC0F1B228730D531A59CB0"
           "E791B39FF7C88A19356D27F4A666A6D0"
           "E26C6487326B4CD4512AC5CD65681CE1"
           "B6AFF4A831852A82A7CF3C521C3C09AA"
           "9F94D6AF56971F1FFCE3E82389857DB0"
           "80C5DF10AC7ACE87666D807AFEA85FEB",
            /*!< RFC 6509 Appendix A page 19.  */

  /* q  */ "265EAEC7C2958FF69971846636B4195E"
           "905B0338672D20986FA6B8D62CF8068B"
           "BD02AAC9F8BF03C6C8A1CC354C69672C"
           "39E46CE7FDF222864D5B49FD2999A9B4"
           "389B1921CC9AD335144AB173595A0738"
           "6DABFD2A0C614AA0A9F3CF14870F026A"
           "A7E535ABD5A5C7C7FF38FA08E2615F6C"
           "203177C42B1EB3A1D99B601EBFAA17FB",
            /*!< RFC 6509 Appendix A page 19.  */

  /* Px */ "53FC09EE332C29AD0A7990053ED9B52A"
           "2B1A2FD60AEC69C698B2F204B6FF7CBF"
           "B5EDB6C0F6CE2308AB10DB9030B09E10"
           "43D5F22CDB9DFA55718BD9E7406CE890"
           "9760AF765DD5BCCB337C86548B72F2E1"
           "A702C3397A60DE74A7C1514DBA66910D"
           "D5CFB4CC80728D87EE9163A5B63F73EC"
           "80EC46C4967E0979880DC8ABEAE63895",
           /*!< RFC 6509 Appendix A page 19.  */

  /* Py */ "0A8249063F6009F1F9F1F0533634A135"
           "D3E82016029906963D778D821E141178"
           "F5EA69F4654EC2B9E7F7F5E5F0DE55F6"
           "6B598CCF9A140B2E416CFF0CA9E032B9"
           "70DAE117AD547C6CCAD696B5B7652FE0"
           "AC6F1E80164AA989492D979FC5A4D5F2"
           "13515AD7E9CB99A980BDAD5AD5BB4636"
           "ADB9B5706A67DCDE75573FD71BEF16D7",
           /*!< RFC 6509 Appendix A page 19.  */

  /* g  */ "66FC2A432B6EA392148F15867D623068"
           "C6A87BD1FB94C41E27FABE658E015A87"
           "371E94744C96FEDA449AE9563F8BC446"
           "CBFDA85D5D00EF577072DA8F541721BE"
           "EE0FAED1828EAB90B99DFB0138C78433"
           "55DF0460B4A9FD74B4F1A32BCAFA1FFA"
           "D682C033A7942BCCE3720F20B9B7B040"
           "3C8CAE87B7A0042ACDE0FAB36461EA46",
           /*!< RFC 6509 Appendix A page 20.  */

        // --- SAKKE Parameter Curve Setup ---
        //
        // - a = -3 (as used in standard prime curves)
        // - b = 0 (MANDATORY for SAKKE cryptographic operations; see RFC 6508 Appendix A, jim-b reference)
        //   - The SAKKE and ECCSI algorithms require the curve y^2 = x^3 - 3x + 0 mod p for all internal crypto operations.
        //   - Do NOT use the standard B parameter here; using b=0 ensures compatibility with test vectors (RFC 6508).
        //   - Only use the official B value (e.g., NIST P-256) for public key serialization
        //     or ASN.1/external exchange, **never for SAKKE encryption**.
  /* a  */ "-3l",  /* Coefficient of 'x', see RFC 6508 Section 
                    * 2.1 description of 'E'. */
  /* b  */ "0",

        // Hash Algorithm
        SakkeHashAlg::SHA256,
        SHA256_DIGEST_LENGTH,  // Hash output length in octets
    };
    return params;
}

std::string printParameterSet(const int param_set) {
    if (param_set != 1) {
        return "Unsupported SAKKE Parameter Set: " + std::to_string(param_set);
    }
    const SakkeParameterSet& param = sakke_param_set_1();
    
    std::ostringstream oss;
    oss << "SAKKE Parameter Set " << param_set << " (IANA: " << param.iana << ")";
    oss << "\nSecurity Level: " << param.n_bits << " bits";
    oss << "\nHash Algorithm: ";
    switch (param.hash_alg) {
        case SakkeHashAlg::SHA256:
            oss << "SHA-256 (" << param.hash_len << " octets)";
            break;
        case SakkeHashAlg::SHA384:
            oss << "SHA-384 (" << param.hash_len << " octets)";
            break;
        case SakkeHashAlg::SHA512:
            oss << "SHA-512 (" << param.hash_len << " octets)";
            break;
        default:
            oss << "Unknown";
    }
    oss << "\nField Prime (p): " << param.p;
    oss << "\nSubgroup Order (q): " << param.q;
    oss << "\nBase Point P: (" << param.Px << ", " << param.Py << ")";
    oss << "\nGenerator g: " << param.g;
    oss << "\n";
    return oss.str();
}

const SakkeParameterSet* get_sakke_param_by_id(const int param_set) {
    if (param_set == 1) return &sakke_param_set_1();
    return nullptr;
}

} // namespace mikey::crypto