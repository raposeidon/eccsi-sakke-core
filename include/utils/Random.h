/*
 * Copyright (C) 2025 raposeidon
 * Licensed under the Apache License, Version 2.0 (the "License");
*/

#pragma once
#include "eccsisakke_export.h"
#include <vector>

namespace eccsi_sakke::utils {

    /**
     * @brief Securely generates a random byte sequence of specified length.
     *
     * @details
     * Uses a cryptographically secure random number generator suitable for key material and nonces.
     *
     * @param num_bytes The number of random bytes to generate.
     * @return std::vector<uint8_t> Vector containing random bytes of size num_bytes.
     * @throws std::runtime_error if secure random generation fails (implementation-dependent).
     *
     * @note This function should always be used for cryptographic purposes, never std::rand or similar.
     * @warning The security of generated values depends on the quality of system entropy.
     */
    ECCSISAKKE_API std::vector<uint8_t> generateRandomR(size_t num_bytes);

} // namespace mikey::utils
