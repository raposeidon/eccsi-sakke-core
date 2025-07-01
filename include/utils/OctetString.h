/*
 * Copyright (C) 2025 raposeidon
 * Licensed under the Apache License, Version 2.0 (the "License");
*/

#pragma once

#include "eccsisakke_export.h"
#include <vector>
#include <string>
#include <cstdint>
#include <iostream>

namespace eccsi_sakke::utils {

/**
 * @class OctetString
 * @brief Utility class for safe manipulation of octet (byte) sequences.
 *
 * - Owns and manages a byte vector for safe handling of arbitrary binary data.
 * - Provides various construction, conversion, and comparison methods, including:
 *    - Hex and plain string conversion.
 *    - Efficient and safe copy/move semantics.
 *    - Equality/inequality, stream output operators.
 * - Supports low-level byte access, size, and slicing operations.
 * - All methods are exception-safe.
 *
 * @note
 *   - Used for all raw binary values, cryptographic keys, and protocol parameters.
 *   - Designed to avoid dependencies on external cryptographic libraries for maximal portability.
 *   - **Secure wipe (zeroization) is NOT performed automatically on destruction.**
 *     - Users MUST explicitly wipe sensitive contents (e.g., via std::fill or a custom wipe function)
 *       before releasing or reusing OctetString objects that hold secret material.
 *   - The class is lightweight and safe for use as a return type or value object.
 *   - Intended for use wherever safe, flexible binary data handling is required.
 */
class ECCSISAKKE_API OctetString
{
public:
    /**
     * @brief Default constructor. Constructs an empty OctetString.
     */
    OctetString();

    /**
     * @brief Copy constructor.
     */
    OctetString(const OctetString &) = default;

    /**
     * @brief Copy assignment.
     */
    OctetString &operator=(const OctetString &) = default;

    /**
     * @brief Move constructor.
     */
    OctetString(OctetString &&) noexcept;

    /**
     * @brief Move assignment.
     */
    OctetString &operator=(OctetString &&) noexcept;

    /**
     * @brief Construct from a byte vector (raw binary data).
     * @param bytes The byte vector to initialize from.
     */
    explicit OctetString(const std::vector<uint8_t> &bytes);

    /**
     * @brief Move-construct from a byte vector (raw binary data).
     * @param bytes The byte vector to move from.
     */
    explicit OctetString(std::vector<uint8_t> &&bytes) noexcept;

    /**
     * @brief Construct from a hex string (e.g., "0A1B2C").
     * @param hexStr The hex string.
     * @throws std::invalid_argument if the input is not valid hex.
     */
    static OctetString fromHex(const std::string &hexStr);

    /**
     * @brief Construct from a plain string (ASCII/UTF-8).
     * @param str The plain string.
     */
    static OctetString fromString(const std::string &str);

    /**
     * @brief Construct from a raw byte buffer.
     * @param ptr The pointer to the buffer.
     * @param len The length of the buffer.
     */
    static OctetString fromBytes(const uint8_t *ptr, size_t len);

    /**
     * @brief Construct from input, auto-detecting hex or plain.
     * @param input The input string.
     * @details If the input contains only hex digits and has even length,
     *          interprets as hex; otherwise as plain string.
     */
    static OctetString fromAutoDetect(const std::string &input);

    /**
     * @brief Test whether a string is a valid hex string.
     * @param input The string to test.
     * @return true if valid hex, false otherwise.
     */
    static bool isHexString(const std::string &input);

    /**
     * @brief Convert the octet string to a hex string (e.g., "0a1b2c").
     * @return The hex string.
     */
    std::string toHexString() const;

    /**
     * @brief Convert the octet string to a plain string (ASCII/UTF-8).
     * @return The plain string.
     */
    std::string toString() const;

    /**
     * @brief Return a human-friendly printable string (non-printable bytes as '.').
     * @return The printable string.
     */
    std::string printableString() const;

    /**
     * @brief Get a reference to the internal byte vector. (const, read-only)
     * @return The byte vector.
     */
    inline const std::vector<uint8_t> &bytes() const { return data; }

    /**
     * @brief Returns a mutable reference to the internal byte vector.(mutable, for secure wipe etc)
     *
     * This allows external code to modify or securely wipe the contents of the OctetString.
     *
     * @warning Modifying the returned vector directly affects the OctetString's state.
     *          Use with care, especially when secure erasure (zeroization) is needed.
     *
     * @return Mutable reference to the underlying byte vector.
     */
    inline std::vector<uint8_t> &bytes() { return data; }

    /**
     * @brief Get the number of bytes.
     * @return The length of the octet string.
     */
    inline size_t size() const { return data.size(); }

    /**
     * @brief Check if the octet string is empty.
     * @return true if empty, false otherwise.
     */
    inline bool empty() const { return data.empty(); }

    /**
     * @brief Append another OctetString to this one.
     * @param other The OctetString to append.
     */
    void append(const OctetString &other);

    /**
     * @brief Append a single byte to the octet string.
     * @param byte The byte to append.
     */
    void append(uint8_t byte);

    /**
     * @brief Get a sub-sequence (slice) of the octet string.
     * @param start The start index.
     * @param len The length of the slice.
     * @return The sliced OctetString.
     */
    OctetString slice(size_t start, size_t len) const;

    /**
     * @brief Print as a hex string to the output stream.
     * @param os The output stream.
     * @param o The OctetString to print.
     * @return Reference to the output stream.
     */
    friend std::ostream &operator<<(std::ostream &os, const OctetString &o) { return os << o.toHexString(); }

    /**
     * @brief Equality comparison (contents).
     * @param other The OctetString to compare.
     * @return true if the contents are equal.
     */
    inline bool operator==(const OctetString &other) const { return data == other.data; }

    /**
     * @brief Inequality comparison (contents).
     * @param other The OctetString to compare.
     * @return true if the contents are NOT equal.
     */
    inline bool operator!=(const OctetString &other) const { return data != other.data; }

private:
    std::vector<uint8_t> data; ///< The underlying byte data.
};

}
