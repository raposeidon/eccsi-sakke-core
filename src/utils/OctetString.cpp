/*
 * Copyright (C) 2025 raposeidon
 * Licensed under the Apache License, Version 2.0 (the "License");
*/

// This file implements the OctetString class for handling byte strings,
// including conversion between hex strings, plain strings, and raw byte buffers.

#include "utils/OctetString.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <stdexcept>
#include <cctype>
#include <openssl/crypto.h>
namespace eccsi_sakke::utils {

/**
 * @brief Default constructor. Constructs an empty OctetString.
 */
OctetString::OctetString() = default;

/**
 * @brief Construct from a byte vector.
 * @param bytes The byte vector.
 */
OctetString::OctetString(const std::vector<uint8_t> &bytes)
    : data(bytes) {}

/**
 * @brief Move-construct from a byte vector.
 * @param bytes The byte vector (rvalue).
 */
OctetString::OctetString(std::vector<uint8_t> &&bytes) noexcept
    : data(std::move(bytes)) {}

/**
 * @brief Move constructor.
 * @param other The OctetString to move from.
 */
OctetString::OctetString(OctetString &&other) noexcept
    : data(std::move(other.data)) {}

/**
 * @brief Move assignment.
 * @param other The OctetString to move from.
 */
OctetString &OctetString::operator=(OctetString &&other) noexcept
{
    if (this != &other)
    {
        data = std::move(other.data);
    }
    return *this;
}

/**
 * @brief Create an OctetString from a hex string.
 * @param hexStr The input hex string.
 * @throws std::invalid_argument if input is invalid hex.
 */
OctetString OctetString::fromHex(const std::string &hexStr)
{
    // erase whitespace (isspace: space, \n, \t, etc)
    std::string hex;
    hex.reserve(hexStr.size());
    for (char c : hexStr)
    {
        if (!isspace(static_cast<unsigned char>(c)))
            hex += c;
    }

    if (hex.length() % 2 != 0)
        throw std::invalid_argument("Hex string length must be even");
    if (!isHexString(hex))
        throw std::invalid_argument("Invalid hex character in OctetString::fromHex");
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.length() / 2);
    for (size_t i = 0; i < hex.length(); i += 2)
    {
        bytes.push_back(static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
    }
    return OctetString(std::move(bytes));
}

/**
 * @brief Create an OctetString from a plain (ASCII/UTF-8) string.
 * @param str The plain string.
 */
OctetString OctetString::fromString(const std::string &str)
{
    return OctetString(std::vector<uint8_t>(str.begin(), str.end()));
}

/**
 * @brief Create an OctetString from a raw byte buffer.
 * @param ptr Pointer to bytes.
 * @param len Number of bytes.
 */
OctetString OctetString::fromBytes(const uint8_t *ptr, size_t len)
{
    return OctetString(std::vector<uint8_t>(ptr, ptr + len));
}

/**
 * @brief Create an OctetString from input, auto-detecting hex or plain string.
 * @param input The input string.
 * @details If the string has only hex digits and even length, treated as hex; otherwise as plain string.
 */
OctetString OctetString::fromAutoDetect(const std::string &input)
{
    return isHexString(input) ? fromHex(input) : fromString(input);
}

/**
 * @brief Check if the string is a valid hex string.
 * @param input Input string.
 * @return true if valid hex, false otherwise.
 */
bool OctetString::isHexString(const std::string &input)
{
    if (input.size() % 2 != 0)
        return false;
    return std::all_of(input.begin(), input.end(),
                        [](char c)
                        { return std::isxdigit(static_cast<unsigned char>(c)); });
}

/**
 * @brief Convert the octet string to a lowercase hex string.
 * @return Hex string representation.
 */
std::string OctetString::toHexString() const
{
    std::ostringstream oss;
    for (auto b : data)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    return oss.str();
}

/**
 * @brief Convert to plain (ASCII/UTF-8) string.
 * @return Plain string.
 */
std::string OctetString::toString() const
{
    return std::string(data.begin(), data.end());
}

/**
 * @brief Get a printable version (non-printables as '.').
 * @return String with ASCII or '.'.
 */
std::string OctetString::printableString() const
{
    std::string out;
    for (uint8_t b : data)
        out += (b >= 0x20 && b <= 0x7E) ? static_cast<char>(b) : '.';
    return out;
}

/**
 * @brief Append another OctetString.
 * @param other The OctetString to append.
 */
void OctetString::append(const OctetString &other)
{
    data.insert(data.end(), other.data.begin(), other.data.end());
}

/**
 * @brief Append a single byte.
 * @param byte The byte to append.
 */
void OctetString::append(uint8_t byte)
{
    data.push_back(byte);
}

/**
 * @brief Get a subrange as a new OctetString.
 * @param start Start index.
 * @param len Number of bytes.
 * @return The slice as OctetString.
 */
OctetString OctetString::slice(size_t start, size_t len) const
{
    if (start >= data.size())
        return OctetString();
    size_t real_len = std::min(len, data.size() - start);
    return OctetString(std::vector<uint8_t>(data.begin() + start, data.begin() + start + real_len));
}

}
