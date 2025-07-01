/*
 * Copyright (C) 2025 raposeidon
 * Licensed under the Apache License, Version 2.0 (the "License");
*/

#pragma once
#include "utils/Logger.h"

/**
 * @def LOG_MODULE
 * @brief Module name used for all logs in this translation unit.
 * @note Redefine LOG_MODULE before including this header to customize.
 * @example
 *   #define LOG_MODULE "CRYPTO"
 *   #include "LoggerMacro.h"
 */
#ifndef LOG_MODULE
#define LOG_MODULE "APP"
#endif


/**
 * @def LOG_ERROR(...)
 * @brief Logs an error-level message with module, file, and line context.
 * @param ... Message components (variadic)
 *
 * @def LOG_WARNING(...)
 * @brief Logs a warning-level message.
 * @param ... Message components (variadic)
 *
 * @def LOG_INFO(...)
 * @brief Logs an info-level message.
 * @param ... Message components (variadic)
 *
 * @def LOG_DEBUG(...)
 * @brief Logs a debug-level message.
 * @param ... Message components (variadic)
 *
 * @def LOG_MESSAGE(...)
 * @brief Logs a general message.
 * @param ... Message components (variadic)
 *
 * @note All macros expand to calls to eccsi_sakke::utils::Logger.
 * @note Each log entry automatically includes file and line for traceability.
 */

/**
 * @code
 * // Usage Example:
 * #include "LoggerMacro.h"
 *
 * LOG_INFO("Start parsing");
 * LOG_ERROR("Fatal error, code=", errorCode);
 *
 * #define LOG_MODULE "CRYPTO"
 * #include "LoggerMacro.h"
 * LOG_DEBUG("Encryption started, key=", key);
 * @endcode
 */

// Macro definitions
#define LOG_ERROR(...)   eccsi_sakke::utils::Logger::error(LOG_MODULE, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_WARNING(...) eccsi_sakke::utils::Logger::warning(LOG_MODULE, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_INFO(...)    eccsi_sakke::utils::Logger::info(LOG_MODULE, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_DEBUG(...)   eccsi_sakke::utils::Logger::debug(LOG_MODULE, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_MESSAGE(...) eccsi_sakke::utils::Logger::message(LOG_MODULE, __FILE__, __LINE__, __VA_ARGS__)

/**
 * @remark
 * - Always include this header where logging is needed.
 * - Set LOG_MODULE before including for per-file or per-module labeling.
 * - Macros are type-safe and work with any types supporting operator<<.
 * - Output can be customized globally via Logger::setOutput().
 */
