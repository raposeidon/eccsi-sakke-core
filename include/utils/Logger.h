/*
 * Copyright (C) 2025 raposeidon
 * Licensed under the Apache License, Version 2.0 (the "License");
*/

#pragma once
#include "eccsisakke_export.h"
#include <string>
#include <sstream>
#include <functional>
#include <iostream>

namespace eccsi_sakke::utils {

/**
 * @enum LogLevel
 * @brief Severity levels for logging output.
 */    
enum class LogLevel : int
{
    LOG_ERROR = 1,
    LOG_WARNING = 2,
    LOG_INFO = 3,
    LOG_DEBUG = 4,
    LOG_MESSAGE = 5
};

/**
 * @brief Default logging output function. Writes to stderr.
 * @param level    LogLevel
 * @param module   Logical module/component name
 * @param message  Log message (already formatted)
 */
ECCSISAKKE_API void defaultLogOutput(LogLevel, const std::string &, const std::string &);

/**
 * @class Logger
 * @brief Centralized static logger for SAKKE/ECCSI modules.
 *
 * - Allows setting minimum log level at runtime.
 * - Log output can be redirected by setting a custom output function.
 * - Thread-safe for normal usage.
 */
class ECCSISAKKE_API Logger
{
public:
    /// Log output handler type.
    using OutputFunc = std::function<void(LogLevel, const std::string &, const std::string &)>;

    /**
     * @brief Sets the log output function. Thread-safe.
     * @param func User-provided callback for log output.
     */

    static void setOutput(OutputFunc func);

    /**
     * @brief Sets the minimum log level to output.
     * @param minLevel Only logs of this level or higher will be output.
     */    
    static void setLevel(LogLevel minLevel);

    /**
     * @brief Gets the currently set minimum log level.
     * @return LogLevel
     */    
    static LogLevel getLevel();

    /**
     * @brief Checks whether a log of this level should be output.
     * @param level LogLevel to test
     * @return true if should print, false otherwise
     * @note Used internally.
     */
    static bool shouldPrint(LogLevel level);

    /**
     * @brief Logs a message at the specified level, including file and line info.
     * @param level   LogLevel
     * @param module  Module or component name
     * @param file    Source filename
     * @param line    Source line number
     * @param args    Variadic arguments (stringifiable)
     * @return Formatted log message (empty string if not output)
     *
     * @note Internal helper; prefer the level-specific wrappers (error/info/debug/etc).
     */
    template <typename... Args>
    static std::string log(LogLevel level, const std::string &module, const std::string &file, int line, Args &&...args)
    {
        if (!shouldPrint(level))
            return ""; // 레벨이 낮으면 출력하지 않음
        std::ostringstream oss;
        oss << "(" << shortFileName(file) << ":" << line << ") ";
        (oss << ... << args);
        std::string msg = oss.str();
        if (outputFunc)
            outputFunc(level, module, msg);
        return msg;
    }

    /// Logs at error level.
    template <typename... Args>
    static std::string error(const std::string &module, const std::string &file, int line, Args &&...args)
    {
        return log(LogLevel::LOG_ERROR, module, file, line, std::forward<Args>(args)...);
    }
    /// Logs at info level.
    template <typename... Args>
    static std::string info(const std::string &module, const std::string &file, int line, Args &&...args)
    {
        return log(LogLevel::LOG_INFO, module, file, line, std::forward<Args>(args)...);
    }
    /// Logs at debug level.
    template <typename... Args>
    static std::string debug(const std::string &module, const std::string &file, int line, Args &&...args)
    {
        return log(LogLevel::LOG_DEBUG, module, file, line, std::forward<Args>(args)...);
    }
    /// Logs at message level.
    template <typename... Args>
    static std::string message(const std::string &module, const std::string &file, int line, Args &&...args)
    {
        return log(LogLevel::LOG_MESSAGE, module, file, line, std::forward<Args>(args)...);
    }
    /// Logs at warning level.
    template <typename... Args>
    static std::string warning(const std::string &module, const std::string &file, int line, Args &&...args)
    {
        return log(LogLevel::LOG_WARNING, module, file, line, std::forward<Args>(args)...);
    }

private:
    /// Current minimum log level
    static LogLevel minLogLevel;
    /// Active log output function
    static OutputFunc outputFunc;

    /**
     * @brief Extracts the short filename (no path) from a full file path.
     * @param file Full file path string
     * @return Short filename
     */    
    static std::string shortFileName(const std::string &file)
    {
        size_t pos = file.find_last_of("/\\");
        return (pos == std::string::npos) ? file : file.substr(pos + 1);
    }
};

}
