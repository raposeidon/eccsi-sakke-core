/*
 * Copyright (C) 2025 raposeidon
 * Licensed under the Apache License, Version 2.0 (the "License");
*/

// This file implements the Logger class for logging messages with different severity levels.

#include "utils/Logger.h"
#include <mutex>

#ifdef _WIN32
#include <windows.h>
#elif defined(__ANDROID__)
#include <android/log.h>
#endif

namespace eccsi_sakke::utils {

Logger::OutputFunc Logger::outputFunc = nullptr;

std::atomic<LogLevel> Logger::minLogLevel{LogLevel::LOG_DEBUG};

void Logger::setOutput(OutputFunc func)
{
    std::unique_lock<std::shared_mutex> lock(outputMutex());
    outputFunc = func;
}

void Logger::setLevel(LogLevel minLevel) { minLogLevel.store(minLevel, std::memory_order_relaxed); }
LogLevel Logger::getLevel() { return minLogLevel.load(std::memory_order_relaxed); }

bool Logger::shouldPrint(LogLevel level)
{
    return static_cast<int>(level) <= static_cast<int>(minLogLevel.load(std::memory_order_relaxed));
}

static std::string sanitizeLogMessage(const std::string &msg)
{
    std::string out;
    out.reserve(msg.size());
    for (unsigned char c : msg)
    {
        if (c == '\n' || c == '\r' || c == '\t')
            out += c;
        else if (c < 0x20 || c == 0x7F)
            out += '?';
        else
            out += static_cast<char>(c);
    }
    return out;
}

// This function is used to output logs to the console with color coding based on the log level
ECCSISAKKE_API void defaultLogOutput(LogLevel level, const std::string &module, const std::string &msg)
{
    const std::string safeMsg = sanitizeLogMessage(msg);
#ifdef _WIN32
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    WORD origAttr = 0;
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (!GetConsoleScreenBufferInfo(hConsole, &csbi)) {
        origAttr = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
    } else {
        origAttr = csbi.wAttributes;
    }

    WORD color = origAttr;
    switch (level)
    {
    case LogLevel::LOG_ERROR:
        color = FOREGROUND_RED | FOREGROUND_INTENSITY;
        SetConsoleTextAttribute(hConsole, color);
        std::cerr << "[ERROR][" << module << "] " << safeMsg << std::endl;
        SetConsoleTextAttribute(hConsole, origAttr);
        return;
    case LogLevel::LOG_WARNING:
        color = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY; // Yellow
        SetConsoleTextAttribute(hConsole, color);
        std::cout << "[WARN][" << module << "] " << safeMsg << std::endl;
        SetConsoleTextAttribute(hConsole, origAttr);
        return;
    case LogLevel::LOG_INFO:
        color = FOREGROUND_GREEN | FOREGROUND_INTENSITY;
        SetConsoleTextAttribute(hConsole, color);
        std::cout << "[INFO][" << module << "] " << safeMsg << std::endl;
        SetConsoleTextAttribute(hConsole, origAttr);
        return;
    case LogLevel::LOG_DEBUG:
        color = FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY; // Cyan
        SetConsoleTextAttribute(hConsole, color);
        std::cout << "[DEBUG][" << module << "] " << safeMsg << std::endl;
        SetConsoleTextAttribute(hConsole, origAttr);
        return;
    default:
        SetConsoleTextAttribute(hConsole, origAttr);
        std::cout << "[MSG][" << module << "] " << safeMsg << std::endl;
        return;
    }
#elif defined(__ANDROID__)
    // Android: output to logcat via __android_log_print
    const std::string tag = "ECCSI-SAKKE/" + module;
    switch (level)
    {
    case LogLevel::LOG_ERROR:
        __android_log_print(ANDROID_LOG_ERROR, tag.c_str(), "%s", safeMsg.c_str());
        break;
    case LogLevel::LOG_WARNING:
        __android_log_print(ANDROID_LOG_WARN, tag.c_str(), "%s", safeMsg.c_str());
        break;
    case LogLevel::LOG_INFO:
        __android_log_print(ANDROID_LOG_INFO, tag.c_str(), "%s", safeMsg.c_str());
        break;
    case LogLevel::LOG_DEBUG:
        __android_log_print(ANDROID_LOG_DEBUG, tag.c_str(), "%s", safeMsg.c_str());
        break;
    default:
        __android_log_print(ANDROID_LOG_VERBOSE, tag.c_str(), "%s", safeMsg.c_str());
        break;
    }
#else
    // Other platforms: standard output without color coding
    switch (level)
    {
    case LogLevel::LOG_ERROR:
        std::cerr << "[ERROR][" << module << "] " << safeMsg << std::endl;
        break;
    case LogLevel::LOG_WARNING:
        std::cout << "[WARN][" << module << "] " << safeMsg << std::endl;
        break;
    case LogLevel::LOG_INFO:
        std::cout << "[INFO][" << module << "] " << safeMsg << std::endl;
        break;
    case LogLevel::LOG_DEBUG:
        std::cout << "[DEBUG][" << module << "] " << safeMsg << std::endl;
        break;
    default:
        std::cout << "[MSG][" << module << "] " << safeMsg << std::endl;
        break;
    }
#endif
}

}
