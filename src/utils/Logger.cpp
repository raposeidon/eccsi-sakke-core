/*
 * Copyright (C) 2025 raposeidon
 * Licensed under the Apache License, Version 2.0 (the "License");
*/

// This file implements the Logger class for logging messages with different severity levels.

#include "utils/Logger.h"

#ifdef _WIN32
#include <windows.h>
#endif

namespace eccsi_sakke::utils {

Logger::OutputFunc Logger::outputFunc = nullptr;

LogLevel Logger::minLogLevel = LogLevel::LOG_DEBUG;

void Logger::setOutput(OutputFunc func)
{
    outputFunc = func;
}

void Logger::setLevel(LogLevel minLevel) { minLogLevel = minLevel; }
LogLevel Logger::getLevel() { return minLogLevel; }

bool Logger::shouldPrint(LogLevel level)
{
    return static_cast<int>(level) <= static_cast<int>(minLogLevel);
}

// This function is used to output logs to the console with color coding based on the log level
ECCSISAKKE_API void defaultLogOutput(LogLevel level, const std::string &module, const std::string &msg)
{
#ifdef _WIN32
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    WORD origAttr = 0;
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(hConsole, &csbi);
    origAttr = csbi.wAttributes;

    WORD color = origAttr;
    switch (level)
    {
    case LogLevel::LOG_ERROR:
        color = FOREGROUND_RED | FOREGROUND_INTENSITY;
        SetConsoleTextAttribute(hConsole, color);
        std::cerr << "[ERROR][" << module << "] " << msg << std::endl;
        SetConsoleTextAttribute(hConsole, origAttr);
        return;
    case LogLevel::LOG_WARNING:
        color = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY; // Yellow
        SetConsoleTextAttribute(hConsole, color);
        std::cout << "[WARN][" << module << "] " << msg << std::endl;
        SetConsoleTextAttribute(hConsole, origAttr);
        return;
    case LogLevel::LOG_INFO:
        color = FOREGROUND_GREEN | FOREGROUND_INTENSITY;
        SetConsoleTextAttribute(hConsole, color);
        std::cout << "[INFO][" << module << "] " << msg << std::endl;
        SetConsoleTextAttribute(hConsole, origAttr);
        return;
    case LogLevel::LOG_DEBUG:
        color = FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY; // Cyan
        SetConsoleTextAttribute(hConsole, color);
        std::cout << "[DEBUG][" << module << "] " << msg << std::endl;
        SetConsoleTextAttribute(hConsole, origAttr);
        return;
    default:
        SetConsoleTextAttribute(hConsole, origAttr);
        std::cout << "[MSG][" << module << "] " << msg << std::endl;
        return;
    }
#else
    // Non-Windows platforms use standard output without color coding
    switch (level)
    {
    case LogLevel::ERROR:
        std::cerr << "[ERROR][" << module << "] " << msg << std::endl;
        break;
    case LogLevel::WARNING:
        std::cout << "[WARN][" << module << "] " << msg << std::endl;
        break;
    case LogLevel::INFO:
        std::cout << "[INFO][" << module << "] " << msg << std::endl;
        break;
    case LogLevel::DEBUG:
        std::cout << "[DEBUG][" << module << "] " << msg << std::endl;
        break;
    default:
        std::cout << "[MSG][" << module << "] " << msg << std::endl;
        break;
    }
#endif
}

}
