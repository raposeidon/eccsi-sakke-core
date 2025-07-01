/*
 * Copyright (C) 2025 raposeidon
 * Licensed under the Apache License, Version 2.0 (the "License");
*/

/**
 * @file eccsisakke_export.h
 * @brief DLL/shared library symbol export/import macro for cross-platform builds.
 *
 * - Defines the ECCSISAKKE_API macro for exporting or importing public symbols.
 * - On Windows, resolves to __declspec(dllexport) or __declspec(dllimport) as needed.
 * - On Linux/Unix, expands to nothing (default visibility).
 * - For static builds, macro is empty.
 *
 * @note
 *   - Define ECCSISAKKE_EXPORTS when building the DLL/shared library.
 *   - Define ECCSISAKKE_STATIC for static builds (no symbol attributes).
 *   - Include this header in all public headers that declare exported API.
 *
 * @example
 *   class ECCSISAKKE_API MyExportedClass { ... };
 *   ECCSISAKKE_API void exportedFunction();
 */

#pragma once

#if defined(_WIN32)
#if defined(ECCSISAKKE_STATIC)
#define ECCSISAKKE_API
#elif defined(ECCSISAKKE_EXPORTS)
#define ECCSISAKKE_API __declspec(dllexport)
#else
#define ECCSISAKKE_API __declspec(dllimport)
#endif
#else
#define ECCSISAKKE_API
#endif