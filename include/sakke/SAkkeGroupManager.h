/*
 * Copyright (C) 2025 raposeidon
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#pragma once

#include <openssl/ec.h>
#include <map>
#include <mutex>
#include <stdexcept>
#include "sakke/SakkeParameterSet.h"  // Definition of SakkeParameterSet required

namespace eccsi_sakke::sakke {

/**
 * @class SakkeGroupManager
 * @brief Singleton class for managing and caching EC_GROUP and EC_POINT instances for SAKKE parameter sets.
 *
 * - Ensures thread-safe access and reuse of expensive OpenSSL group/point objects.
 * - Prevents redundant allocation for each SAKKE operation.
 */
class SakkeGroupManager {
public:
    /**
     * @brief Returns the singleton instance of SakkeGroupManager.
     * @return Reference to the singleton instance.
     */
    static SakkeGroupManager& getInstance();

    /**
     * @brief Retrieves the EC_GROUP and generator EC_POINT for the specified parameter set.
     *        If not cached, creates and stores them internally.
     * @param paramSetId  SAKKE parameter set identifier.
     * @return std::pair containing (EC_GROUP*, EC_POINT*).
     * @throws std::runtime_error if parameter set is invalid or group creation fails.
     * @note Returned pointers are managed internally; do not free them manually.
     */
    std::pair<EC_GROUP*, EC_POINT*> getGroup(const int paramSetId);

private:
    /**
     * @brief Constructor. Private to enforce singleton pattern.
     */
    SakkeGroupManager() = default;

    /**
     * @brief Destructor. Frees all cached EC_GROUP and EC_POINT instances.
     */
    ~SakkeGroupManager();

    /**
     * @brief Creates a new EC_GROUP and base point EC_POINT for the given parameter set.
     * @param param  SAKKE parameter set definition.
     * @return std::pair containing (EC_GROUP*, EC_POINT*).
     * @throws std::runtime_error on creation failure.
     */
    std::pair<EC_GROUP*, EC_POINT*> createGroup(const SakkeParameterSet& param);

    /// Internal cache: paramSetId -> (EC_GROUP*, EC_POINT*)
    std::map<int, std::pair<EC_GROUP*, EC_POINT*>> groupMap_;

    /// Mutex for thread-safe access to the group cache.
    std::mutex mutex_;
};

}
