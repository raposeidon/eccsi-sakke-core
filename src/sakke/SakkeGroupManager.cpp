/*
 * Copyright (C) 2025 raposeidon
 * Licensed under the Apache License, Version 2.0 (the "License");
*/

#include "sakke/SakkeGroupManager.h"
#include "sakke/SakkeParameterSet.h"
#include "utils/LoggerMacro.h"
#include <stdexcept>
#include <utility>

namespace eccsi_sakke::sakke {
SakkeGroupManager::~SakkeGroupManager() {
    for (auto& [id, group_and_basePoint] : groupMap_) {
        if (group_and_basePoint.first) EC_GROUP_free(group_and_basePoint.first);
        if (group_and_basePoint.second) EC_POINT_free(group_and_basePoint.second);
    }
}

SakkeGroupManager& SakkeGroupManager::getInstance() {
    static SakkeGroupManager instance;
    return instance;
}

std::pair<EC_GROUP*, EC_POINT*> SakkeGroupManager::getGroup(const int paramSetId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = groupMap_.find(paramSetId);
    if (it != groupMap_.end())
        return it->second;  // Return the group and basePoint if already cached

    const eccsi_sakke::sakke::SakkeParameterSet* param = eccsi_sakke::sakke::get_sakke_param_by_id(paramSetId);
    if (!param) {
        LOG_ERROR("Invalid parameter set ID: ", paramSetId);
        return {nullptr, nullptr};
    }

    auto group_and_basePoint = createGroup(*param);
    groupMap_[paramSetId] = group_and_basePoint;
    return group_and_basePoint;
}

std::pair<EC_GROUP*, EC_POINT*> SakkeGroupManager::createGroup(const eccsi_sakke::sakke::SakkeParameterSet& param) {
    BIGNUM* p = nullptr, *a = nullptr, *b = nullptr;
    BIGNUM* Gx = nullptr, *Gy = nullptr;

    if (!BN_hex2bn(&p, param.p.c_str()) ||
    !BN_dec2bn(&a, param.a.c_str()) ||
    !BN_dec2bn(&b, param.b.c_str()) ||
    !BN_hex2bn(&Gx, param.Px.c_str())||
    !BN_hex2bn(&Gy, param.Py.c_str())) {
        LOG_ERROR("Failed to convert parameter string to BIGNUM");
        return {nullptr, nullptr};
    }

    EC_GROUP* group = EC_GROUP_new_curve_GFp(p, a, b, nullptr);
    if (!group){
        LOG_ERROR("Failed to create EC_GROUP");
        return {nullptr, nullptr};
    }
    
    EC_POINT* P = EC_POINT_new(group);
    if (!P || !EC_POINT_set_affine_coordinates(group, P, Gx, Gy, nullptr)) {
        LOG_ERROR("Failed to create generator point");
        EC_GROUP_free(group);
        EC_POINT_free(P);
        return {nullptr, nullptr};
    }

    BN_free(p); BN_free(a); BN_free(b);
    BN_free(Gx); BN_free(Gy);

    return {group, P};
}

}
