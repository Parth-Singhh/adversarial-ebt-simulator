#include "AttackModel.h"

#include <algorithm>
#include <cctype>

AttackType AttackModel::parseAttackType(const std::string& value)
{
    std::string lowered = value;
    std::transform(lowered.begin(), lowered.end(), lowered.begin(), ::tolower);

    if (lowered == "drop")
        return AttackType::Drop;
    if (lowered == "selective" || lowered == "selective_forward")
        return AttackType::SelectiveForward;
    if (lowered == "delay" || lowered == "delay_jitter")
        return AttackType::DelayJitter;
    if (lowered == "flood" || lowered == "flood_duplicates")
        return AttackType::FloodDuplicates;
    if (lowered == "equivocation")
        return AttackType::Equivocation;
    if (lowered == "spoof" || lowered == "spoof_metadata")
        return AttackType::SpoofMetadata;
    return AttackType::Honest;
}

std::string AttackModel::toString(AttackType type)
{
    switch (type) {
        case AttackType::Drop: return "drop";
        case AttackType::SelectiveForward: return "selective_forward";
        case AttackType::DelayJitter: return "delay_jitter";
        case AttackType::FloodDuplicates: return "flood_duplicates";
        case AttackType::Equivocation: return "equivocation";
        case AttackType::SpoofMetadata: return "spoof_metadata";
        default: return "honest";
    }
}

AttackDecision AttackModel::decide(AttackType type, int nodeId, int neighborId,
                                   simtime_t jitterMax)
{
    AttackDecision decision;

    switch (type) {
        case AttackType::Drop:
            decision.drop = true;
            break;
        case AttackType::SelectiveForward:
            decision.drop = ((nodeId + neighborId) % 2 == 1);
            break;
        case AttackType::DelayJitter:
            decision.extraDelay = uniform(SIMTIME_ZERO, jitterMax);
            break;
        case AttackType::FloodDuplicates:
            decision.duplicateBurst = 2;
            break;
        case AttackType::Equivocation:
            decision.equivocate = true;
            break;
        case AttackType::SpoofMetadata:
            decision.spoofMetadata = true;
            break;
        case AttackType::Honest:
        default:
            break;
    }

    return decision;
}
