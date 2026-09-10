#include "AttackModel.h"

#include <algorithm>
#include <cctype>
#include <sstream>

AttackType AttackModel::parseAttackType(const std::string& value)
{
    std::string lowered = value;
    std::transform(lowered.begin(), lowered.end(), lowered.begin(), ::tolower);

    if (lowered == "drop" || lowered == "drop_all")
        return AttackType::DropAll;
    if (lowered == "probabilistic" || lowered == "probabilistic_forward")
        return AttackType::ProbabilisticForward;
    if (lowered == "delay" || lowered == "delay_jitter")
        return AttackType::Delay;
    if (lowered == "selective" || lowered == "selective_forward")
        return AttackType::SelectiveForward;
    if (lowered == "isolation")
        return AttackType::Isolation;
    if (lowered == "flood" || lowered == "flood_duplicates")
        return AttackType::FloodDuplicates;
    return AttackType::Honest;
}

std::string AttackModel::toString(AttackType type)
{
    switch (type) {
        case AttackType::DropAll: return "drop_all";
        case AttackType::ProbabilisticForward: return "probabilistic_forward";
        case AttackType::Delay: return "delay";
        case AttackType::SelectiveForward: return "selective_forward";
        case AttackType::Isolation: return "isolation";
        case AttackType::FloodDuplicates: return "flood_duplicates";
        default: return "honest";
    }
}

std::set<int> AttackModel::parseNodeSet(const std::string& value, int maxNodes)
{
    std::set<int> out;
    std::stringstream ss(value);
    std::string token;

    while (std::getline(ss, token, ',')) {
        if (token.empty())
            continue;
        try {
            int id = std::stoi(token);
            if (id >= 0 && id < maxNodes)
                out.insert(id);
        } catch (...) {
        }
    }

    return out;
}
