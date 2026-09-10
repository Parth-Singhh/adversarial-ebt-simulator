#ifndef __ADVERSARIAL_EBT_ATTACKMODEL_H
#define __ADVERSARIAL_EBT_ATTACKMODEL_H

#include <memory>
#include <set>
#include <string>

#include "AttackPolicy.h"

enum class AttackType {
    Honest,
    DropAll,
    ProbabilisticForward,
    Delay,
    SelectiveForward,
    Isolation,
    FloodDuplicates
};

class AttackModel
{
  public:
    static AttackType parseAttackType(const std::string& value);
    static std::string toString(AttackType type);
    static std::unique_ptr<AttackPolicy> createPolicy(AttackType type);
    static std::set<int> parseNodeSet(const std::string& value, int maxNodes);
};

#endif
