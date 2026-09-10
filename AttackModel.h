#ifndef __ADVERSARIAL_EBT_ATTACKMODEL_H
#define __ADVERSARIAL_EBT_ATTACKMODEL_H

#include <omnetpp.h>
#include <string>

enum class AttackType {
    Honest,
    Drop,
    SelectiveForward,
    DelayJitter,
    FloodDuplicates,
    Equivocation,
    SpoofMetadata
};

struct AttackDecision {
    bool drop = false;
    int duplicateBurst = 0;
    simtime_t extraDelay = SIMTIME_ZERO;
    bool equivocate = false;
    bool spoofMetadata = false;
};

class AttackModel
{
  public:
    static AttackType parseAttackType(const std::string& value);
    static std::string toString(AttackType type);
    static AttackDecision decide(AttackType type, int nodeId, int neighborId,
                                 simtime_t jitterMax);
};

#endif
