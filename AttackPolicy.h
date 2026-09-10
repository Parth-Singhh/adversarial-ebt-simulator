#ifndef __ADVERSARIAL_EBT_ATTACKPOLICY_H
#define __ADVERSARIAL_EBT_ATTACKPOLICY_H

#include <omnetpp.h>
#include <string>

#include "AttackConfig.h"

enum AttackFlag {
    ATTACK_FLAG_DROP = 1 << 0,
    ATTACK_FLAG_DELAY = 1 << 1,
    ATTACK_FLAG_SELECTIVE = 1 << 2,
    ATTACK_FLAG_ISOLATION = 1 << 3,
    ATTACK_FLAG_SPOOF = 1 << 4,
    ATTACK_FLAG_EQUIVOCATION = 1 << 5
};

struct AttackContext {
    int nodeId = -1;
    int neighborId = -1;
    int sourceId = -1;
    int originId = -1;
    int hopCount = 0;
    int numNodes = 0;
    int broadcastSeq = 0;
    AttackConfig config;
};

struct AttackOutcome {
    bool drop = false;
    int duplicateBurst = 0;
    simtime_t extraDelay = SIMTIME_ZERO;
    bool spoofMetadata = false;
    bool equivocate = false;
    int payloadVariantId = 0;
    int attackFlags = 0;
    std::string reason = "forward";
};

class AttackPolicy
{
  public:
    virtual ~AttackPolicy() = default;
    virtual AttackOutcome decide(const AttackContext& ctx) const = 0;
};

#endif
