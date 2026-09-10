#ifndef __ADVERSARIAL_EBT_ATTACKCONFIG_H
#define __ADVERSARIAL_EBT_ATTACKCONFIG_H

#include <omnetpp.h>
#include <set>
#include <string>

struct AttackConfig {
    double forwardProb = 1.0;
    double selectiveTargetFraction = 0.5;
    simtime_t maxExtraDelay = SIMTIME_ZERO;
    std::string isolationMode = "none";
    std::set<int> isolatedPeers;
    bool enableSpoofMetadata = false;
    bool enableEquivocation = false;
};

#endif
