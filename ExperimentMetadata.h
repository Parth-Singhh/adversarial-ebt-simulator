#ifndef __ADVERSARIAL_EBT_EXPERIMENTMETADATA_H
#define __ADVERSARIAL_EBT_EXPERIMENTMETADATA_H

#include <set>
#include <string>

#include "AttackModel.h"

struct ExperimentMetadata {
    int runId = 0;
    int sessionId = 0;
    int sourceNode = 0;
    int maliciousSeed = 0;
    double maliciousFraction = 0.0;
    AttackType attackType = AttackType::Honest;
    std::set<int> maliciousNodes;
    std::set<int> isolatedPeers;
};

#endif
