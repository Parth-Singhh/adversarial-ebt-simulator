#ifndef __ADVERSARIAL_EBT_EXPERIMENTCONTROLLER_H
#define __ADVERSARIAL_EBT_EXPERIMENTCONTROLLER_H

#include <omnetpp.h>
#include <set>

#include "AttackModel.h"

using namespace omnetpp;

class ExperimentController : public cSimpleModule
{
  protected:
    int numNodes = 0;
    int sourceNode = 0;
    int sessionId = 0;
    int numBroadcasts = 1;

    double maliciousFraction = 0.0;
    int maliciousSeed = 1;

    std::set<int> maliciousNodes;

    AttackType configuredAttack = AttackType::Honest;
    AttackConfig config;

    // Phase 1: use two initialization stages.
    // Stage 0 reads and prepares experiment configuration.
    // Stage 1 applies the configuration to EpidemicNode modules
    // after all nodes have completed their own initialization.
    virtual int numInitStages() const override { return 2; }
    virtual void initialize(int stage) override;

    virtual void handleMessage(cMessage *msg) override;

    std::set<int> parseFixedMaliciousNodes(const char *spec) const;
    std::set<int> sampleMaliciousNodes() const;
};

#endif