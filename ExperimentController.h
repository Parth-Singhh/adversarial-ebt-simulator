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

    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;

    std::set<int> parseFixedMaliciousNodes(const char *spec) const;
    std::set<int> sampleMaliciousNodes() const;
};

#endif
