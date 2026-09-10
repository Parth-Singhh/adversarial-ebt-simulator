#include "ExperimentController.h"

#include <algorithm>
#include <cmath>
#include <numeric>
#include <random>
#include <sstream>

#include "EpidemicNode.h"

Define_Module(ExperimentController);

enum {
    KIND_TRIGGER = 1
};

void ExperimentController::initialize()
{
    numNodes = par("numNodes");
    sourceNode = par("sourceNode");
    sessionId = par("sessionId");
    numBroadcasts = par("numBroadcasts");
    maliciousFraction = par("maliciousFraction");
    maliciousSeed = par("maliciousSeed");
    configuredAttack = AttackModel::parseAttackType(par("attackType").stdstringValue());

    const std::string fixed = par("fixedMaliciousNodes").stdstringValue();
    maliciousNodes = fixed.empty() ? sampleMaliciousNodes() : parseFixedMaliciousNodes(fixed.c_str());

    for (int i = 0; i < numNodes; ++i) {
        auto *node = check_and_cast<EpidemicNode *>(getParentModule()->getSubmodule("node", i));
        bool isMalicious = maliciousNodes.count(i) > 0;
        node->configureRole(isMalicious, isMalicious ? configuredAttack : AttackType::Honest);
    }

    simtime_t firstAt = par("firstBroadcastAt");
    simtime_t interval = par("broadcastInterval");

    for (int seq = 0; seq < numBroadcasts; ++seq) {
        auto *trigger = new cMessage("triggerBroadcast", KIND_TRIGGER);
        trigger->addPar("seq") = seq;
        scheduleAt(firstAt + seq * interval, trigger);
    }
}

std::set<int> ExperimentController::parseFixedMaliciousNodes(const char *spec) const
{
    std::set<int> result;
    std::stringstream ss(spec);
    std::string token;

    while (std::getline(ss, token, ',')) {
        if (token.empty())
            continue;
        int id = std::stoi(token);
        if (id >= 0 && id < numNodes)
            result.insert(id);
    }

    return result;
}

std::set<int> ExperimentController::sampleMaliciousNodes() const
{
    std::set<int> result;
    int wanted = std::max(0, std::min(numNodes, (int)std::round(maliciousFraction * numNodes)));

    std::vector<int> ids(numNodes);
    std::iota(ids.begin(), ids.end(), 0);
    std::mt19937 rng(maliciousSeed);
    std::shuffle(ids.begin(), ids.end(), rng);

    for (int i = 0; i < wanted; ++i)
        result.insert(ids[i]);

    if (result.count(sourceNode)) {
        result.erase(sourceNode);
        for (int id : ids) {
            if (id != sourceNode && !result.count(id)) {
                result.insert(id);
                break;
            }
        }
    }

    return result;
}

void ExperimentController::handleMessage(cMessage *msg)
{
    if (msg->getKind() == KIND_TRIGGER) {
        int seq = msg->par("seq");
        auto *source = check_and_cast<EpidemicNode *>(getParentModule()->getSubmodule("node", sourceNode));
        source->triggerBroadcast(sessionId, seq);
    }

    delete msg;
}
