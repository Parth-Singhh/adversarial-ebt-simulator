#ifndef __EPIDEMICBROADCASTTREE_EPIDEMICNODE_H
#define __EPIDEMICBROADCASTTREE_EPIDEMICNODE_H

#include <omnetpp.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "AttackModel.h"
#include "BroadcastId.h"

using namespace omnetpp;

class StatsCollector;

class EpidemicNode : public cSimpleModule
{
  public:
    void configureRole(bool maliciousRole, AttackType type);
    void triggerBroadcast(int sessionId, int sequenceNo);

  protected:
    struct BroadcastState {
        bool seen = false;
        bool forwardScheduled = false;
        bool forwarded = false;
        bool terminal = false;

        int parentId = -1;
        int depth = 0;

        simtime_t firstSeenTime = SIMTIME_ZERO;

        std::unordered_set<int> forwardedPeers;
        long duplicateCount = 0;
        std::vector<int> acceptedParents;
        std::vector<int> rejectedParents;
    };

    int nodeId = -1;
    int numNodes = 0;

    int fanout = 3;
    int maxMessages = 1000;
    simtime_t forwardDelay;
    simtime_t gossipDelay;
    simtime_t maliciousJitterMax;

    bool malicious = false;
    AttackType attackType = AttackType::Honest;

    int totalAcceptedBroadcasts = 0;

    std::unordered_map<BroadcastId, BroadcastState, BroadcastIdHash> stateByBroadcast;
    std::unordered_map<int, int> gateByNeighborId;

    simsignal_t firstReceptionSignal;
    simsignal_t duplicateSignal;
    simsignal_t transmitSignal;
    simsignal_t dropSignal;
    simsignal_t maliciousSignal;

    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;

    BroadcastId keyFromPacket(const class EpidemicMessage *msg) const;
    void refreshNeighborCache();
    std::vector<int> selectRandomNeighbors(int excludeNeighborId, int desiredFanout);

    void onReceive(class EpidemicMessage *msg);
    void processForwardEvent(const BroadcastId& key);
    void sendToNeighbor(const BroadcastId& key, BroadcastState& state, int neighborId,
                        int senderId, int originId, int attackTag, simtime_t extraDelay);

    StatsCollector *collector() const;
};

#endif
