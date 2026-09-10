#ifndef __ADVERSARIAL_EBT_STATSCOLLECTOR_H
#define __ADVERSARIAL_EBT_STATSCOLLECTOR_H

#include <omnetpp.h>
#include <map>
#include <set>
#include <unordered_map>
#include <vector>

#include "BroadcastId.h"

using namespace omnetpp;

class StatsCollector : public cSimpleModule
{
  public:
    void recordSourceStart(const BroadcastId& id, int sourceId, simtime_t at);
    void recordParentCommit(const BroadcastId& id, int nodeId, int parentId, int depth,
                            simtime_t firstSeen);
    void recordDuplicate(const BroadcastId& id, int nodeId);
    void recordTransmission(const BroadcastId& id, int from, int to);
    void recordDrop(const BroadcastId& id, int nodeId, const char *reason);
    void recordMaliciousAction(const BroadcastId& id, int nodeId, const char *attackType);
    void recordTopology(const std::vector<int>& degrees, int componentCount,
                        int sourceComponentSize, int edgeCount);

  protected:
    struct BroadcastStats {
        int sourceId = -1;
        std::set<int> reached;
        std::unordered_map<int, int> parentByNode;
        std::unordered_map<int, int> depthByNode;
        std::unordered_map<int, simtime_t> firstSeenByNode;
        long duplicates = 0;
        long transmissions = 0;
        long drops = 0;
        long maliciousActions = 0;
        int forgedMetadataEvents = 0;
    };

    int numNodes = 0;
    int sourceNode = 0;
    int topologyComponents = 0;
    int topologySourceComponentSize = 0;
    int topologyEdgeCount = 0;
    std::vector<int> topologyDegrees;

    std::unordered_map<BroadcastId, BroadcastStats, BroadcastIdHash> stats;

    cOutVector globalCoverageVector;
    cOutVector globalTransmissionVector;
    cOutVector globalDuplicateVector;

    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    bool isTreeValid(const BroadcastStats& s) const;
    simtime_t completionTime(const BroadcastStats& s) const;
    simtime_t timeToCoverage(const BroadcastStats& s, double ratio) const;
    void recordTimeSeries(const BroadcastId& id);
};

#endif
