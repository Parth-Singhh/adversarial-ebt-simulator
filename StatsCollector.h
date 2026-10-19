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
    // ------------------------------------------------------------
    // Broadcast lifecycle / reception
    // ------------------------------------------------------------
    void recordSourceStart(
        const BroadcastId& id,
        int sourceId,
        simtime_t at
    );

    void recordFirstReception(
        const BroadcastId& id,
        int nodeId,
        int parentId,
        int depth,
        simtime_t firstSeen
    );

    void recordParentCommit(
        const BroadcastId& id,
        int nodeId,
        int parentId,
        int depth,
        simtime_t firstSeen
    );

    // ------------------------------------------------------------
    // Traffic / attack events
    // ------------------------------------------------------------
    void recordDuplicate(
        const BroadcastId& id,
        int nodeId
    );

    void recordTransmission(
        const BroadcastId& id,
        int from,
        int to
    );

    void recordDrop(
        const BroadcastId& id,
        int nodeId,
        const char *reason
    );

    void recordMaliciousAction(
        const BroadcastId& id,
        int nodeId,
        const char *attackType
    );

    // ------------------------------------------------------------
    // Topology information
    // ------------------------------------------------------------
    void recordTopology(
        const std::vector<int>& degrees,
        int componentCount,
        int sourceComponentSize,
        int edgeCount
    );

  protected:

    // ============================================================
    // Per-broadcast statistics
    // ============================================================
    struct BroadcastStats
    {
        int sourceId = -1;

        // A node enters this set when it FIRST receives the
        // broadcast, not when it later commits to forwarding.
        std::set<int> reached;

        // Final parent relationship used for the EBT.
        std::unordered_map<int, int> parentByNode;

        // Final depth associated with the committed parent.
        std::unordered_map<int, int> depthByNode;

        // Time of first successful reception.
        std::unordered_map<int, simtime_t> firstSeenByNode;

        // Number of receptions that were duplicates.
        long duplicates = 0;

        // Number of actual transmission events.
        long transmissions = 0;

        // Number of dropped forwarding attempts/events.
        long drops = 0;

        // Number of malicious attack actions.
        long maliciousActions = 0;

        // Number of observations involving forged metadata.
        int forgedMetadataEvents = 0;
    };

    // ============================================================
    // Global / topology state
    // ============================================================
    int numNodes = 0;
    int sourceNode = 0;

    int topologyComponents = 0;
    int topologySourceComponentSize = 0;
    int topologyEdgeCount = 0;

    std::vector<int> topologyDegrees;

    // Statistics indexed by broadcast identifier.
    std::unordered_map<
        BroadcastId,
        BroadcastStats,
        BroadcastIdHash
    > stats;

    // ============================================================
    // Time-series outputs
    // ============================================================
    cOutVector globalCoverageVector;
    cOutVector globalTransmissionVector;
    cOutVector globalDuplicateVector;

    // ============================================================
    // OMNeT++ lifecycle
    // ============================================================
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    // ============================================================
    // Research metric helpers
    // ============================================================
    bool isTreeValid(
        const BroadcastStats& s
    ) const;

    simtime_t completionTime(
        const BroadcastStats& s
    ) const;

    simtime_t timeToCoverage(
        const BroadcastStats& s,
        double ratio
    ) const;

    void recordTimeSeries(
        const BroadcastId& id
    );
};

#endif