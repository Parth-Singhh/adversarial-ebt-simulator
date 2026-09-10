#ifndef __EPIDEMICBROADCASTTREE_EPIDEMICNODE_H
#define __EPIDEMICBROADCASTTREE_EPIDEMICNODE_H

#include <omnetpp.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace omnetpp;

class EpidemicNode : public cSimpleModule
{
  protected:
    int nodeId = -1;
    int numNodes = 0;
    bool source = false;

    int fanout = 3;
    simtime_t forwardDelay;
    simtime_t gossipDelay;

    int nextMessageId = 0;

    // messageId -> parent node ID.
    // The source has parent = -1.
    std::unordered_map<int, int> parent;

    // messageId -> hop/depth of this node.
    std::unordered_map<int, int> depth;

    // messageId -> set of children in the epidemic tree.
    std::unordered_map<int, std::unordered_set<int>> children;

    // Number of duplicate receptions per message.
    std::unordered_map<int, long> duplicateReception;

    cMessage *startMessage = nullptr;

    // Statistics.
    cLongHistogram numTreeChildrenHist;
    cLongHistogram depthHist;

    cOutVector coverageVector;
    cOutVector transmissionsVector;
    cOutVector duplicatesVector;
    cOutVector treeEdgesVector;

    long totalTransmissions = 0;
    long totalDuplicates = 0;
    long totalFirstReceptions = 0;

    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    void startBroadcast();
    void receiveEpidemicMessage(EpidemicMessage *msg);

    void scheduleForward(EpidemicMessage *msg);
    void forwardMessage(int messageId, int originId, int hopCount,
                        simtime_t creationTime);

    std::vector<int> selectRandomNeighbors(int excludeGateIndex, int desiredFanout);

    bool hasSeen(int messageId) const;
    int gateToNode(int gateIndex) const;

    void recordTreeEdge(int child, int p);
};

#endif
