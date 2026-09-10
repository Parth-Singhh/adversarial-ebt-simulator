#include "StatsCollector.h"

#include <algorithm>
#include <cmath>
#include <functional>

Define_Module(StatsCollector);

void StatsCollector::initialize()
{
    numNodes = par("numNodes");
    sourceNode = par("sourceNode");

    globalCoverageVector.setName("globalCoverage");
    globalTransmissionVector.setName("globalTransmissions");
    globalDuplicateVector.setName("globalDuplicates");
}

void StatsCollector::handleMessage(cMessage *msg)
{
    delete msg;
}

void StatsCollector::recordTopology(const std::vector<int>& degrees, int componentCount,
                                    int sourceComponentSize, int edgeCount)
{
    topologyDegrees = degrees;
    topologyComponents = componentCount;
    topologySourceComponentSize = sourceComponentSize;
    topologyEdgeCount = edgeCount;
}

void StatsCollector::recordSourceStart(const BroadcastId& id, int sourceId, simtime_t at)
{
    auto& s = stats[id];
    s.sourceId = sourceId;
    s.reached.insert(sourceId);
    s.parentByNode[sourceId] = -1;
    s.depthByNode[sourceId] = 0;
    s.firstSeenByNode[sourceId] = at;
    recordTimeSeries(id);
}

void StatsCollector::recordParentCommit(const BroadcastId& id, int nodeId, int parentId,
                                        int depth, simtime_t firstSeen)
{
    auto& s = stats[id];
    s.reached.insert(nodeId);
    s.parentByNode[nodeId] = parentId;
    s.depthByNode[nodeId] = depth;
    s.firstSeenByNode[nodeId] = firstSeen;
    if (parentId < 0 || parentId >= numNodes)
        s.forgedMetadataEvents++;
    recordTimeSeries(id);
}

void StatsCollector::recordDuplicate(const BroadcastId& id, int)
{
    auto& s = stats[id];
    s.duplicates++;
    recordTimeSeries(id);
}

void StatsCollector::recordTransmission(const BroadcastId& id, int, int)
{
    auto& s = stats[id];
    s.transmissions++;
    recordTimeSeries(id);
}

void StatsCollector::recordDrop(const BroadcastId& id, int, const char *)
{
    auto& s = stats[id];
    s.drops++;
    recordTimeSeries(id);
}

void StatsCollector::recordMaliciousAction(const BroadcastId& id, int, const char *attackType)
{
    auto& s = stats[id];
    s.maliciousActions++;
    if (std::string(attackType) == "spoof_metadata")
        s.forgedMetadataEvents++;
    recordTimeSeries(id);
}

void StatsCollector::recordTimeSeries(const BroadcastId& id)
{
    const auto& s = stats[id];
    double denominator = std::max(1, numNodes);
    globalCoverageVector.record((double)s.reached.size() / denominator);
    globalTransmissionVector.record((double)s.transmissions);
    globalDuplicateVector.record((double)s.duplicates);
}

bool StatsCollector::isTreeValid(const BroadcastStats& s) const
{
    if (s.reached.empty())
        return false;

    int edgeCount = 0;
    for (const auto& p : s.parentByNode) {
        if (p.second >= 0)
            edgeCount++;
    }
    if (edgeCount != (int)s.reached.size() - 1)
        return false;

    std::set<int> visiting;
    std::set<int> visited;

    std::function<bool(int)> dfs = [&](int node) {
        if (visiting.count(node))
            return false;
        if (visited.count(node))
            return true;

        visiting.insert(node);
        auto it = s.parentByNode.find(node);
        if (it != s.parentByNode.end() && it->second >= 0) {
            if (!s.reached.count(it->second))
                return false;
            if (!dfs(it->second))
                return false;
        }
        visiting.erase(node);
        visited.insert(node);
        return true;
    };

    for (int node : s.reached) {
        if (!dfs(node))
            return false;
    }

    return true;
}

simtime_t StatsCollector::completionTime(const BroadcastStats& s) const
{
    simtime_t maxSeen = SIMTIME_ZERO;
    for (const auto& item : s.firstSeenByNode)
        maxSeen = std::max(maxSeen, item.second);
    return maxSeen;
}

simtime_t StatsCollector::timeToCoverage(const BroadcastStats& s, double ratio) const
{
    int targetBase = topologySourceComponentSize > 0 ? topologySourceComponentSize : numNodes;
    int target = std::max(1, (int)std::ceil(ratio * targetBase));

    std::vector<simtime_t> arrivals;
    arrivals.reserve(s.firstSeenByNode.size());
    for (const auto& kv : s.firstSeenByNode)
        arrivals.push_back(kv.second);

    if ((int)arrivals.size() < target)
        return -1;

    std::sort(arrivals.begin(), arrivals.end());
    return arrivals[target - 1];
}

void StatsCollector::finish()
{
    recordScalar("topology.components", topologyComponents);
    recordScalar("topology.sourceComponentSize", topologySourceComponentSize);
    recordScalar("topology.edgeCount", topologyEdgeCount);

    if (!topologyDegrees.empty()) {
        long sum = 0;
        for (int d : topologyDegrees)
            sum += d;
        recordScalar("topology.avgDegree", (double)sum / topologyDegrees.size());
    }

    for (const auto& kv : stats) {
        const BroadcastId& id = kv.first;
        const BroadcastStats& s = kv.second;
        std::string prefix = "broadcast." + id.toString() + ".";

        int edges = 0;
        int maxDepth = 0;
        for (const auto& p : s.parentByNode)
            if (p.second >= 0)
                edges++;
        for (const auto& d : s.depthByNode)
            maxDepth = std::max(maxDepth, d.second);

        recordScalar((prefix + "reached").c_str(), (double)s.reached.size());
        recordScalar((prefix + "coverageRatio").c_str(), (double)s.reached.size() / std::max(1, numNodes));
        recordScalar((prefix + "duplicates").c_str(), s.duplicates);
        recordScalar((prefix + "transmissions").c_str(), s.transmissions);
        recordScalar((prefix + "drops").c_str(), s.drops);
        recordScalar((prefix + "maliciousActions").c_str(), s.maliciousActions);
        recordScalar((prefix + "forgedMetadataEvents").c_str(), s.forgedMetadataEvents);
        recordScalar((prefix + "treeEdges").c_str(), edges);
        recordScalar((prefix + "maxDepth").c_str(), maxDepth);
        recordScalar((prefix + "treeValid").c_str(), isTreeValid(s) ? 1 : 0);
        recordScalar((prefix + "completionTime").c_str(), completionTime(s));

        simtime_t t90 = timeToCoverage(s, 0.9);
        if (t90 >= SIMTIME_ZERO)
            recordScalar((prefix + "timeTo90pctReachable").c_str(), t90);
    }
}
