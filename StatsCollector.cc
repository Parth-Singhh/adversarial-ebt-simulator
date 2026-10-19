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

void StatsCollector::recordTopology(
    const std::vector<int>& degrees,
    int componentCount,
    int sourceComponentSize,
    int edgeCount)
{
    topologyDegrees = degrees;
    topologyComponents = componentCount;
    topologySourceComponentSize = sourceComponentSize;
    topologyEdgeCount = edgeCount;
}

void StatsCollector::recordSourceStart(
    const BroadcastId& id,
    int sourceId,
    simtime_t at)
{
    auto& s = stats[id];

    s.sourceId = sourceId;

    // The source has successfully received/started the broadcast
    // at the beginning of the dissemination process.
    s.reached.insert(sourceId);

    // The source is the root of the EBT and therefore has no parent.
    s.parentByNode[sourceId] = -1;
    s.depthByNode[sourceId] = 0;
    s.firstSeenByNode[sourceId] = at;

    recordTimeSeries(id);
}

void StatsCollector::recordFirstReception(
    const BroadcastId& id,
    int nodeId,
    int parentId,
    int depth,
    simtime_t firstSeen)
{
    auto& s = stats[id];

    /*
     * IMPORTANT:
     *
     * Coverage is defined by successful first reception.
     * A node does NOT need to have committed to forwarding yet
     * in order to count as reached.
     */
    s.reached.insert(nodeId);

    s.firstSeenByNode[nodeId] = firstSeen;

    /*
     * We intentionally do NOT write parentByNode/depthByNode here.
     *
     * Those represent the committed EBT structure, which is recorded
     * later by recordParentCommit().
     */
    (void)parentId;
    (void)depth;

    recordTimeSeries(id);
}

void StatsCollector::recordParentCommit(
    const BroadcastId& id,
    int nodeId,
    int parentId,
    int depth,
    simtime_t firstSeen)
{
    auto& s = stats[id];

    /*
     * The node should already have been counted as reached by
     * recordFirstReception(). Keeping this insert is harmless and
     * makes the collector robust if the source/commit path is used
     * independently.
     */
    s.reached.insert(nodeId);

    s.parentByNode[nodeId] = parentId;
    s.depthByNode[nodeId] = depth;

    /*
     * Keep the original first-seen time when available.
     * If it does not exist yet, use the supplied value.
     */
    if (s.firstSeenByNode.find(nodeId) ==
        s.firstSeenByNode.end()) {
        s.firstSeenByNode[nodeId] = firstSeen;
    }

    /*
     * A source/root parent of -1 is NORMAL and must not be treated
     * as forged metadata.
     *
     * Only non-source nodes with an impossible parent ID are counted
     * here as structurally invalid metadata.
     */
    if (nodeId != s.sourceId &&
        (parentId < 0 || parentId >= numNodes)) {
        s.forgedMetadataEvents++;
    }

    recordTimeSeries(id);
}

void StatsCollector::recordDuplicate(
    const BroadcastId& id,
    int)
{
    auto& s = stats[id];

    s.duplicates++;

    recordTimeSeries(id);
}

void StatsCollector::recordTransmission(
    const BroadcastId& id,
    int,
    int)
{
    auto& s = stats[id];

    s.transmissions++;

    recordTimeSeries(id);
}

void StatsCollector::recordDrop(
    const BroadcastId& id,
    int,
    const char *)
{
    auto& s = stats[id];

    s.drops++;

    recordTimeSeries(id);
}

void StatsCollector::recordMaliciousAction(
    const BroadcastId& id,
    int,
    const char *attackType)
{
    auto& s = stats[id];

    s.maliciousActions++;

    if (attackType != nullptr &&
        std::string(attackType) == "spoof_metadata") {
        s.forgedMetadataEvents++;
    }

    recordTimeSeries(id);
}

void StatsCollector::recordTimeSeries(
    const BroadcastId& id)
{
    const auto& s = stats[id];

    /*
     * For connected networks, this is simply reached / numNodes.
     *
     * For sparse/disconnected topologies, use the size of the source
     * component as the denominator so that physically unreachable
     * nodes are not incorrectly treated as protocol failures.
     */
    const int denominator =
        topologySourceComponentSize > 0
            ? topologySourceComponentSize
            : std::max(1, numNodes);

    globalCoverageVector.record(
        static_cast<double>(s.reached.size()) /
        denominator
    );

    globalTransmissionVector.record(
        static_cast<double>(s.transmissions)
    );

    globalDuplicateVector.record(
        static_cast<double>(s.duplicates)
    );
}

bool StatsCollector::isTreeValid(
    const BroadcastStats& s) const
{
    if (s.reached.empty())
        return false;

    /*
     * We expect exactly one parent edge for every reached node
     * except the source.
     *
     * parentByNode contains the committed EBT structure.
     */
    int edgeCount = 0;

    for (const auto& p : s.parentByNode) {
        if (p.first == s.sourceId)
            continue;

        if (p.second >= 0)
            edgeCount++;
        else
            return false;
    }

    if (edgeCount !=
        static_cast<int>(s.reached.size()) - 1) {
        return false;
    }

    std::set<int> visiting;
    std::set<int> visited;

    std::function<bool(int)> dfs =
        [&](int node) -> bool
    {
        if (visiting.count(node) > 0)
            return false;   // cycle

        if (visited.count(node) > 0)
            return true;

        visiting.insert(node);

        /*
         * The source is the only legal root.
         */
        if (node == s.sourceId) {
            visiting.erase(node);
            visited.insert(node);
            return true;
        }

        auto it =
            s.parentByNode.find(node);

        if (it == s.parentByNode.end())
            return false;

        const int parent = it->second;

        if (parent < 0 ||
            parent >= numNodes) {
            return false;
        }

        if (s.reached.count(parent) == 0)
            return false;

        if (!dfs(parent))
            return false;

        visiting.erase(node);
        visited.insert(node);

        return true;
    };

    for (int node : s.reached) {
        if (!dfs(node))
            return false;
    }

    /*
     * Every reached node must ultimately lead back to the source.
     * Since cycles are rejected above and the edge count is correct,
     * this represents a single rooted tree over the reached nodes.
     */
    return visited.size() == s.reached.size();
}

simtime_t StatsCollector::completionTime(
    const BroadcastStats& s) const
{
    const int target =
        topologySourceComponentSize > 0
            ? topologySourceComponentSize
            : std::max(1, numNodes);

    if (static_cast<int>(s.reached.size()) < target)
        return -1;

    auto sourceIt =
        s.firstSeenByNode.find(s.sourceId);

    if (sourceIt == s.firstSeenByNode.end())
        return -1;

    simtime_t maxSeen = sourceIt->second;

    for (const auto& item : s.firstSeenByNode) {
        maxSeen = std::max(maxSeen, item.second);
    }

    // Return elapsed time relative to this broadcast's start.
    return maxSeen - sourceIt->second;
}

simtime_t StatsCollector::timeToCoverage(
    const BroadcastStats& s,
    double ratio) const
{
    ratio = std::max(0.0, std::min(1.0, ratio));

    const int targetBase =
        topologySourceComponentSize > 0
            ? topologySourceComponentSize
            : std::max(1, numNodes);

    const int target =
        std::max(
            1,
            static_cast<int>(
                std::ceil(ratio * targetBase)
            )
        );

    auto sourceIt =
        s.firstSeenByNode.find(s.sourceId);

    if (sourceIt == s.firstSeenByNode.end())
        return -1;

    std::vector<simtime_t> arrivals;
    arrivals.reserve(s.firstSeenByNode.size());

    for (const auto& kv : s.firstSeenByNode) {
        arrivals.push_back(kv.second);
    }

    if (static_cast<int>(arrivals.size()) < target)
        return -1;

    std::sort(arrivals.begin(), arrivals.end());

    // Convert absolute simulation timestamp to elapsed duration.
    return arrivals[target - 1] - sourceIt->second;
}

void StatsCollector::finish()
{
    // ------------------------------------------------------------
    // Global topology statistics
    // ------------------------------------------------------------

    recordScalar(
        "topology.components",
        topologyComponents
    );

    recordScalar(
        "topology.sourceComponentSize",
        topologySourceComponentSize
    );

    recordScalar(
        "topology.edgeCount",
        topologyEdgeCount
    );

    if (!topologyDegrees.empty()) {
        long sum = 0;

        for (int degree : topologyDegrees)
            sum += degree;

        recordScalar(
            "topology.avgDegree",
            static_cast<double>(sum) /
            topologyDegrees.size()
        );
    }

    // ------------------------------------------------------------
    // Per-broadcast statistics
    // ------------------------------------------------------------

    for (const auto& kv : stats) {

        const BroadcastId& id =
            kv.first;

        const BroadcastStats& s =
            kv.second;

        const std::string prefix =
            "broadcast." +
            id.toString() +
            ".";

        // --------------------------------------------------------
        // Tree structure
        // --------------------------------------------------------

        int edges = 0;
        int maxDepth = 0;

        for (const auto& p :
             s.parentByNode) {

            if (p.first != s.sourceId &&
                p.second >= 0) {
                edges++;
            }
        }

        for (const auto& d :
             s.depthByNode) {

            maxDepth =
                std::max(
                    maxDepth,
                    d.second
                );
        }

        // --------------------------------------------------------
        // Core dissemination metrics
        // --------------------------------------------------------

        recordScalar(
            (prefix + "reached").c_str(),
            static_cast<double>(
                s.reached.size()
            )
        );

        const int coverageDenominator =
            topologySourceComponentSize > 0
                ? topologySourceComponentSize
                : std::max(1, numNodes);

        recordScalar(
            (prefix + "coverageRatio").c_str(),
            static_cast<double>(
                s.reached.size()
            ) /
            coverageDenominator
        );

        recordScalar(
            (prefix + "duplicates").c_str(),
            static_cast<double>(
                s.duplicates
            )
        );

        recordScalar(
            (prefix + "transmissions").c_str(),
            static_cast<double>(
                s.transmissions
            )
        );

        recordScalar(
            (prefix + "drops").c_str(),
            static_cast<double>(
                s.drops
            )
        );

        // --------------------------------------------------------
        // Adversarial metrics
        // --------------------------------------------------------

        recordScalar(
            (prefix + "maliciousActions").c_str(),
            static_cast<double>(
                s.maliciousActions
            )
        );

        recordScalar(
            (prefix + "forgedMetadataEvents").c_str(),
            static_cast<double>(
                s.forgedMetadataEvents
            )
        );

        // --------------------------------------------------------
        // EBT structural metrics
        // --------------------------------------------------------

        recordScalar(
            (prefix + "treeEdges").c_str(),
            static_cast<double>(
                edges
            )
        );

        recordScalar(
            (prefix + "maxDepth").c_str(),
            static_cast<double>(
                maxDepth
            )
        );

        recordScalar(
            (prefix + "treeValid").c_str(),
            isTreeValid(s) ? 1.0 : 0.0
        );

        // --------------------------------------------------------
        // Completion / dissemination timing
        // --------------------------------------------------------

        const simtime_t completion =
            completionTime(s);

        recordScalar(
            (prefix + "completionTime").c_str(),
            completion
        );

        // Time to 90% coverage
        const simtime_t t90 =
            timeToCoverage(s, 0.9);

        if (t90 >= SIMTIME_ZERO) {
            recordScalar(
                (prefix + "timeTo90pctReachable").c_str(),
                t90
            );
        }

        // Time to 95% coverage
        const simtime_t t95 =
            timeToCoverage(s, 0.95);

        if (t95 >= SIMTIME_ZERO) {
            recordScalar(
                (prefix + "timeTo95pctReachable").c_str(),
                t95
            );
        }

        // Time until the last node that actually received
        // this broadcast, even if total coverage is incomplete.
        const auto sourceIt =
            s.firstSeenByNode.find(s.sourceId);

        if (sourceIt != s.firstSeenByNode.end()) {
            simtime_t lastSeen =
                sourceIt->second;

            for (const auto& item : s.firstSeenByNode) {
                lastSeen = std::max(
                    lastSeen,
                    item.second
                );
            }

            recordScalar(
                (prefix + "lastReachedTime").c_str(),
                lastSeen - sourceIt->second
            );
        }
    }
}
