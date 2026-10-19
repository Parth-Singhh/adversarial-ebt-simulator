#include "TopologyBuilder.h"

#include <algorithm>
#include <fstream>
#include <queue>
#include <sstream>

#include "StatsCollector.h"

Define_Module(TopologyBuilder);

void TopologyBuilder::initialize()
{
    numNodes = par("numNodes");
    sourceNode = par("sourceNode");

    // ------------------------------------------------------------
    // Validate topology configuration
    // ------------------------------------------------------------
    if (numNodes <= 0) {
        throw cRuntimeError(
            "TopologyBuilder: numNodes must be greater than 0, got %d",
            numNodes
        );
    }

    if (sourceNode < 0 || sourceNode >= numNodes) {
        throw cRuntimeError(
            "TopologyBuilder: sourceNode=%d is outside "
            "the valid range [0,%d)",
            sourceNode,
            numNodes
        );
    }

    const simtime_t linkDelay =
        par("linkDelay");

    if (linkDelay < SIMTIME_ZERO) {
        throw cRuntimeError(
            "TopologyBuilder: linkDelay must be >= 0, got %s",
            linkDelay.str().c_str()
        );
    }

    // ------------------------------------------------------------
    // Build topology
    // ------------------------------------------------------------
    const auto edges =
        buildEdgeSet();

    connectEdges(edges);

    // ------------------------------------------------------------
    // Compute topology statistics
    // ------------------------------------------------------------
    std::vector<int> degrees;
    int components = 0;
    int sourceCompSize = 0;

    computeTopologyStats(
        edges,
        degrees,
        components,
        sourceCompSize
    );

    auto *collector =
        check_and_cast<StatsCollector *>(
            getParentModule()->getSubmodule(
                "collector"
            )
        );

    collector->recordTopology(
        degrees,
        components,
        sourceCompSize,
        static_cast<int>(
            edges.size()
        )
    );
}

void TopologyBuilder::handleMessage(
    cMessage *msg)
{
    delete msg;
}

std::set<std::pair<int, int>>
TopologyBuilder::buildEdgeSet() const
{
    const std::string mode =
        par("topologyMode").stdstringValue();

    if (mode == "erdosRenyi")
        return buildErdosRenyi(
            par("erProbability")
        );

    if (mode == "fixedDegree")
        return buildFixedDegree(
            par("fixedDegree")
        );

    if (mode == "file")
        return buildFromFile(
            par("graphFile").stdstringValue()
        );

    if (mode == "complete")
        return buildComplete();

    throw cRuntimeError(
        "TopologyBuilder: unknown topologyMode='%s'",
        mode.c_str()
    );
}

std::set<std::pair<int, int>>
TopologyBuilder::buildComplete() const
{
    std::set<std::pair<int, int>> edges;

    for (int i = 0;
         i < numNodes;
         ++i) {

        for (int j = i + 1;
             j < numNodes;
             ++j) {

            edges.insert({
                i,
                j
            });
        }
    }

    return edges;
}

std::set<std::pair<int, int>>
TopologyBuilder::buildErdosRenyi(
    double p
) const
{
    std::set<std::pair<int, int>> edges;

    // Keep probability inside its mathematically valid range.
    p =
        std::max(
            0.0,
            std::min(
                1.0,
                p
            )
        );

    for (int i = 0;
         i < numNodes;
         ++i) {

        for (int j = i + 1;
             j < numNodes;
             ++j) {

            if (uniform(0, 1) < p) {
                edges.insert({
                    i,
                    j
                });
            }
        }
    }

    return edges;
}

std::set<std::pair<int, int>>
TopologyBuilder::buildFixedDegree(
    int degree
) const
{
    std::set<std::pair<int, int>> edges;

    int k =
        std::max(
            0,
            std::min(
                degree,
                numNodes - 1
            )
        );

    /*
     * This construction produces an even-degree circulant topology.
     * Preserve the existing behavior for odd requested degrees by
     * reducing k to the nearest lower even value.
     */
    if (k % 2 == 1)
        --k;

    for (int i = 0;
         i < numNodes;
         ++i) {

        for (int d = 1;
             d <= k / 2;
             ++d) {

            const int j =
                (i + d) % numNodes;

            const int a =
                std::min(i, j);

            const int b =
                std::max(i, j);

            edges.insert({
                a,
                b
            });
        }
    }

    return edges;
}

std::set<std::pair<int, int>>
TopologyBuilder::buildFromFile(
    const std::string& path
) const
{
    std::set<std::pair<int, int>> edges;

    std::ifstream in(path);

    if (!in.is_open()) {
        throw cRuntimeError(
            "TopologyBuilder: cannot open graph file: %s",
            path.c_str()
        );
    }

    std::string line;

    while (std::getline(in, line)) {

        // Ignore empty lines.
        if (line.empty())
            continue;

        // Ignore comment lines.
        if (line[0] == '#')
            continue;

        std::stringstream ss(line);

        int u;
        int v;

        if (!(ss >> u >> v))
            continue;

        // Ignore invalid node IDs.
        if (u < 0 ||
            u >= numNodes ||
            v < 0 ||
            v >= numNodes) {
            continue;
        }

        // Ignore self-loops.
        if (u == v)
            continue;

        const int a =
            std::min(
                u,
                v
            );

        const int b =
            std::max(
                u,
                v
            );

        edges.insert({
            a,
            b
        });
    }

    return edges;
}

void TopologyBuilder::connectEdges(
    const std::set<std::pair<int, int>>& edges
)
{
    std::vector<int> degree(
        numNodes,
        0
    );

    // ------------------------------------------------------------
    // Calculate node degrees
    // ------------------------------------------------------------
    for (const auto& edge : edges) {

        const int a = edge.first;
        const int b = edge.second;

        ++degree[a];
        ++degree[b];
    }

    // Tracks which gate index is used next for every node.
    std::vector<int> nextGate(
        numNodes,
        0
    );

    // ------------------------------------------------------------
    // Resize every node's gate vector before connecting.
    // ------------------------------------------------------------
    for (int i = 0;
         i < numNodes;
         ++i) {

        cModule *node =
            getParentModule()->getSubmodule(
                "node",
                i
            );

        if (node == nullptr) {
            throw cRuntimeError(
                "TopologyBuilder: node[%d] does not exist",
                i
            );
        }

        node->setGateSize(
            "port",
            degree[i]
        );
    }

    const simtime_t linkDelay =
        par("linkDelay");

    // ------------------------------------------------------------
    // Create the bidirectional connections.
    // ------------------------------------------------------------
    for (const auto& edge : edges) {

        const int a = edge.first;
        const int b = edge.second;

        const int gateA =
            nextGate[a]++;

        const int gateB =
            nextGate[b]++;

        cModule *nodeA =
            getParentModule()->getSubmodule(
                "node",
                a
            );

        cModule *nodeB =
            getParentModule()->getSubmodule(
                "node",
                b
            );

        cGate *aOut =
            nodeA->gate(
                "port$o",
                gateA
            );

        cGate *aIn =
            nodeA->gate(
                "port$i",
                gateA
            );

        cGate *bOut =
            nodeB->gate(
                "port$o",
                gateB
            );

        cGate *bIn =
            nodeB->gate(
                "port$i",
                gateB
            );

        if (aOut == nullptr ||
            aIn == nullptr ||
            bOut == nullptr ||
            bIn == nullptr) {

            throw cRuntimeError(
                "TopologyBuilder: invalid gate while "
                "connecting node[%d] <-> node[%d]",
                a,
                b
            );
        }

        // --------------------------------------------------------
        // A -> B
        //
        // finalizeParameters() is required for dynamically created
        // channel objects in current OMNeT++ versions.
        // connectTo() then installs and initializes the channel
        // according to the current module lifecycle.
        // --------------------------------------------------------
        auto *ab = cDelayChannel::create("ch");

        aOut->connectTo(bIn, ab, true);
        ab->finalizeParameters();
        ab->setDelay(linkDelay.dbl());
        ab->callInitialize();

        // --------------------------------------------------------
        // B -> A
        // --------------------------------------------------------
        auto *ba = cDelayChannel::create("ch");

        bOut->connectTo(aIn, ba, true);
        ba->finalizeParameters();
        ba->setDelay(linkDelay.dbl());
        ba->callInitialize();
    }
}

void TopologyBuilder::computeTopologyStats(
    const std::set<std::pair<int, int>>& edges,
    std::vector<int>& degrees,
    int& componentCount,
    int& sourceComponentSize
) const
{
    degrees.assign(
        numNodes,
        0
    );

    std::vector<
        std::vector<int>
    > adj(numNodes);

    // ------------------------------------------------------------
    // Build adjacency representation
    // ------------------------------------------------------------
    for (const auto& edge : edges) {

        const int u =
            edge.first;

        const int v =
            edge.second;

        ++degrees[u];
        ++degrees[v];

        adj[u].push_back(v);
        adj[v].push_back(u);
    }

    componentCount = 0;
    sourceComponentSize = 0;

    std::vector<bool> visited(
        numNodes,
        false
    );

    // ------------------------------------------------------------
    // Find connected components using BFS.
    // ------------------------------------------------------------
    for (int i = 0;
         i < numNodes;
         ++i) {

        if (visited[i])
            continue;

        ++componentCount;

        int componentSize = 0;

        std::queue<int> q;

        q.push(i);

        visited[i] = true;

        while (!q.empty()) {

            const int u =
                q.front();

            q.pop();

            ++componentSize;

            for (int v :
                 adj[u]) {

                if (!visited[v]) {

                    visited[v] = true;

                    q.push(v);
                }
            }
        }

        // The source component is the component containing sourceNode.
        if (visited[sourceNode] &&
            sourceComponentSize == 0) {

            sourceComponentSize =
                componentSize;
        }
    }

    // Defensive fallback; sourceNode has already been validated.
    if (sourceComponentSize == 0)
        sourceComponentSize = 1;
}
