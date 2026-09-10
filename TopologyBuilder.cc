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

    auto edges = buildEdgeSet();
    connectEdges(edges);

    std::vector<int> degrees;
    int components = 0;
    int sourceCompSize = 0;
    computeTopologyStats(edges, degrees, components, sourceCompSize);

    auto *collector = check_and_cast<StatsCollector *>(getParentModule()->getSubmodule("collector"));
    collector->recordTopology(degrees, components, sourceCompSize, (int)edges.size());
}

void TopologyBuilder::handleMessage(cMessage *msg)
{
    delete msg;
}

std::set<std::pair<int, int>> TopologyBuilder::buildEdgeSet() const
{
    std::string mode = par("topologyMode").stdstringValue();
    if (mode == "erdosRenyi")
        return buildErdosRenyi(par("erProbability"));
    if (mode == "fixedDegree")
        return buildFixedDegree(par("fixedDegree"));
    if (mode == "file")
        return buildFromFile(par("graphFile").stdstringValue());
    return buildComplete();
}

std::set<std::pair<int, int>> TopologyBuilder::buildComplete() const
{
    std::set<std::pair<int, int>> edges;
    for (int i = 0; i < numNodes; ++i)
        for (int j = i + 1; j < numNodes; ++j)
            edges.insert({i, j});
    return edges;
}

std::set<std::pair<int, int>> TopologyBuilder::buildErdosRenyi(double p) const
{
    std::set<std::pair<int, int>> edges;
    for (int i = 0; i < numNodes; ++i) {
        for (int j = i + 1; j < numNodes; ++j) {
            if (uniform(0, 1) <= p)
                edges.insert({i, j});
        }
    }
    return edges;
}

std::set<std::pair<int, int>> TopologyBuilder::buildFixedDegree(int degree) const
{
    std::set<std::pair<int, int>> edges;
    int k = std::max(0, std::min(degree, numNodes - 1));
    if (k % 2 == 1)
        k--;

    for (int i = 0; i < numNodes; ++i) {
        for (int d = 1; d <= k / 2; ++d) {
            int j = (i + d) % numNodes;
            int a = std::min(i, j);
            int b = std::max(i, j);
            edges.insert({a, b});
        }
    }

    return edges;
}

std::set<std::pair<int, int>> TopologyBuilder::buildFromFile(const std::string& path) const
{
    std::set<std::pair<int, int>> edges;
    std::ifstream in(path);
    if (!in.is_open())
        throw cRuntimeError("Cannot open graph file: %s", path.c_str());

    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#')
            continue;
        std::stringstream ss(line);
        int u, v;
        if (!(ss >> u >> v))
            continue;
        if (u < 0 || u >= numNodes || v < 0 || v >= numNodes || u == v)
            continue;
        int a = std::min(u, v);
        int b = std::max(u, v);
        edges.insert({a, b});
    }

    return edges;
}

void TopologyBuilder::connectEdges(const std::set<std::pair<int, int>>& edges)
{
    std::vector<int> degree(numNodes, 0);
    for (const auto& e : edges) {
        degree[e.first]++;
        degree[e.second]++;
    }

    std::vector<int> nextGate(numNodes, 0);

    for (int i = 0; i < numNodes; ++i) {
        cModule *node = getParentModule()->getSubmodule("node", i);
        node->setGateSize("port", degree[i]);
    }

    simtime_t linkDelay = par("linkDelay");

    for (const auto& e : edges) {
        int a = e.first;
        int b = e.second;
        int ga = nextGate[a]++;
        int gb = nextGate[b]++;

        cModule *nodeA = getParentModule()->getSubmodule("node", a);
        cModule *nodeB = getParentModule()->getSubmodule("node", b);

        cGate *aOut = nodeA->gate("port$o", ga);
        cGate *aIn = nodeA->gate("port$i", ga);
        cGate *bOut = nodeB->gate("port$o", gb);
        cGate *bIn = nodeB->gate("port$i", gb);

        auto *ab = cDelayChannel::create("ch");
        ab->setDelay(linkDelay);
        aOut->connectTo(bIn, ab);

        auto *ba = cDelayChannel::create("ch");
        ba->setDelay(linkDelay);
        bOut->connectTo(aIn, ba);
    }
}

void TopologyBuilder::computeTopologyStats(const std::set<std::pair<int, int>>& edges,
                                           std::vector<int>& degrees,
                                           int& componentCount,
                                           int& sourceComponentSize) const
{
    degrees.assign(numNodes, 0);
    std::vector<std::vector<int>> adj(numNodes);

    for (const auto& e : edges) {
        degrees[e.first]++;
        degrees[e.second]++;
        adj[e.first].push_back(e.second);
        adj[e.second].push_back(e.first);
    }

    componentCount = 0;
    sourceComponentSize = 0;
    std::vector<bool> visited(numNodes, false);

    for (int i = 0; i < numNodes; ++i) {
        if (visited[i])
            continue;
        componentCount++;

        int size = 0;
        std::queue<int> q;
        q.push(i);
        visited[i] = true;

        while (!q.empty()) {
            int u = q.front();
            q.pop();
            size++;

            for (int v : adj[u]) {
                if (!visited[v]) {
                    visited[v] = true;
                    q.push(v);
                }
            }
        }

        if (i == sourceNode || (sourceComponentSize == 0 && visited[sourceNode]))
            sourceComponentSize = size;
    }
}
