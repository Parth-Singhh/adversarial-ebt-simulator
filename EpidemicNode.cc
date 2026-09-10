#include "EpidemicNode.h"
#include "EpidemicMessage_m.h"

#include <algorithm>
#include <cmath>
#include <random>

Define_Module(EpidemicNode);

void EpidemicNode::initialize()
{
    nodeId = par("nodeId");
    numNodes = par("numNodes");
    source = par("isSource");

    fanout = par("fanout");
    forwardDelay = par("forwardDelay");
    gossipDelay = par("gossipDelay");

    startMessage = new cMessage("startBroadcast");

    WATCH(nodeId);
    WATCH(fanout);

    if (source)
        scheduleAt(SIMTIME_ZERO + uniform(0, 1e-6), startMessage);
}

int EpidemicNode::gateToNode(int gateIndex) const
{
    cGate *g = gate("port$o", gateIndex);
    cGate *next = g->getNextGate();
    if (!next)
        return -1;

    cModule *remote = next->getOwnerModule();
    if (!remote)
        return -1;

    return remote->par("nodeId");
}

bool EpidemicNode::hasSeen(int messageId) const
{
    return parent.find(messageId) != parent.end();
}

std::vector<int> EpidemicNode::selectRandomNeighbors(int excludeGateIndex,
                                                       int desiredFanout)
{
    std::vector<int> candidates;

    for (int i = 0; i < gateSize("port"); ++i) {
        if (i == excludeGateIndex)
            continue;

        if (gate("port$o", i)->getNextGate() != nullptr)
            candidates.push_back(i);
    }

    // Fisher-Yates shuffle using OMNeT++ RNG.
    for (int i = (int)candidates.size() - 1; i > 0; --i) {
        int j = intuniform(0, i);
        std::swap(candidates[i], candidates[j]);
    }

    if ((int)candidates.size() > desiredFanout)
        candidates.resize(desiredFanout);

    return candidates;
}

void EpidemicNode::startBroadcast()
{
    int messageId = getId() * 1000000 + nextMessageId++;

    parent[messageId] = -1;
    depth[messageId] = 0;

    totalFirstReceptions++;

    EV_INFO << "Node " << nodeId
            << " starts epidemic broadcast, messageId="
            << messageId << endl;

    forwardMessage(messageId, nodeId, 0, simTime());
}

void EpidemicNode::scheduleForward(EpidemicMessage *msg)
{
    // Copy only the information needed for forwarding. The original packet is
    // deleted by the caller after processing.
    int messageId = msg->getMessageId();
    int originId = msg->getOriginId();
    int hopCount = msg->getHopCount();
    simtime_t creationTime = msg->getCreationTime();

    auto *event = new cMessage("forwardEpidemic");
    event->addPar("messageId") = messageId;
    event->addPar("originId") = originId;
    event->addPar("hopCount") = hopCount;
    event->addPar("creationTime") = creationTime;

    scheduleAt(simTime() + forwardDelay, event);
}

void EpidemicNode::forwardMessage(int messageId, int originId, int hopCount,
                                  simtime_t creationTime)
{
    int incomingGate = -1;

    // The parent gate is not stored explicitly. For a fully connected graph,
    // exclude the parent by looking up the parent node ID.
    auto pIt = parent.find(messageId);
    if (pIt != parent.end() && pIt->second >= 0) {
        int parentId = pIt->second;
        for (int i = 0; i < gateSize("port"); ++i) {
            if (gateToNode(i) == parentId) {
                incomingGate = i;
                break;
            }
        }
    }

    auto selected = selectRandomNeighbors(incomingGate, fanout);

    for (int gateIndex : selected) {
        auto *out = new EpidemicMessage("epidemicBroadcast");
        out->setMessageId(messageId);
        out->setOriginId(originId);
        out->setSenderId(nodeId);
        out->setHopCount(hopCount + 1);
        out->setCreationTime(creationTime);
        out->setByteLength(32);

        sendDelayed(out, gossipDelay, "port$o", gateIndex);
        totalTransmissions++;
    }

    coverageVector.record((double)parent.size() / (double)numNodes);
    transmissionsVector.record(totalTransmissions);

    long duplicateCount = 0;
    for (const auto& x : duplicateReception)
        duplicateCount += x.second;
    duplicatesVector.record(duplicateCount);

    long edges = 0;
    for (const auto& x : children)
        edges += x.second.size();
    treeEdgesVector.record(edges);
}

void EpidemicNode::recordTreeEdge(int child, int p)
{
    children[p].insert(child);
}

void EpidemicNode::receiveEpidemicMessage(EpidemicMessage *msg)
{
    const int messageId = msg->getMessageId();
    const int senderId = msg->getSenderId();
    const int hopCount = msg->getHopCount();

    if (hasSeen(messageId)) {
        duplicateReception[messageId]++;
        totalDuplicates++;

        EV_DEBUG << "Node " << nodeId
                 << " ignores duplicate message " << messageId
                 << " from node " << senderId << endl;

        delete msg;
        return;
    }

    // First reception establishes the tree parent.
    parent[messageId] = senderId;
    depth[messageId] = hopCount;

    recordTreeEdge(nodeId, senderId);
    totalFirstReceptions++;

    EV_INFO << "Node " << nodeId
            << " first received message " << messageId
            << " from parent " << senderId
            << ", depth=" << hopCount << endl;

    scheduleForward(msg);

    delete msg;
}

void EpidemicNode::handleMessage(cMessage *msg)
{
    if (msg == startMessage) {
        startBroadcast();
        return;
    }

    // Self-message generated for delayed forwarding.
    if (msg->isSelfMessage()) {
        int messageId = msg->par("messageId");
        int originId = msg->par("originId");
        int hopCount = msg->par("hopCount");
        simtime_t creationTime = msg->par("creationTime");

        forwardMessage(messageId, originId, hopCount, creationTime);
        delete msg;
        return;
    }

    auto *packet = check_and_cast<EpidemicMessage *>(msg);
    receiveEpidemicMessage(packet);
}

void EpidemicNode::finish()
{
    long totalTreeEdges = 0;
    long maxDepth = 0;

    // This module stores only its local portion of the tree.
    for (const auto& item : children)
        totalTreeEdges += item.second.size();

    for (const auto& item : depth)
        maxDepth = std::max(maxDepth, (long)item.second);

    recordScalar("nodeId", nodeId);
    recordScalar("firstReceptions", totalFirstReceptions);
    recordScalar("duplicateReceptions", totalDuplicates);
    recordScalar("transmissions", totalTransmissions);
    recordScalar("localTreeEdges", totalTreeEdges);
    recordScalar("maximumLocalDepth", maxDepth);

    delete startMessage;
}
