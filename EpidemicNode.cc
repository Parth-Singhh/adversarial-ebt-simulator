#include "EpidemicNode.h"

#include <algorithm>

#include "EpidemicMessage_m.h"
#include "StatsCollector.h"

Define_Module(EpidemicNode);

enum {
    KIND_FORWARD = 100
};

void EpidemicNode::initialize()
{
    nodeId = par("nodeId");
    numNodes = par("numNodes");
    fanout = par("fanout");
    maxMessages = par("maxMessages");
    forwardDelay = par("forwardDelay");
    gossipDelay = par("gossipDelay");
    maliciousJitterMax = par("maliciousJitterMax");

    malicious = par("isMalicious");
    attackType = AttackModel::parseAttackType(par("attackType").stdstringValue());
    if (!malicious)
        attackType = AttackType::Honest;

    firstReceptionSignal = registerSignal("firstReception");
    duplicateSignal = registerSignal("duplicateReception");
    transmitSignal = registerSignal("transmission");
    dropSignal = registerSignal("drop");
    maliciousSignal = registerSignal("maliciousAction");

    refreshNeighborCache();
}

void EpidemicNode::configureRole(bool maliciousRole, AttackType type)
{
    malicious = maliciousRole;
    attackType = maliciousRole ? type : AttackType::Honest;
}

StatsCollector *EpidemicNode::collector() const
{
    return check_and_cast<StatsCollector *>(getParentModule()->getSubmodule("collector"));
}

BroadcastId EpidemicNode::keyFromPacket(const EpidemicMessage *msg) const
{
    BroadcastId key;
    key.sessionId = msg->getSessionId();
    key.originId = msg->getOriginId();
    key.sequenceNo = msg->getBroadcastSeq();
    return key;
}

void EpidemicNode::refreshNeighborCache()
{
    gateByNeighborId.clear();

    for (int i = 0; i < gateSize("port"); ++i) {
        cGate *outGate = gate("port$o", i);
        cGate *next = outGate ? outGate->getNextGate() : nullptr;
        if (!next)
            continue;

        cModule *remote = next->getOwnerModule();
        if (!remote)
            continue;

        int neighborId = remote->par("nodeId");
        gateByNeighborId[neighborId] = i;
    }
}

std::vector<int> EpidemicNode::selectRandomNeighbors(int excludeNeighborId, int desiredFanout)
{
    if (gateByNeighborId.empty())
        refreshNeighborCache();

    std::vector<int> candidates;
    candidates.reserve(gateByNeighborId.size());

    for (const auto& kv : gateByNeighborId) {
        if (kv.first == excludeNeighborId)
            continue;
        candidates.push_back(kv.first);
    }

    for (int i = (int)candidates.size() - 1; i > 0; --i) {
        int j = intuniform(0, i);
        std::swap(candidates[i], candidates[j]);
    }

    if ((int)candidates.size() > desiredFanout)
        candidates.resize(desiredFanout);

    return candidates;
}

void EpidemicNode::triggerBroadcast(int sessionId, int sequenceNo)
{
    BroadcastId key{sessionId, nodeId, sequenceNo};
    auto& state = stateByBroadcast[key];

    if (state.seen)
        return;

    state.seen = true;
    state.parentId = -1;
    state.depth = 0;
    state.firstSeenTime = simTime();
    state.forwardScheduled = true;
    state.acceptedParents.push_back(-1);

    totalAcceptedBroadcasts++;

    collector()->recordSourceStart(key, nodeId, simTime());
    collector()->recordParentCommit(key, nodeId, -1, 0, simTime());

    auto *event = new cMessage("forwardBroadcast", KIND_FORWARD);
    event->addPar("sessionId") = key.sessionId;
    event->addPar("originId") = key.originId;
    event->addPar("sequenceNo") = key.sequenceNo;
    scheduleAt(simTime() + forwardDelay, event);
}

void EpidemicNode::sendToNeighbor(const BroadcastId& key, BroadcastState& state, int neighborId,
                                  int senderId, int originId, int attackTag,
                                  simtime_t extraDelay)
{
    auto gateIt = gateByNeighborId.find(neighborId);
    if (gateIt == gateByNeighborId.end())
        return;

    auto *out = new EpidemicMessage("epidemicBroadcast");
    out->setSessionId(key.sessionId);
    out->setBroadcastSeq(key.sequenceNo);
    out->setOriginId(originId);
    out->setSenderId(senderId);
    out->setHopCount(state.depth + 1);
    out->setCreationTime(state.firstSeenTime);
    out->setAttackTag(attackTag);
    out->setSpoofed(senderId != nodeId || originId != key.originId);
    out->setByteLength(48);

    sendDelayed(out, gossipDelay + extraDelay, "port$o", gateIt->second);
    state.forwardedPeers.insert(neighborId);

    emit(transmitSignal, 1L);
    collector()->recordTransmission(key, nodeId, neighborId);
}

void EpidemicNode::processForwardEvent(const BroadcastId& key)
{
    auto it = stateByBroadcast.find(key);
    if (it == stateByBroadcast.end())
        return;

    BroadcastState& state = it->second;
    if (state.forwarded || state.terminal)
        return;

    collector()->recordParentCommit(key, nodeId, state.parentId, state.depth, state.firstSeenTime);

    auto selected = selectRandomNeighbors(state.parentId, fanout);
    bool droppedAll = true;

    for (int neighborId : selected) {
        AttackDecision decision = malicious
            ? AttackModel::decide(attackType, nodeId, neighborId, maliciousJitterMax)
            : AttackDecision{};

        if (malicious && attackType != AttackType::Honest) {
            emit(maliciousSignal, 1L);
            collector()->recordMaliciousAction(key, nodeId, AttackModel::toString(attackType).c_str());
        }

        if (decision.drop) {
            emit(dropSignal, 1L);
            collector()->recordDrop(key, nodeId, "attack_drop");
            continue;
        }

        droppedAll = false;

        int senderId = decision.spoofMetadata ? ((nodeId + 7) % std::max(1, numNodes)) : nodeId;
        int originId = decision.spoofMetadata ? ((key.originId + 13) % std::max(1, numNodes)) : key.originId;
        int attackTag = decision.equivocate ? (nodeId * 1000 + neighborId) : 0;

        sendToNeighbor(key, state, neighborId, senderId, originId, attackTag, decision.extraDelay);

        for (int n = 0; n < decision.duplicateBurst; ++n)
            sendToNeighbor(key, state, neighborId, senderId, originId, attackTag, decision.extraDelay);
    }

    if (droppedAll && !selected.empty()) {
        emit(dropSignal, 1L);
        collector()->recordDrop(key, nodeId, "all_candidates_dropped");
    }

    state.forwarded = true;
    state.terminal = true;
}

void EpidemicNode::onReceive(EpidemicMessage *msg)
{
    BroadcastId key = keyFromPacket(msg);
    auto& state = stateByBroadcast[key];

    if (!state.seen && totalAcceptedBroadcasts >= maxMessages) {
        emit(dropSignal, 1L);
        collector()->recordDrop(key, nodeId, "max_messages_limit");
        delete msg;
        return;
    }

    const int senderId = msg->getSenderId();
    const int hopCount = msg->getHopCount();

    if (!state.seen) {
        state.seen = true;
        state.parentId = senderId;
        state.depth = hopCount;
        state.firstSeenTime = simTime();
        state.forwardScheduled = true;
        state.acceptedParents.push_back(senderId);

        totalAcceptedBroadcasts++;

        emit(firstReceptionSignal, 1L);

        auto *event = new cMessage("forwardBroadcast", KIND_FORWARD);
        event->addPar("sessionId") = key.sessionId;
        event->addPar("originId") = key.originId;
        event->addPar("sequenceNo") = key.sequenceNo;
        scheduleAt(simTime() + forwardDelay, event);

        delete msg;
        return;
    }

    state.duplicateCount++;
    emit(duplicateSignal, 1L);
    collector()->recordDuplicate(key, nodeId);

    if (!state.forwarded && simTime() == state.firstSeenTime) {
        bool betterDepth = hopCount < state.depth;
        bool tieBreakSender = (hopCount == state.depth && senderId < state.parentId);

        if (betterDepth || tieBreakSender) {
            state.rejectedParents.push_back(state.parentId);
            state.parentId = senderId;
            state.depth = hopCount;
            state.acceptedParents.push_back(senderId);
        } else {
            state.rejectedParents.push_back(senderId);
        }
    }

    delete msg;
}

void EpidemicNode::handleMessage(cMessage *msg)
{
    if (msg->isSelfMessage() && msg->getKind() == KIND_FORWARD) {
        BroadcastId key;
        key.sessionId = msg->par("sessionId");
        key.originId = msg->par("originId");
        key.sequenceNo = msg->par("sequenceNo");

        processForwardEvent(key);
        delete msg;
        return;
    }

    auto *packet = check_and_cast<EpidemicMessage *>(msg);
    onReceive(packet);
}
