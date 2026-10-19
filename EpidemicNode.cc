#include "EpidemicNode.h"

#include <algorithm>
#include <cmath>

#include "EpidemicMessage_m.h"
#include "StatsCollector.h"

Define_Module(EpidemicNode);

enum {
    KIND_FORWARD = 100,
    KIND_TRIGGER = 1
};

void EpidemicNode::initialize()
{
    nodeId = par("nodeId");
    numNodes = par("numNodes");
    runId = par("runId");
    sourceNode = par("sourceNode");
    sessionId = par("sessionId");

    fanout = par("fanout");
    maxMessages = par("maxMessages");
    forwardDelay = par("forwardDelay");
    gossipDelay = par("gossipDelay");

    attackConfig.forwardProb =
        par("forwardProb");

    attackConfig.selectiveTargetFraction =
        par("selectiveTargetFraction");

    attackConfig.maxExtraDelay =
        par("maxExtraDelay");

    attackConfig.isolationMode =
        par("isolationMode").stdstringValue();

    attackConfig.isolatedPeers =
        AttackModel::parseNodeSet(
            par("isolatedPeerSet").stdstringValue(),
            numNodes
        );

    attackConfig.enableSpoofMetadata =
        par("enableSpoofMetadata");

    attackConfig.enableEquivocation =
        par("enableEquivocation");

    // Every node starts as honest.
    //
    // ExperimentController applies the actual malicious role after
    // all EpidemicNode modules have completed initialization.
    malicious = false;
    attackType = AttackType::Honest;
    attackPolicy = AttackModel::createPolicy(attackType);

    firstReceptionSignal =
        registerSignal("firstReception");

    duplicateSignal =
        registerSignal("duplicateReception");

    transmitSignal =
        registerSignal("transmission");

    dropSignal =
        registerSignal("drop");

    maliciousSignal =
        registerSignal("maliciousAction");

    refreshNeighborCache();
}

void EpidemicNode::configureRole(
    bool maliciousRole,
    AttackType type,
    const AttackConfig& config)
{
    malicious = maliciousRole;

    attackType =
        maliciousRole
            ? type
            : AttackType::Honest;

    attackConfig = config;

    attackPolicy =
        AttackModel::createPolicy(
            attackType
        );
}

StatsCollector *EpidemicNode::collector() const
{
    return check_and_cast<StatsCollector *>(
        getParentModule()->getSubmodule("collector")
    );
}

BroadcastId EpidemicNode::keyFromPacket(
    const EpidemicMessage *msg) const
{
    BroadcastId key;

    key.runId =
        msg->getRunId();

    key.sessionId =
        msg->getSessionId();

    key.originId =
        msg->getOriginId();

    key.sequenceNo =
        msg->getBroadcastSeq();

    return key;
}

void EpidemicNode::refreshNeighborCache()
{
    gateByNeighborId.clear();

    for (int i = 0;
         i < gateSize("port");
         ++i) {

        cGate *outGate =
            gate("port$o", i);

        cGate *next =
            outGate != nullptr
                ? outGate->getNextGate()
                : nullptr;

        if (next == nullptr)
            continue;

        cModule *remote =
            next->getOwnerModule();

        if (remote == nullptr)
            continue;

        int neighborId =
            remote->par("nodeId");

        gateByNeighborId[neighborId] = i;
    }
}

std::vector<int>
EpidemicNode::selectRandomNeighbors(
    int excludeNeighborId,
    int desiredFanout)
{
    if (gateByNeighborId.empty())
        refreshNeighborCache();

    desiredFanout =
        std::max(
            0,
            desiredFanout
        );

    std::vector<int> candidates;

    candidates.reserve(
        gateByNeighborId.size()
    );

    for (const auto& entry :
         gateByNeighborId) {

        int neighborId =
            entry.first;

        if (neighborId ==
            excludeNeighborId) {
            continue;
        }

        candidates.push_back(
            neighborId
        );
    }

    for (int i =
             static_cast<int>(
                 candidates.size()
             ) - 1;
         i > 0;
         --i) {

        int j =
            intuniform(
                0,
                i
            );

        std::swap(
            candidates[i],
            candidates[j]
        );
    }

    if (static_cast<int>(
            candidates.size()
        ) > desiredFanout) {

        candidates.resize(
            desiredFanout
        );
    }

    return candidates;
}

void EpidemicNode::triggerBroadcast(
    int broadcastSessionId,
    int sequenceNo)
{

    Enter_Method_Silent();
    BroadcastId key{
        runId,
        broadcastSessionId,
        nodeId,
        sequenceNo
    };

    auto& state =
        stateByBroadcast[key];

    if (state.seen)
        return;

    state.seen = true;
    state.parentId = -1;
    state.depth = 0;

    state.firstSeenTime =
        simTime();

    state.commitDeadline =
        state.firstSeenTime +
        forwardDelay;

    state.forwardScheduled = true;

    state.acceptedParents.push_back(
        -1
    );

    totalAcceptedBroadcasts++;

    collector()->recordSourceStart(
        key,
        nodeId,
        simTime()
    );

    auto *event =
        new cMessage(
            "forwardBroadcast",
            KIND_FORWARD
        );

    event->addPar(
        "runId"
    ) = key.runId;

    event->addPar(
        "sessionId"
    ) = key.sessionId;

    event->addPar(
        "originId"
    ) = key.originId;

    event->addPar(
        "sequenceNo"
    ) = key.sequenceNo;

    scheduleAt(
        state.commitDeadline,
        event
    );
}

void EpidemicNode::sendToNeighbor(
    const BroadcastId& key,
    BroadcastState& state,
    int neighborId,
    int senderId,
    int originId,
    const AttackOutcome& outcome)
{
    auto gateIt =
        gateByNeighborId.find(
            neighborId
        );

    if (gateIt ==
        gateByNeighborId.end()) {
        return;
    }

    auto *out =
        new EpidemicMessage(
            "epidemicBroadcast"
        );

    out->setRunId(
        key.runId
    );

    out->setSessionId(
        key.sessionId
    );

    out->setBroadcastSeq(
        key.sequenceNo
    );

    out->setOriginId(
        originId
    );

    out->setSenderId(
        senderId
    );

    out->setHopCount(
        state.depth + 1
    );

    out->setGlobalBroadcastId(
        key.globalId()
    );

    out->setParentCandidateId(
        nodeId
    );

    out->setCreationTime(
        state.firstSeenTime
    );

    out->setFirstSeenAtSender(
        state.firstSeenTime
    );

    out->setAttackFlags(
        outcome.attackFlags
    );

    out->setPayloadVariantId(
        outcome.payloadVariantId
    );

    out->setSpoofed(
        senderId != nodeId ||
        originId != key.originId
    );

    out->setByteLength(
        64
    );

    sendDelayed(
        out,
        gossipDelay +
            outcome.extraDelay,
        "port$o",
        gateIt->second
    );

    state.forwardedPeers.insert(
        neighborId
    );

    emit(
        transmitSignal,
        1L
    );

    collector()->recordTransmission(
        key,
        nodeId,
        neighborId
    );
}

void EpidemicNode::processForwardEvent(
    const BroadcastId& key)
{
    auto it =
        stateByBroadcast.find(
            key
        );

    if (it ==
        stateByBroadcast.end()) {
        return;
    }

    BroadcastState& state =
        it->second;

    if (state.forwarded ||
        state.terminal) {
        return;
    }

    // Parent commitment is recorded separately from first reception.
    collector()->recordParentCommit(
        key,
        nodeId,
        state.parentId,
        state.depth,
        state.firstSeenTime
    );

    auto selected =
        selectRandomNeighbors(
            state.parentId,
            fanout
        );

    bool droppedAll = true;

    for (int neighborId :
         selected) {

        AttackContext ctx;

        ctx.nodeId =
            nodeId;

        ctx.neighborId =
            neighborId;

        ctx.sourceId =
            sourceNode;

        ctx.originId =
            key.originId;

        ctx.hopCount =
            state.depth;

        ctx.numNodes =
            numNodes;

        ctx.broadcastSeq =
            key.sequenceNo;

        ctx.config =
            attackConfig;

        AttackOutcome outcome =
            (malicious &&
             attackPolicy)
                ? attackPolicy->decide(ctx)
                : AttackOutcome{};

        if (malicious &&
            attackType != AttackType::Honest) {

            emit(
                maliciousSignal,
                1L
            );

            std::string attackName =
                AttackModel::toString(
                    attackType
                );

            collector()->recordMaliciousAction(
                key,
                nodeId,
                attackName.c_str()
            );
        }

        // --------------------------------------------------------
        // Optional metadata spoofing
        // --------------------------------------------------------
        if (malicious &&
            attackConfig.enableSpoofMetadata) {

            outcome.spoofMetadata = true;

            outcome.attackFlags |=
                ATTACK_FLAG_SPOOF;
        }

        // --------------------------------------------------------
        // Optional equivocation
        // --------------------------------------------------------
        if (malicious &&
            attackConfig.enableEquivocation) {

            outcome.equivocate = true;

            outcome.payloadVariantId =
                nodeId * 1000 +
                neighborId;

            outcome.attackFlags |=
                ATTACK_FLAG_EQUIVOCATION;
        }

        // --------------------------------------------------------
        // Attack decides to drop the transmission
        // --------------------------------------------------------
        if (outcome.drop) {

            emit(
                dropSignal,
                1L
            );

            collector()->recordDrop(
                key,
                nodeId,
                outcome.reason.c_str()
            );

            state.forwardAttempts.push_back({
                neighborId,
                false,
                outcome.extraDelay,
                outcome.reason
            });

            continue;
        }

        droppedAll = false;

        // --------------------------------------------------------
        // Metadata that will appear inside the outgoing packet
        // --------------------------------------------------------
        int senderId =
            outcome.spoofMetadata
                ? (
                    (nodeId + 7) %
                    std::max(
                        1,
                        numNodes
                    )
                  )
                : nodeId;

        int originId =
            outcome.spoofMetadata
                ? (
                    (key.originId + 13) %
                    std::max(
                        1,
                        numNodes
                    )
                  )
                : key.originId;

        sendToNeighbor(
            key,
            state,
            neighborId,
            senderId,
            originId,
            outcome
        );

        state.forwardAttempts.push_back({
            neighborId,
            true,
            outcome.extraDelay,
            outcome.reason
        });

        // --------------------------------------------------------
        // Additional duplicate transmissions for flood attack
        // --------------------------------------------------------
        for (int n = 0;
             n < outcome.duplicateBurst;
             ++n) {

            sendToNeighbor(
                key,
                state,
                neighborId,
                senderId,
                originId,
                outcome
            );
        }
    }

    // If candidates existed but every one was dropped, record the
    // aggregate event as well.
    if (droppedAll &&
        !selected.empty()) {

        emit(
            dropSignal,
            1L
        );

        collector()->recordDrop(
            key,
            nodeId,
            "all_candidates_dropped"
        );
    }

    state.forwarded = true;
    state.terminal = true;
}

void EpidemicNode::onReceive(
    EpidemicMessage *msg)
{
    BroadcastId key =
        keyFromPacket(msg);

    auto& state =
        stateByBroadcast[key];

    // ------------------------------------------------------------
    // Per-node acceptance limit
    // ------------------------------------------------------------
    if (!state.seen &&
        totalAcceptedBroadcasts >= maxMessages) {

        emit(
            dropSignal,
            1L
        );

        collector()->recordDrop(
            key,
            nodeId,
            "max_messages_limit"
        );

        delete msg;
        return;
    }

    const int senderId =
        msg->getSenderId();

    const int hopCount =
        msg->getHopCount();

    // ============================================================
    // FIRST RECEPTION
    // ============================================================
    if (!state.seen) {

        state.seen = true;

        state.parentId =
            senderId;

        state.depth =
            hopCount;

        state.firstSeenTime =
            simTime();

        state.commitDeadline =
            state.firstSeenTime +
            forwardDelay;

        state.forwardScheduled =
            true;

        state.acceptedParents.push_back(
            senderId
        );

        state.receptions.push_back({
            senderId,
            hopCount,
            simTime()
        });

        totalAcceptedBroadcasts++;

        emit(
            firstReceptionSignal,
            1L
        );

        /*
         * IMPORTANT PHASE 1 FIX:
         *
         * Successful first reception is what makes the node
         * "reached" for coverage purposes.
         *
         * Parent commitment remains a separate event handled later
         * by recordParentCommit().
         */
        collector()->recordFirstReception(
            key,
            nodeId,
            senderId,
            hopCount,
            simTime()
        );

        auto *event =
            new cMessage(
                "forwardBroadcast",
                KIND_FORWARD
            );

        event->addPar(
            "runId"
        ) = key.runId;

        event->addPar(
            "sessionId"
        ) = key.sessionId;

        event->addPar(
            "originId"
        ) = key.originId;

        event->addPar(
            "sequenceNo"
        ) = key.sequenceNo;

        scheduleAt(
            state.commitDeadline,
            event
        );

        delete msg;
        return;
    }

    // ============================================================
    // DUPLICATE RECEPTION
    // ============================================================
    state.duplicateCount++;

    state.receptions.push_back({
        senderId,
        hopCount,
        simTime()
    });

    emit(
        duplicateSignal,
        1L
    );

    collector()->recordDuplicate(
        key,
        nodeId
    );

    // ------------------------------------------------------------
    // While the commitment window is open, allow a better parent
    // candidate to replace the current one.
    // ------------------------------------------------------------
    if (!state.forwarded &&
        simTime() <= state.commitDeadline) {

        const bool betterDepth =
            hopCount < state.depth;

        const bool tieBreakSender =
            hopCount == state.depth &&
            senderId < state.parentId;

        if (betterDepth ||
            tieBreakSender) {

            state.rejectedParents.push_back(
                state.parentId
            );

            state.parentId =
                senderId;

            state.depth =
                hopCount;

            state.acceptedParents.push_back(
                senderId
            );
        }
        else {
            state.rejectedParents.push_back(
                senderId
            );
        }
    }

    delete msg;
}

void EpidemicNode::handleMessage(
    cMessage *msg)
{
    // ------------------------------------------------------------
    // Scheduled forwarding event
    // ------------------------------------------------------------
    if (msg->isSelfMessage() &&
        msg->getKind() == KIND_FORWARD) {

        BroadcastId key;

        key.runId =
            msg->par("runId");

        key.sessionId =
            msg->par("sessionId");

        key.originId =
            msg->par("originId");

        key.sequenceNo =
            msg->par("sequenceNo");

        processForwardEvent(
            key
        );

        delete msg;
        return;
    }

    // ------------------------------------------------------------
    // Broadcast trigger from ExperimentController
    // ------------------------------------------------------------
    if (msg->getKind() ==
        KIND_TRIGGER) {

        int sequenceNo =
            msg->par("seq");

        triggerBroadcast(
            sessionId,
            sequenceNo
        );

        delete msg;
        return;
    }

    // ------------------------------------------------------------
    // Network packet
    // ------------------------------------------------------------
    auto *packet =
        check_and_cast<EpidemicMessage *>(
            msg
        );

    onReceive(packet);
}
