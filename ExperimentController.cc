#include "ExperimentController.h"

#include <algorithm>
#include <cmath>
#include <numeric>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include "EpidemicNode.h"

Define_Module(ExperimentController);

enum {
    KIND_TRIGGER = 1
};

void ExperimentController::initialize(int stage)
{
    /*
     * Phase 1 uses two initialization stages.
     *
     * Stage 0:
     *   - Read experiment parameters
     *   - Select malicious nodes
     *   - Read attack configuration
     *
     * Stage 1:
     *   - Apply malicious/honest roles to EpidemicNode modules
     *   - Schedule broadcast triggers
     *
     * This prevents EpidemicNode::initialize() from overwriting
     * malicious-role configuration that was assigned too early.
     */

    if (stage == 0) {
        // ------------------------------------------------------------
        // Basic experiment parameters
        // ------------------------------------------------------------
        numNodes = par("numNodes");
        sourceNode = par("sourceNode");
        sessionId = par("sessionId");
        numBroadcasts = par("numBroadcasts");
        maliciousFraction = par("maliciousFraction");
        maliciousSeed = par("maliciousSeed");

        // ------------------------------------------------------------
        // Validate basic configuration
        // ------------------------------------------------------------
        if (numNodes <= 0) {
            throw cRuntimeError(
                "numNodes must be greater than 0, got %d",
                numNodes
            );
        }

        if (sourceNode < 0 || sourceNode >= numNodes) {
            throw cRuntimeError(
                "sourceNode=%d is outside the valid range [0, %d)",
                sourceNode,
                numNodes
            );
        }

        if (numBroadcasts < 0) {
            throw cRuntimeError(
                "numBroadcasts must be >= 0, got %d",
                numBroadcasts
            );
        }

        if (maliciousFraction < 0.0 ||
            maliciousFraction > 1.0) {
            throw cRuntimeError(
                "maliciousFraction must be in [0,1], got %g",
                maliciousFraction
            );
        }

        // ------------------------------------------------------------
        // Attack selection
        // ------------------------------------------------------------
        configuredAttack =
            AttackModel::parseAttackType(
                par("attackType").stdstringValue()
            );

        // ------------------------------------------------------------
        // Read attack configuration
        // ------------------------------------------------------------
        config.forwardProb =
            par("forwardProb");

        config.selectiveTargetFraction =
            par("selectiveTargetFraction");

        config.maxExtraDelay =
            par("maxExtraDelay");

        config.isolationMode =
            par("isolationMode").stdstringValue();

        config.isolatedPeers =
            AttackModel::parseNodeSet(
                par("isolatedPeerSet").stdstringValue(),
                numNodes
            );

        config.enableSpoofMetadata =
            par("enableSpoofMetadata");

        config.enableEquivocation =
            par("enableEquivocation");

        // ------------------------------------------------------------
        // Validate attack-specific parameters
        // ------------------------------------------------------------
        if (config.forwardProb < 0.0 ||
            config.forwardProb > 1.0) {
            throw cRuntimeError(
                "forwardProb must be in [0,1], got %g",
                config.forwardProb
            );
        }

        if (config.selectiveTargetFraction < 0.0 ||
            config.selectiveTargetFraction > 1.0) {
            throw cRuntimeError(
                "selectiveTargetFraction must be in [0,1], got %g",
                config.selectiveTargetFraction
            );
        }

        if (config.maxExtraDelay < SIMTIME_ZERO) {
            throw cRuntimeError(
                "maxExtraDelay must be >= 0, got %s",
                config.maxExtraDelay.str().c_str()
            );
        }

        // ------------------------------------------------------------
        // Determine malicious nodes
        // ------------------------------------------------------------
        const std::string fixed =
            par("fixedMaliciousNodes").stdstringValue();

        if (fixed.empty()) {
            maliciousNodes =
                sampleMaliciousNodes();
        }
        else {
            maliciousNodes =
                parseFixedMaliciousNodes(fixed.c_str());

            // The source must always remain honest.
            if (maliciousNodes.count(sourceNode) > 0) {
                throw cRuntimeError(
                    "sourceNode=%d cannot be listed as malicious "
                    "because the experiment requires an honest source",
                    sourceNode
                );
            }
        }

        return;
    }

    if (stage == 1) {
        // ------------------------------------------------------------
        // Apply roles only AFTER every EpidemicNode has initialized.
        // ------------------------------------------------------------
        for (int i = 0; i < numNodes; ++i) {
            auto *node =
                check_and_cast<EpidemicNode *>(
                    getParentModule()->getSubmodule("node", i)
                );

            const bool isMalicious =
                maliciousNodes.count(i) > 0;

            node->configureRole(
                isMalicious,
                isMalicious
                    ? configuredAttack
                    : AttackType::Honest,
                config
            );
        }

        // ------------------------------------------------------------
        // Schedule broadcasts only after node configuration is complete.
        // ------------------------------------------------------------
        const simtime_t firstAt =
            par("firstBroadcastAt");

        const simtime_t interval =
            par("broadcastInterval");

        for (int seq = 0;
             seq < numBroadcasts;
             ++seq) {

            auto *trigger =
                new cMessage(
                    "triggerBroadcast",
                    KIND_TRIGGER
                );

            trigger->addPar("seq") = seq;

            scheduleAt(
                firstAt + seq * interval,
                trigger
            );
        }

        return;
    }

    throw cRuntimeError(
        "Unexpected initialization stage %d",
        stage
    );
}

std::set<int>
ExperimentController::parseFixedMaliciousNodes(
    const char *spec
) const
{
    std::set<int> result;

    if (spec == nullptr)
        return result;

    std::stringstream ss(spec);
    std::string token;

    while (std::getline(ss, token, ',')) {
        if (token.empty())
            continue;

        try {
            std::size_t processed = 0;

            int id =
                std::stoi(
                    token,
                    &processed
                );

            // Reject tokens containing junk such as "4abc".
            if (processed != token.size()) {
                throw cRuntimeError(
                    "Invalid fixed malicious node specification '%s'",
                    token.c_str()
                );
            }

            if (id < 0 || id >= numNodes) {
                throw cRuntimeError(
                    "Fixed malicious node id %d is outside "
                    "the valid range [0,%d)",
                    id,
                    numNodes
                );
            }

            result.insert(id);
        }
        catch (const std::invalid_argument&) {
            throw cRuntimeError(
                "Invalid fixed malicious node id '%s'",
                token.c_str()
            );
        }
        catch (const std::out_of_range&) {
            throw cRuntimeError(
                "Fixed malicious node id '%s' is out of range",
                token.c_str()
            );
        }
    }

    return result;
}

std::set<int>
ExperimentController::sampleMaliciousNodes() const
{
    std::set<int> result;

    /*
     * Keep the source honest.
     *
     * Therefore the maximum possible number of malicious nodes
     * is numNodes - 1.
     */
    const int maximumMalicious =
        std::max(0, numNodes - 1);

    int wanted =
        static_cast<int>(
            std::round(
                maliciousFraction * numNodes
            )
        );

    wanted =
        std::max(
            0,
            std::min(
                maximumMalicious,
                wanted
            )
        );

    // A zero malicious fraction must select no malicious nodes.
    if (wanted == 0)
        return result;

    // Create node IDs [0, numNodes).
    std::vector<int> ids(numNodes);

    std::iota(
        ids.begin(),
        ids.end(),
        0
    );

    // Deterministic sampling for reproducible experiments.
    std::mt19937 rng(
        static_cast<std::mt19937::result_type>(
            maliciousSeed
        )
    );

    std::shuffle(
        ids.begin(),
        ids.end(),
        rng
    );

    for (int id : ids) {
        if (id == sourceNode)
            continue;

        result.insert(id);

        if (static_cast<int>(result.size()) >= wanted)
            break;
    }

    return result;
}

void ExperimentController::handleMessage(cMessage *msg)
{
    if (msg->getKind() == KIND_TRIGGER) {
        const int seq =
            msg->par("seq");

        auto *source =
            check_and_cast<EpidemicNode *>(
                getParentModule()->getSubmodule(
                    "node",
                    sourceNode
                )
            );

        source->triggerBroadcast(
            sessionId,
            seq
        );
    }

    delete msg;
}
