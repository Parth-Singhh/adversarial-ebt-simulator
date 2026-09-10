#ifndef __ADVERSARIAL_EBT_BROADCASTID_H
#define __ADVERSARIAL_EBT_BROADCASTID_H

#include <cstddef>
#include <cstdint>
#include <sstream>
#include <string>

struct BroadcastId {
    int runId = 0;
    int sessionId = 0;
    int originId = -1;
    int sequenceNo = 0;

    bool operator==(const BroadcastId& other) const {
        return runId == other.runId &&
               sessionId == other.sessionId &&
               originId == other.originId &&
               sequenceNo == other.sequenceNo;
    }

    std::string toString() const {
        return "r" + std::to_string(runId) +
               "_s" + std::to_string(sessionId) +
               "_o" + std::to_string(originId) +
               "_b" + std::to_string(sequenceNo);
    }

    static BroadcastId fromString(const std::string& encoded) {
        BroadcastId id;
        char r, s, o, b, us1, us2, us3;
        std::stringstream ss(encoded);
        if (ss >> r >> id.runId >> us1 >> s >> id.sessionId >> us2 >> o >> id.originId >> us3 >> b >> id.sequenceNo) {
            if (r == 'r' && us1 == '_' && s == 's' && us2 == '_' && o == 'o' && us3 == '_' && b == 'b')
                return id;
        }
        return BroadcastId{};
    }

    int64_t globalId() const {
        int64_t value = (int64_t(runId & 0xFFFF) << 48) |
                        (int64_t(sessionId & 0xFFFF) << 32) |
                        (int64_t(originId & 0xFFFF) << 16) |
                        int64_t(sequenceNo & 0xFFFF);
        return value;
    }
};

struct BroadcastIdHash {
    std::size_t operator()(const BroadcastId& id) const {
        std::size_t h0 = std::hash<int>{}(id.runId);
        std::size_t h1 = std::hash<int>{}(id.sessionId);
        std::size_t h2 = std::hash<int>{}(id.originId);
        std::size_t h3 = std::hash<int>{}(id.sequenceNo);
        return h0 ^ (h1 << 1) ^ (h2 << 2) ^ (h3 << 3);
    }
};

#endif
