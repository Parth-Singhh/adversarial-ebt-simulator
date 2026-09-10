#ifndef __ADVERSARIAL_EBT_BROADCASTID_H
#define __ADVERSARIAL_EBT_BROADCASTID_H

#include <cstddef>
#include <string>

struct BroadcastId {
    int sessionId = 0;
    int originId = -1;
    int sequenceNo = 0;

    bool operator==(const BroadcastId& other) const {
        return sessionId == other.sessionId &&
               originId == other.originId &&
               sequenceNo == other.sequenceNo;
    }

    std::string toString() const {
        return "s" + std::to_string(sessionId) +
               "_o" + std::to_string(originId) +
               "_b" + std::to_string(sequenceNo);
    }
};

struct BroadcastIdHash {
    std::size_t operator()(const BroadcastId& id) const {
        std::size_t h1 = std::hash<int>{}(id.sessionId);
        std::size_t h2 = std::hash<int>{}(id.originId);
        std::size_t h3 = std::hash<int>{}(id.sequenceNo);
        return h1 ^ (h2 << 1) ^ (h3 << 2);
    }
};

#endif
