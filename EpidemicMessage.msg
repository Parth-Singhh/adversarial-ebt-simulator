packet EpidemicMessage
{
    int runId;
    int sessionId;
    int broadcastSeq;
    int originId;
    int senderId;
    int hopCount;
    int64 globalBroadcastId;
    int parentCandidateId;
    simtime_t creationTime;
    simtime_t firstSeenAtSender;
    int attackFlags;
    int payloadVariantId;
    bool spoofed;
}
