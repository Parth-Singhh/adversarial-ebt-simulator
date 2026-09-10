packet EpidemicMessage
{
    int sessionId;
    int broadcastSeq;
    int originId;
    int senderId;
    int hopCount;
    simtime_t creationTime;
    int attackTag;
    bool spoofed;
}
