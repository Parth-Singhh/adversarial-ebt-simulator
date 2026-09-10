packet EpidemicMessage
{
    int messageId;
    int originId;
    int senderId;
    int hopCount;
    simtime_t creationTime;
}
