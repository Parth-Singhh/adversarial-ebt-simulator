simple ExperimentController
{
    parameters:
        int numNodes;
        int sourceNode;
        int sessionId = default(1);
        int numBroadcasts = default(1);
        double firstBroadcastAt @unit(s) = default(0s);
        double broadcastInterval @unit(s) = default(100ms);
        double maliciousFraction = default(0);
        int maliciousSeed = default(1);
        string fixedMaliciousNodes = default("");
        string attackType = default("honest");
        @display("i=block/control");
}
