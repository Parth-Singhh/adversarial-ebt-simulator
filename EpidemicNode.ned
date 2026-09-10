simple EpidemicNode
{
    parameters:
        int nodeId;
        int numNodes;
        int runId = default(0);
        int sourceNode = default(0);
        int fanout = default(3);
        double forwardDelay @unit(s) = default(10ms);
        double gossipDelay @unit(s) = default(1ms);
        int maxMessages = default(1000);

        double forwardProb = default(0.7);
        double selectiveTargetFraction = default(0.5);
        double maxExtraDelay @unit(s) = default(50ms);
        string isolationMode = default("none");
        string isolatedPeerSet = default("");
        bool enableSpoofMetadata = default(false);
        bool enableEquivocation = default(false);

        @display("i=device/server");
    gates:
        inout port[];
}
