simple ExperimentController
{
    parameters:
        // ------------------------------------------------------------
        // Core experiment configuration
        // ------------------------------------------------------------
        int numNodes;
        int sourceNode;

        int sessionId = default(1);
        int numBroadcasts = default(1);

        double firstBroadcastAt @unit(s) = default(0s);
        double broadcastInterval @unit(s) = default(100ms);

        // ------------------------------------------------------------
        // Malicious-node configuration
        // ------------------------------------------------------------
        double maliciousFraction = default(0);
        int maliciousSeed = default(1);
        string fixedMaliciousNodes = default("");

        string attackType = default("honest");

        // ------------------------------------------------------------
        // Attack parameters
        //
        // These are read by ExperimentController in initialization
        // stage 0 and passed to the selected malicious nodes in
        // initialization stage 1.
        // ------------------------------------------------------------
        double forwardProb = default(1.0);
        double selectiveTargetFraction = default(0.5);

        double maxExtraDelay @unit(s) = default(0s);

        string isolationMode = default("none");
        string isolatedPeerSet = default("");

        bool enableSpoofMetadata = default(false);
        bool enableEquivocation = default(false);

        @display("i=block/control");
}