simple EpidemicNode
{
    parameters:
        int nodeId;
        int numNodes;
        int fanout = default(3);
        double forwardDelay @unit(s) = default(10ms);
        double gossipDelay @unit(s) = default(1ms);
        int maxMessages = default(1000);
        bool isMalicious = default(false);
        string attackType = default("honest");
        double maliciousJitterMax @unit(s) = default(50ms);
        @display("i=device/server");
    gates:
        inout port[];
}
