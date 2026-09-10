simple EpidemicNode
{
    parameters:
        int nodeId;
        int numNodes;
        bool isSource = default(false);
        int fanout = default(3);
        double forwardDelay @unit(s) = default(10ms);
        double gossipDelay @unit(s) = default(1ms);
        int maxMessages = default(1000);
        @display("i=device/server");
        gates:
            input port[];
            output port[];
}
