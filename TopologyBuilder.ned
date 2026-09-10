simple TopologyBuilder
{
    parameters:
        int numNodes;
        int sourceNode;
        string topologyMode = default("complete");
        double erProbability = default(0.1);
        int fixedDegree = default(4);
        string graphFile = default("");
        double linkDelay @unit(s) = default(1ms);
        @display("i=block/process");
}
