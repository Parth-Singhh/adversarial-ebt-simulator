network EpidemicBroadcastTree
{
    parameters:
        int numNodes = default(50);
        int sourceNode = default(0);

        string topologyMode = default("complete");
        double erProbability = default(0.1);
        int fixedDegree = default(4);
        string graphFile = default("");
        double linkDelay @unit(s) = default(1ms);

        int sessionId = default(1);
        int numBroadcasts = default(1);
        double firstBroadcastAt @unit(s) = default(0s);
        double broadcastInterval @unit(s) = default(100ms);

        double maliciousFraction = default(0);
        int maliciousSeed = default(1);
        string fixedMaliciousNodes = default("");
        string attackType = default("honest");

        @display("bgb=900,650");

    submodules:
        collector: StatsCollector {
            parameters:
                numNodes = parent.numNodes;
                sourceNode = parent.sourceNode;
                @display("p=120,40");
        }

        controller: ExperimentController {
            parameters:
                numNodes = parent.numNodes;
                sourceNode = parent.sourceNode;
                sessionId = parent.sessionId;
                numBroadcasts = parent.numBroadcasts;
                firstBroadcastAt = parent.firstBroadcastAt;
                broadcastInterval = parent.broadcastInterval;
                maliciousFraction = parent.maliciousFraction;
                maliciousSeed = parent.maliciousSeed;
                fixedMaliciousNodes = parent.fixedMaliciousNodes;
                attackType = parent.attackType;
                @display("p=320,40");
        }

        topologyBuilder: TopologyBuilder {
            parameters:
                numNodes = parent.numNodes;
                sourceNode = parent.sourceNode;
                topologyMode = parent.topologyMode;
                erProbability = parent.erProbability;
                fixedDegree = parent.fixedDegree;
                graphFile = parent.graphFile;
                linkDelay = parent.linkDelay;
                @display("p=520,40");
        }

        node[numNodes]: EpidemicNode {
		parameters:
                nodeId = index;
                numNodes = parent.numNodes;
                sessionId = parent.sessionId;
                @display("p=,,m,10,70,50;i=device/server");
}
}