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
                numNodes = numNodes;
                sourceNode = sourceNode;
                @display("p=120,40");
        }

        controller: ExperimentController {
            parameters:
                numNodes = numNodes;
                sourceNode = sourceNode;
                sessionId = sessionId;
                numBroadcasts = numBroadcasts;
                firstBroadcastAt = firstBroadcastAt;
                broadcastInterval = broadcastInterval;
                maliciousFraction = maliciousFraction;
                maliciousSeed = maliciousSeed;
                fixedMaliciousNodes = fixedMaliciousNodes;
                attackType = attackType;
                @display("p=320,40");
        }

        topologyBuilder: TopologyBuilder {
            parameters:
                numNodes = numNodes;
                sourceNode = sourceNode;
                topologyMode = topologyMode;
                erProbability = erProbability;
                fixedDegree = fixedDegree;
                graphFile = graphFile;
                linkDelay = linkDelay;
                @display("p=520,40");
        }

        node[numNodes]: EpidemicNode {
            parameters:
                nodeId = index;
                numNodes = numNodes;
                attackType = attackType;
                @display("p=100+uniform(0,700),140+uniform(0,450)");
        }
}
