network EpidemicBroadcastTree
{
    parameters:
        int numNodes = default(50);
        int sourceNode = default(0);
        @display("bgb=900,650");
    submodules:
        node[numNodes]: EpidemicNode {
            parameters:
                nodeId = index;
                isSource = (index == sourceNode);
                numNodes = numNodes;
                @display("p=100+uniform(0,700),100+uniform(0,500)");
        }
    connections allowunconnected:
        for i=0..numNodes-1, for j=i+1..numNodes-1 {
            node[i].port++ <--> { delay = 1ms; datarate = 1Gbps; } <--> node[j].port++;
        }
}
