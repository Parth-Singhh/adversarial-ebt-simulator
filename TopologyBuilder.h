#ifndef __ADVERSARIAL_EBT_TOPOLOGYBUILDER_H
#define __ADVERSARIAL_EBT_TOPOLOGYBUILDER_H

#include <omnetpp.h>
#include <set>
#include <utility>
#include <vector>

using namespace omnetpp;

class TopologyBuilder : public cSimpleModule
{
  protected:
    int numNodes = 0;
    int sourceNode = 0;

    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;

    std::set<std::pair<int, int>> buildEdgeSet() const;
    std::set<std::pair<int, int>> buildComplete() const;
    std::set<std::pair<int, int>> buildErdosRenyi(double p) const;
    std::set<std::pair<int, int>> buildFixedDegree(int degree) const;
    std::set<std::pair<int, int>> buildFromFile(const std::string& path) const;

    void connectEdges(const std::set<std::pair<int, int>>& edges);
    void computeTopologyStats(const std::set<std::pair<int, int>>& edges,
                              std::vector<int>& degrees,
                              int& componentCount,
                              int& sourceComponentSize) const;
};

#endif
