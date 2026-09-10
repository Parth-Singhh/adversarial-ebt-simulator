# Epidemic Broadcast Tree — OMNeT++

A self-contained OMNeT++ simulation of an epidemic (gossip-style) broadcast protocol
that builds a broadcast tree rooted at the original source.

The model does not require INET. Nodes communicate through a fully connected
wireless-like overlay, while the network topology is generated from the NED model.

## Tested design target
OMNeT++ 6.x / modern OMNeT++ versions using C++17.

## Model behavior

1. A source node creates a broadcast message.
2. Nodes receiving a message for the first time adopt the sender as their parent.
3. Each newly infected node gossips the message to a configurable number of
   randomly selected neighbors (`fanout`).
4. Duplicate receptions are ignored.
5. The first sender becomes the parent, producing an epidemic broadcast tree.
6. Simulation statistics include:
   - number of nodes reached
   - duplicate receptions
   - total transmissions
   - tree edges
   - tree depth
   - coverage ratio
   - completion time

## Build

Create an OMNeT++ project and add:

- `EpidemicBroadcastTree.ned`
- `EpidemicNode.ned`
- `EpidemicNode.cc`
- `EpidemicNode.h`
- `EpidemicMessage.msg`
- `omnetpp.ini`

Compile and run `General` from the OMNeT++ IDE.

## Important parameters

In `omnetpp.ini`:

network size:
    **numNodes**

source:
    **sourceNode**

gossip fanout:
    **fanout**

per-hop delay:
    **gossipDelay**

time before a node forwards:
    **forwardDelay**

maximum simulation time:
    **sim-time-limit**

Example:
    numNodes = 100
    fanout = 4
    forwardDelay = 0.01s
    gossipDelay = 1ms

## Extending the model

The implementation is deliberately independent of INET so that it can be used as
a research baseline. You can later replace the overlay links with UDP/IP, wireless
channels, mobility, packet loss, energy models, or an INET-based implementation.
