## Session Aware Load Balancing for Virtualized Network Functions (VNFs)

Network Function Virtualization (NFV) is a promising technology that proposes to move network-based services (firewalls, proxies etc.) from dedicated hardware middle-boxes to software running on commodity servers: Virtualized Network Functions (VNFs). According to the capacity of VNFs, to process a specific traffic workload, one instance of a VNF might not be enough. In that case, multiple instances of VNF have to be deployed and the traffic workload has to distributed across the multiple VNF instances.

Unlike layer 3 forwarding, many VNFs such as firewall, proxy, and VPN perform stateful packet processing: session based packet processing. Therefore, these VNFs require affinity, where traffic for a given session must reach the instance that holds that session's state. In such cases, splitting traffic to balance the load, requires extra measures to preserve session affinity.

This project presents a load balancing approach for VNFs that controls sessions, using consistent hashing techniques. We assume a Load Balancer process which is implemented as a VNF, and is responsible for distribute the traffic over multiple VNF instances, while maintaining the session affinity of the traffic.

The Load Balancer VNF is built over three main modules:

1. Packet capturing module (Capture the packets coming to Load Balancer VNF and extract information about the session)
2. Consistent hashing function module (Decide to which VNF a packet should be forwarded to, based on the session of the packet)
3. Tag inserting module (Insert a VLAN tag to the packet, which represents the VNF that the packet should be forwarded to

We assume a Software Defined Network (SDN) based network to implement the proposed load balancing approach.

##Project Structure:

1. Packet capturing and tag inserting program
2. Consistent hashing function program
3. Example SDN network configuration for mininet simulator
