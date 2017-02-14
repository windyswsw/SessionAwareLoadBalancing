# SessionAwareLoadBalancing

This project presents a load balancing approach for Virtualized Network Functions (VNFs) that controls sessions, using consistent hashing techniques.
We assume a Load Balancer process which is implemented as a VNF, and is responsible for distribute the traffic over multiple VNF instances, while maintaining the session affinity of the traffic.

The Load Balancer VNF is built over two main models:
(1) Packet capturing model (Capture the packets coming to Load Balancer VNF and extract information about the session)
(2) Consistent hashing function that decide to which VNF a packet should be forwarded to

We assume a Software Defined Network (SDN) based network to implement the proposed load balancing approach.
