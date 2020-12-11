UCLA CS118 Project (Simple Router)
====================================

Huy Nguyen - 005358560

## High level design

- Parse Ethernet header of the received packet
- Check Ethernet type (ARP or IP?)
    - If the packet is APR packet
        - If it is an ARP request
        - If it is an ARP reply
    - If the packet is IP packet
        -  Verify checksum and length (if not valid, drop the packet)
        - If the destination is at router
            - If the packet is ICMP echo
                - Verify ICMP checksum (if not valid, drop the packet)
                - Send ICMP echo reply to the incoming interface
            - if the packet is ICMP reply
                - If NAT mode is enabled
                    - If IMCP id in NAT table and dstIP == enternal IP
                        - Translate dest IP to internal IP
                        - Update TTL and checksum
                        - If the next hop addr not in ARP table, queue a ARP request
                        - If the next hop addr is in ARP table, forward the packet
                    - Else, drop the packet
                - If NAT mode is disabled, drop the packet, drop the packet

        - If the destination is not at router
            - If NAT is enable and srcIP==internalIP
                - Translate srcIP to externalIP
            - Update TTL and checksum
            - If the next hop addr not in ARP table, queue a ARP request
            - If the next hop addr is in ARP table, forward the packet

## Difficulties

There are some difficulties that I faced while implementing the simple router:
- It took a long time to understand the given structure of the project. To overcome this problem, I watched the lecture several times, then watched the discussion before jumping into the project
- It was hard to visualize the IP addresses and MAC addresses to debug whatever packed into the headers. After reading post on piazza, I realized that there is a file named utilis.cpp that has all implementation to print out the headers of the received packet
