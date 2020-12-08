/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/***
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface, int nat_flag)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  // print_hdr_eth(ntohl(iface->ip));
  // std::cout<<<<"\n";
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  std::cerr << getRoutingTable() << std::endl;

  // FILL THIS IN
  uint8_t *buffer = (uint8_t *) packet.data();
  ethernet_hdr* ethernetHeader = (ethernet_hdr*)buffer;
  print_hdrs(packet);
  // print_hdr_eth(buffer);
  std::cout << "Ethernet type: " << ntohs(ethernetHeader->ether_type) << std::endl;
  // handle arp packet
  if (ethertype(buffer) == ethertype_arp)
  {
    printf("Handling ARP packet.............................\n");
    uint8_t *payload = buffer + (int) sizeof(ethernet_hdr);
    // print_hdr_arp(payload);
    arp_hdr *arp_header = (arp_hdr*)payload;
    if (ntohs(arp_header->arp_op)==1){
      // std::cout<<"hehe "<<ntohs(arp_header->arp_op);
      handleARPRequest(arp_header, ethernetHeader);
    }
    // the packet is ARP reply 
    else {
      handleARPReply(arp_header, ethernetHeader);
    }
    printf("======================================================\n");
  }
  // handle ip packet
  if (ethertype(buffer) == ethertype_ip){
    printf("Handling IP packet...............................\n");
    uint8_t *payload = buffer + (int) sizeof(ethernet_hdr);
    
    ip_hdr *ip_header = (ip_hdr*)payload;
    // print_hdr_ip(payload);
    //checksum
    uint16_t original_cksum = ip_header->ip_sum;
    ip_header->ip_sum = 0;
    uint16_t calculate_cksum = cksum(ip_header,sizeof(ip_hdr));
    //if correct, handle IP packet
    
    if (calculate_cksum==original_cksum){
      ip_header->ip_sum = calculate_cksum;
      // check valid length
      // printf("%d - %d\n",ip_header->ip_len,(sizeof(ethernet_hdr)+sizeof(ip_hdr)));
      if (ip_header->ip_len >= (sizeof(ethernet_hdr)+(int)sizeof(ip_hdr))){
        handleIPPacket(packet,inIface);
      }
      // invalid packet length
      else printf("Invalid Length\n");
    }
    //else, print out error
    else {
      printf("IP Checksum Error\n");
    }
    printf("====================================================\n");
  }

}

void
SimpleRouter::handleIPPacket(const Buffer& packet,const std::string& inIface){
  //check if the target is the router
  // printf("Handling IP packet...\n");
  // look for interface with target ip
  ip_hdr *iphd = getIPHeader(packet);
  const Interface* looking_interface = findIfaceByIp(iphd->ip_dst);
  // if it is, handle ICPP or NAT
  if (looking_interface != NULL){
    // If IMCP packet?
    if (iphd->ip_p == 0x01){ // IMCP packet
      handleICMPPacket(packet,inIface);
    } else { //Handle NAT
      // Handle NAT
    }
  }
  // if the router is not the target, foward the packet
  else {
    // forward the packet
    forwardPacket(packet,inIface);
  }
  return;
}

void 
SimpleRouter::forwardPacket(const Buffer& packet,const std::string& inIface){
  printf("Forwarding the ip packet..............................\n");
  Buffer sending_packet = std::vector<unsigned char>(packet.size(), 0);
  memcpy(&sending_packet[0],&packet[0],packet.size());
  ip_hdr *iphd = getIPHeader(packet);
  uint8_t ttl = iphd->ip_ttl;
  ttl--;
  // check ttl
  if (ttl>0){
    try {
      // look for next hop
      RoutingTableEntry routing_entry = getRoutingTable().lookup(iphd->ip_dst);
      // look for dest mac in arp cache
      std::shared_ptr<ArpEntry> arpent = m_arp.lookup(routing_entry.gw);
      // if the dist ip in ARP cache
      if (arpent != nullptr){
        // forward the packet
        // set ethernet header
        memcpy(&sending_packet[ETHER_ADDR_LEN],&sending_packet[0],ETHER_ADDR_LEN);
        memcpy(&sending_packet[0],&arpent->mac[0],ETHER_ADDR_LEN);

        // set ip header
        ip_hdr *sending_iphd = getIPHeader(sending_packet);
        sending_iphd->ip_ttl = ttl;
        sending_iphd->ip_sum = 0;
        uint16_t calculate_cksum = cksum(sending_iphd,sizeof(ip_hdr));
        sending_iphd->ip_sum = calculate_cksum;
        printf("Forwarding................!\n");
        print_hdrs(sending_packet);
        sendPacket(sending_packet,routing_entry.ifName);

      } else { // if the dist ip not in ARP cache
        printf("Sending ARP request.........\n");
        // make ARP request
        m_arp.queueRequest(routing_entry.gw, packet,routing_entry.ifName);
      }
    } catch (std::runtime_error& error) {

    }

  } else {
    printf("Stop forwarding ..... TTL=0\n");
  }
}

void
SimpleRouter::handleICMPPacket(const Buffer& packet,const std::string& inIface){
  // printf("Handling ICMP packet......!");
  const Interface* inIF = findIfaceByName(inIface);
  icmp_hdr *icmphd = getICMPHeader(packet);
  // check sum for icmp
  uint16_t original_cksum = icmphd->icmp_sum;
  icmphd->icmp_sum = 0;
  uint16_t calculate_cksum = cksum(icmphd,packet.size()-sizeof(ethernet_hdr)-sizeof(ip_hdr));
  // printf("%d - %d\n",original_cksum,calculate_cksum);
  //if correct, handle IP packet
  if (calculate_cksum==original_cksum){
    if (icmphd->icmp_type == 8){ //echo message
      // create reply packet and send back to the interface that receive the packet
      Buffer sending_packet = std::vector<unsigned char>(packet.size(), 0);
      memcpy(&sending_packet[0],&packet[0],packet.size());

      // set ethernet header
      memcpy(&sending_packet[0],&packet[ETHER_ADDR_LEN],ETHER_ADDR_LEN);
      memcpy(&sending_packet[ETHER_ADDR_LEN],&inIF->addr[0],ETHER_ADDR_LEN);

      // set ip header
      ip_hdr* ip_reply_hd = getIPHeader(sending_packet);
      ip_hdr* iphd = getIPHeader(packet);
      memcpy(&ip_reply_hd->ip_dst,&iphd->ip_src,sizeof(ip_reply_hd->ip_dst));
      memcpy(&ip_reply_hd->ip_src,&iphd->ip_dst,sizeof(ip_reply_hd->ip_dst));
      ip_reply_hd->ip_sum = 0;
      uint16_t calculate_cksum = cksum(ip_reply_hd,sizeof(ip_hdr));
      ip_reply_hd->ip_sum = calculate_cksum;

      // set icmp header
      icmp_hdr* icmp_reply_hd = getICMPHeader(sending_packet);
      icmp_reply_hd->icmp_type = 0;
      icmp_reply_hd->icmp_sum = 0;
      uint16_t calculate_icmp_cksum = cksum(icmp_reply_hd,sending_packet.size()-sizeof(ethernet_hdr)-sizeof(ip_hdr));
      icmp_reply_hd->icmp_sum = calculate_icmp_cksum;
      //set checksum for icmp header
      //set checksum for ip header
      // printf("received................!\n");
      // print_hdrs(packet);
      // printf("sending................!\n");
      // print_hdrs(sending_packet);
      sendPacket(sending_packet, inIF->name);
      //look for the 

    } 
  } else {
    printf("ICMP Checksum Error...........\n");
  }
  
}

ip_hdr* SimpleRouter::getIPHeader(const Buffer& packet){
  uint8_t *buffer = (uint8_t *) packet.data();
  uint8_t *payload = buffer + (int) sizeof(ethernet_hdr);
  return (ip_hdr*) payload;
}

icmp_hdr* SimpleRouter::getICMPHeader(const Buffer& packet){
  uint8_t *buffer = (uint8_t *) packet.data();
  uint8_t *payload = buffer + (int) sizeof(ethernet_hdr) + (int) sizeof(ip_hdr);
  return (icmp_hdr*) payload;
}

void
SimpleRouter::handleARPRequest(arp_hdr *arphdr, ethernet_hdr* ethernetHeader){
  // find existing entry of source ip
  printf("Handling ARP request ................\n");
  std::shared_ptr<simple_router::ArpEntry> arp_entry;
  arp_entry = m_arp.lookup(arphdr->arp_sip);
  // if not found, add new entry for source IP
  if (arp_entry == NULL){
    // create a new ARP entry
    printf("Have not seen this IP in cache.... insert new ARP entry\n");
    Buffer mac = std::vector<unsigned char>(6, 0);
    memcpy(&mac[0], &(ethernetHeader->ether_shost), ETHER_ADDR_LEN);
    m_arp.insertArpEntry(mac,arphdr->arp_sip);
    // std::cout<<mac[0]<<" "<< arphdr->arp_sip;
  }
  // check if the looking IP is any interface in the router
  // print_addr_ip_int(arphdr->arp_tip);
  const Interface *looking_interf = findIfaceByIp(arphdr->arp_tip);
  // if it is, send an ARP reply
  if (looking_interf != nullptr){
    //create ARP reply packet
    Buffer reply_packet = std::vector<unsigned char>(42, 0);
    //set ethenet header
    // ethernet_hdr* new_ethernet_header = (ethernet_hdr*) malloc(sizeof(ethernet_hdr));
    memcpy(ethernetHeader->ether_dhost, &(ethernetHeader->ether_shost), ETHER_ADDR_LEN);
    memcpy(ethernetHeader->ether_shost, &looking_interf->addr[0], ETHER_ADDR_LEN);
    // memcpy(&(new_ethernet_header->ether_type), &(ethernetHeader->ether_type), sizeof(uint16_t));
    //set arp header
    // arp_hdr* new_arp_header = (arp_hdr*) malloc(sizeof(arp_hdr));  
    memcpy(&arphdr->arp_tip,&arphdr->arp_sip,sizeof(arphdr->arp_tip));
    memcpy(&arphdr->arp_sip,&looking_interf->ip,sizeof(arphdr->arp_sip));
    memcpy(&arphdr->arp_tha,&arphdr->arp_sha,sizeof(arphdr->arp_sha));
    memcpy(&arphdr->arp_sha,&looking_interf->addr[0],sizeof(arphdr->arp_sha));
    arphdr->arp_op = htons(0x0002);
    memcpy(&reply_packet[0],ethernetHeader,sizeof(ethernet_hdr));
    memcpy(&reply_packet[sizeof(ethernet_hdr)],arphdr,sizeof(arp_hdr));
    // uint8_t *buffer = (uint8_t *) reply_packet.data();
    // uint8_t *payload = (uint8_t*)new_arp_header;
    // print_hdr_arp(payload);
    printf("Sending a reply packet via.......... %s\n",(looking_interf->name).c_str());
    print_hdrs(reply_packet);
    sendPacket(reply_packet, looking_interf->name);
    //send ARP reply packet to the interface that the ARP packet is coming
  }
  // else, drop the ARP packet (do nothing)
  return;
}



void 
SimpleRouter::handleARPReply(const arp_hdr *arphd, const ethernet_hdr* ethernetHeader){
  //check if the ip and MAC address are in ARP cache
  std::shared_ptr<simple_router::ArpEntry> arp_entry = m_arp.lookup(arphd->arp_sip);
  //if not found, store in ARP cache and send out all pending packages
  printf("Handling ARP reply.......................\n");
  if (arp_entry == NULL){
    printf("Insert new ARP entry to ARP cache..........\n");
    Buffer mac_address = std::vector<unsigned char>(6, 0);
    memcpy(&mac_address[0],&ethernetHeader->ether_shost[0],ETHER_ADDR_LEN);
    m_arp.insertArpEntry(mac_address,arphd->arp_sip);

    //send out all pending packet
    m_arp.send_out_all_pending_packets(arphd->arp_sip,arphd);
  }
  //else do nothing 
  else {
    printf("Already have ARP entry..........\n");
    //do nothing
  }
  
  return;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
  , m_natTable(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}


} // namespace simple_router {
