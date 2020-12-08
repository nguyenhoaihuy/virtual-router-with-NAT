/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
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

#include "arp-cache.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
ArpCache::periodicCheckArpRequestsAndCacheEntries()
{
  // actually send ARP request
  // int count = 0;
  for (std::list<std::shared_ptr<ArpRequest>>::iterator req = m_arpRequests.begin(); req != m_arpRequests.end();) {
    
      if (steady_clock::now() - (*req)->timeSent > seconds(1)) {
          printf("Sending ARP packet ...!\n");
          // check less than 5 times
          // std::shared_ptr<ArpEntry> arpent = lookup((*req)->ip);
          if ((*req)->nTimesSent < 5){ 
            // actually send the ARP request
            //create ARP request packet
            Buffer arp_request_packet = std::vector<unsigned char>(42, 0);
            RoutingTableEntry routing_entry = m_router.getRoutingTable().lookup((*req)->ip);
            const Interface* inIF = m_router.findIfaceByName(routing_entry.ifName);
            //set ethenet header
            ethernet_hdr *eth_header = (ethernet_hdr*) malloc(sizeof(ethernet_hdr));
            arp_hdr *arp_header = (arp_hdr*) malloc(sizeof(arp_hdr));
            memset(eth_header->ether_dhost, 255, ETHER_ADDR_LEN);
            memcpy(eth_header->ether_shost, &inIF->addr[0], ETHER_ADDR_LEN);
            eth_header->ether_type = htons(0x0806);
            //set arp header
            // arp_hdr* new_arp_header = (arp_hdr*) malloc(sizeof(arp_hdr));  
            memcpy(&arp_header->arp_tip,&(*req)->ip,sizeof(arp_header->arp_tip));
            memcpy(&arp_header->arp_sip,&inIF->ip,sizeof(arp_header->arp_sip));
            memset(arp_header->arp_tha,255,sizeof(arp_header->arp_sha));
            memcpy(&arp_header->arp_sha,&inIF->addr[0],sizeof(arp_header->arp_sha));
            arp_header->arp_op = htons(0x0001);
            arp_header->arp_hrd = htons(0x0001);
            arp_header->arp_pro = htons(0x0800);
            arp_header->arp_hln = 6;
            arp_header->arp_pln = 4;
            //
            memcpy(&arp_request_packet[0],eth_header,sizeof(ethernet_hdr));
            memcpy(&arp_request_packet[sizeof(ethernet_hdr)],arp_header,sizeof(arp_hdr));
            // uint8_t *buffer = (uint8_t *) reply_packet.data();
            // uint8_t *payload = (uint8_t*)new_arp_header;
            // print_hdr_arp(payload);
            printf("Sending a ARP request packet via ......%s\n",(inIF->name).c_str());
            m_router.sendPacket(arp_request_packet, inIF->name);
            print_hdrs(arp_request_packet);
            (*req)->timeSent = steady_clock::now();
            (*req)->nTimesSent++;
            ++req;
          } else { // remove the ARP request
            req=m_arpRequests.erase(req);
          }
      } else {//remove the ARP request
        req=m_arpRequests.erase(req);
      }
  }


  for (std::list<std::shared_ptr<ArpEntry>>::iterator entry = m_cacheEntries.begin(); entry != m_cacheEntries.end();) {
      // count++;
      // printf("ip:.............%s\n",ipToString((*entry)->ip).c_str());
      if (!((*entry)->isValid)){
        // printf("erease.............................%d.!\n",count);
        entry = m_cacheEntries.erase(entry);
      } else {
        ++entry;
      }
  }
  // printf("Number of request = %d.........\n",count);

  //
  // FILL THIS IN

}

void 
ArpCache::send_out_all_pending_packets(uint32_t tip,const struct arp_hdr *replying_arp_hdr){
  // Find pending request
  std::shared_ptr<ArpRequest> pending_request = nullptr;
  for (const auto& arp_request : m_arpRequests){
    if (arp_request->ip == tip){
      pending_request = arp_request;
      break;
    }
  }
  // send all packets in the pending request
  // check if any request relate to arp
  // if so, send all packets to the target
  if (pending_request!=NULL){
    printf("Sending all pending packets\n");
    for (const auto& packet : pending_request->packets){
      // make sending packet
      Buffer sending_packet = std::vector<unsigned char>(packet.packet.size(), 0);
      ethernet_hdr* new_ethernet_header = (ethernet_hdr*) malloc(sizeof(ethernet_hdr));
      memcpy(new_ethernet_header->ether_shost, &replying_arp_hdr->arp_tha[0], ETHER_ADDR_LEN);
      memcpy(new_ethernet_header->ether_dhost, &replying_arp_hdr->arp_sha[0], ETHER_ADDR_LEN);
      new_ethernet_header->ether_type = htons(0x0800);

      memcpy(&sending_packet[0],new_ethernet_header,sizeof(ethernet_hdr));
      memcpy(&sending_packet[sizeof(ethernet_hdr)],&packet.packet[sizeof(ethernet_hdr)],packet.packet.size()-sizeof(ethernet_hdr));
      // uint8_t *buffer = (uint8_t *) reply_packet.data();
      // uint8_t *payload = (uint8_t*)new_arp_header;
      // print_hdr_arp(payload);
      //look for out interface to send
      try{
        RoutingTableEntry routing_entry = m_router.getRoutingTable().lookup(tip);
        printf("Sending pending packet.... to %s!\n",routing_entry.ifName.c_str());
        print_hdrs(sending_packet);
          // const Interface* out_intf = m_router.findIfaceByName(routing_entry.ifName);
        m_router.sendPacket(sending_packet,routing_entry.ifName);
      } catch (std::runtime_error& error){
        printf("Cannot find next hop to forward the packet\n");
      }
      
      
      
    }
  }
  //if not found, do nothing
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.

ArpCache::ArpCache(SimpleRouter& router)
  : m_router(router)
  , m_shouldStop(false)
  , m_tickerThread(std::bind(&ArpCache::ticker, this))
{
}

ArpCache::~ArpCache()
{
  m_shouldStop = true;
  m_tickerThread.join();
}

std::shared_ptr<ArpEntry>
ArpCache::lookup(uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  for (const auto& entry : m_cacheEntries) {
    if (entry->isValid && entry->ip == ip) {
      return entry;
    }
  }

  return nullptr;
}

std::shared_ptr<ArpRequest>
ArpCache::queueRequest(uint32_t ip, const Buffer& packet, const std::string& iface)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });

  if (request == m_arpRequests.end()) {
    request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
  }

  (*request)->packets.push_back({packet, iface});
  return *request;
}

void
ArpCache::removeRequest(const std::shared_ptr<ArpRequest>& entry)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  m_arpRequests.remove(entry);
}

std::shared_ptr<ArpRequest>
ArpCache::insertArpEntry(const Buffer& mac, uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto entry = std::make_shared<ArpEntry>();
  entry->mac = mac;
  entry->ip = ip;
  entry->timeAdded = steady_clock::now();
  entry->isValid = true;
  m_cacheEntries.push_back(entry);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });
  if (request != m_arpRequests.end()) {
    return *request;
  }
  else {
    return nullptr;
  }
}

void
ArpCache::clear()
{
  std::lock_guard<std::mutex> lock(m_mutex);

  m_cacheEntries.clear();
  m_arpRequests.clear();
}

void
ArpCache::ticker()
{
  while (!m_shouldStop) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    {
      std::lock_guard<std::mutex> lock(m_mutex);

      auto now = steady_clock::now();

      for (auto& entry : m_cacheEntries) {
        if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO)) {
          entry->isValid = false;
        }
      }

      periodicCheckArpRequestsAndCacheEntries();
    }
  }
}

std::ostream&
operator<<(std::ostream& os, const ArpCache& cache)
{
  std::lock_guard<std::mutex> lock(cache.m_mutex);

  os << "\nMAC            IP         AGE                       VALID\n"
     << "-----------------------------------------------------------\n";

  auto now = steady_clock::now();
  for (const auto& entry : cache.m_cacheEntries) {

    os << macToString(entry->mac) << "   "
       << ipToString(entry->ip) << "   "
       << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
       << entry->isValid
       << "\n";
  }
  os << std::endl;
  return os;
}

} // namespace simple_router
