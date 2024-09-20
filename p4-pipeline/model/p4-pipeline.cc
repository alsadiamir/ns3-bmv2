/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2018 Stanford University
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors: Stephen Ibanez <sibanez@stanford.edu>
 */

#include <bm/bm_sim/parser.h>
#include <bm/bm_sim/tables.h>
#include <bm/bm_sim/logger.h>
#include <bm/bm_sim/event_logger.h>
#include <bm/bm_runtime/bm_runtime.h>
#include <bm/bm_sim/options_parse.h>

#include <unistd.h>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <chrono>
#include <thread>

#include "p4-pipeline.h"
#include "ns3/ethernet-header.h"
#include "ns3/udp-header.h"
#include "ns3/ipv4-header.h"
#include "ns3/ethernet-header.h"
#include "ns3/tcp-header.h"

// NOTE: do not include "ns3/log.h" because of name conflict with LOG_DEBUG

#define PACKET_LENGTH_REG_IDX 0

extern int import_primitives();

namespace ns3 {

namespace {

uint64_t Mac48AddressToLongInt(Mac48Address address) {
    uint8_t buf[6];
    address.CopyTo(buf);
    
    uint64_t longInt = 0;
    for (int i = 0; i < 6; ++i) {
        longInt = (longInt << 8) | buf[i];
    }
    return longInt;
}


struct hash_ex {
  uint32_t operator()(const char *buf, size_t s) const {
    const uint32_t p = 16777619;
    uint32_t hash = 2166136261;

    for (size_t i = 0; i < s; i++)
      hash = (hash ^ buf[i]) * p;

    hash += hash << 13;
    hash ^= hash >> 7;
    hash += hash << 3;
    hash ^= hash >> 17;
    hash += hash << 5;
    return static_cast<uint32_t>(hash);
  }
};

struct bmv2_hash {
  uint64_t operator()(const char *buf, size_t s) const {
    return bm::hash::xxh64(buf, s);
  }
};

}  // namespace

// if REGISTER_HASH calls placed in the anonymous namespace, some compiler can
// give an unused variable warning
REGISTER_HASH(hash_ex);
REGISTER_HASH(bmv2_hash);

// initialize static attributes
int SimpleP4Pipe::thrift_port = 9090;
bm::packet_id_t SimpleP4Pipe::packet_id = 0;
uint8_t SimpleP4Pipe::ns2bm_buf[MAX_PKT_SIZE] = {};

SimpleP4Pipe::SimpleP4Pipe (std::string jsonFile)
{
  // Required fields
  add_required_field("standard_metadata", "qdepth");
  add_required_field("standard_metadata", "qdepth_bytes");
  add_required_field("standard_metadata", "avg_qdepth");
  add_required_field("standard_metadata", "avg_qdepth_bytes");
  add_required_field("standard_metadata", "timestamp");
  add_required_field("standard_metadata", "idle_time");
  add_required_field("standard_metadata", "qlatency");
  add_required_field("standard_metadata", "avg_deq_rate_bytes");
  add_required_field("standard_metadata", "pkt_len");
  add_required_field("standard_metadata", "pkt_len_bytes");
  add_required_field("standard_metadata", "l3_proto");
  add_required_field("standard_metadata", "flow_hash");
  add_required_field("standard_metadata", "ingress_trigger");
  add_required_field("standard_metadata", "timer_trigger");
  // drop trigger metadata
  add_required_field("standard_metadata", "drop_trigger");
  add_required_field("standard_metadata", "drop_timestamp");
  add_required_field("standard_metadata", "drop_qdepth");
  add_required_field("standard_metadata", "drop_qdepth_bytes");
  add_required_field("standard_metadata", "drop_avg_qdepth");
  add_required_field("standard_metadata", "drop_avg_qdepth_bytes");
  add_required_field("standard_metadata", "drop_pkt_len");
  add_required_field("standard_metadata", "drop_pkt_len_bytes");
  add_required_field("standard_metadata", "drop_l3_proto");
  add_required_field("standard_metadata", "drop_flow_hash");
  // enqueue trigger metadata
  add_required_field("standard_metadata", "enq_trigger");
  add_required_field("standard_metadata", "enq_timestamp");
  add_required_field("standard_metadata", "enq_qdepth");
  add_required_field("standard_metadata", "enq_qdepth_bytes");
  add_required_field("standard_metadata", "enq_avg_qdepth");
  add_required_field("standard_metadata", "enq_avg_qdepth_bytes");
  add_required_field("standard_metadata", "enq_pkt_len");
  add_required_field("standard_metadata", "enq_pkt_len_bytes");
  add_required_field("standard_metadata", "enq_l3_proto");
  add_required_field("standard_metadata", "enq_flow_hash");
  // dequeue trigger metadata
  add_required_field("standard_metadata", "deq_trigger");
  add_required_field("standard_metadata", "deq_enq_timestamp");
  add_required_field("standard_metadata", "deq_qdepth");
  add_required_field("standard_metadata", "deq_qdepth_bytes");
  add_required_field("standard_metadata", "deq_avg_qdepth");
  add_required_field("standard_metadata", "deq_avg_qdepth_bytes");
  add_required_field("standard_metadata", "deq_timestamp");
  add_required_field("standard_metadata", "deq_pkt_len");
  add_required_field("standard_metadata", "deq_pkt_len_bytes");
  add_required_field("standard_metadata", "deq_l3_proto");
  add_required_field("standard_metadata", "deq_flow_hash");
  // P4 program outputs
  add_required_field("standard_metadata", "drop");
  add_required_field("standard_metadata", "mark");
  // P4 program tracedata
  add_required_field("standard_metadata", "trace_var1");
  add_required_field("standard_metadata", "trace_var2");
  add_required_field("standard_metadata", "trace_var3");
  add_required_field("standard_metadata", "trace_var4");

  add_required_field("scalars", "userMetadata._stats_Median5");
  add_required_field("scalars", "hash_posix_0");
  add_required_field("ethernet", "srcAddr");
  add_required_field("ethernet", "dstAddr");
  add_required_field("ethernet", "etherType");

  force_arith_header("standard_metadata");
  force_arith_header("scalars");
  force_arith_header("ethernet");
  // force_arith_header("stats");

  import_primitives();

  // Initialize the switch
  bm::OptionsParser opt_parser;
  opt_parser.config_file_path = jsonFile;
  opt_parser.debugger_addr = std::string("ipc:///tmp/bmv2-") +
                             std::to_string(thrift_port) +
                             std::string("-debug.ipc");
  opt_parser.notifications_addr = std::string("ipc:///tmp/bmv2-") +
                             std::to_string(thrift_port) +
                             std::string("-notifications.ipc");
  opt_parser.file_logger = std::string("/tmp/bmv2-") +
                             std::to_string(thrift_port) +
                             std::string("-pipeline.log");
  opt_parser.thrift_port = thrift_port++;

  int status = init_from_options_parser(opt_parser);
  if (status != 0) {
    BMLOG_DEBUG("Failed to initialize the P4 pipeline");
    std::exit(status);
  }

}

void
SimpleP4Pipe::run_cli(std::string commandsFile) {
  int port = get_runtime_port();
  bm_runtime::start_server(this, port);
  start_and_return();

  std::this_thread::sleep_for(std::chrono::seconds(5));

  // Run the CLI commands to populate table entries
  std::string cmd = "/home/mininet/ns3-repos/ns-3-allinone/ns-3.29/src/bmv2-tools/run_bmv2_CLI --thrift_port " + std::to_string(port) + " " + commandsFile;
  std::system (cmd.c_str());
}

void
SimpleP4Pipe::start_and_return_() {

}

int
SimpleP4Pipe::receive_(port_t port_num, const char *buffer, int len)
{
  return 0;
}

Ptr<Packet>
SimpleP4Pipe::process_pipeline(Ptr<Packet> ns3_packet, std_meta_t &std_meta) {
  bm::Parser *parser = this->get_parser("parser");
  bm::Pipeline *mau = this->get_pipeline("ingress");
  bm::Deparser *deparser = this->get_deparser("deparser");
  bm::PHV *phv;

  int len = ns3_packet->GetSize();
  auto packet = get_bm_packet(ns3_packet);

  BMELOG(packet_in, *packet);

  phv = packet->get_phv();
  phv->reset_metadata();

  /* Set standard metadata */

  // using packet register 0 to store length, this register will be updated for
  // each add_header / remove_header primitive call
  packet->set_register(PACKET_LENGTH_REG_IDX, len);
  phv->get_field("standard_metadata.qdepth").set(std_meta.qdepth);
  phv->get_field("standard_metadata.qdepth_bytes").set(std_meta.qdepth_bytes);
  phv->get_field("standard_metadata.avg_qdepth").set(std_meta.avg_qdepth);
  phv->get_field("standard_metadata.avg_qdepth_bytes").set(std_meta.avg_qdepth_bytes);
  phv->get_field("standard_metadata.timestamp").set(std_meta.timestamp);
  phv->get_field("standard_metadata.idle_time").set(std_meta.idle_time);
  phv->get_field("standard_metadata.qlatency").set(std_meta.qlatency);
  phv->get_field("standard_metadata.avg_deq_rate_bytes").set(std_meta.avg_deq_rate_bytes);
  phv->get_field("standard_metadata.pkt_len").set(std_meta.pkt_len);
  phv->get_field("standard_metadata.pkt_len_bytes").set(std_meta.pkt_len_bytes);
  phv->get_field("standard_metadata.l3_proto").set(std_meta.l3_proto);
  phv->get_field("standard_metadata.flow_hash").set(std_meta.flow_hash);
  phv->get_field("standard_metadata.ingress_trigger").set(std_meta.ingress_trigger);
  phv->get_field("standard_metadata.timer_trigger").set(std_meta.timer_trigger);
  // drop trigger metadata
  phv->get_field("standard_metadata.drop_trigger").set(std_meta.drop_trigger);
  phv->get_field("standard_metadata.drop_timestamp").set(std_meta.drop_timestamp);
  phv->get_field("standard_metadata.drop_qdepth").set(std_meta.drop_qdepth);
  phv->get_field("standard_metadata.drop_qdepth_bytes").set(std_meta.drop_qdepth_bytes);
  phv->get_field("standard_metadata.drop_avg_qdepth").set(std_meta.drop_avg_qdepth);
  phv->get_field("standard_metadata.drop_avg_qdepth_bytes").set(std_meta.drop_avg_qdepth_bytes);
  phv->get_field("standard_metadata.drop_pkt_len").set(std_meta.drop_pkt_len);
  phv->get_field("standard_metadata.drop_pkt_len_bytes").set(std_meta.drop_pkt_len_bytes);
  phv->get_field("standard_metadata.drop_l3_proto").set(std_meta.drop_l3_proto);
  phv->get_field("standard_metadata.drop_flow_hash").set(std_meta.drop_flow_hash);
  // enqueue trigger metadata
  phv->get_field("standard_metadata.enq_trigger").set(std_meta.enq_trigger);
  phv->get_field("standard_metadata.enq_timestamp").set(std_meta.enq_timestamp);
  phv->get_field("standard_metadata.enq_qdepth").set(std_meta.enq_qdepth);
  phv->get_field("standard_metadata.enq_qdepth_bytes").set(std_meta.enq_qdepth_bytes);
  phv->get_field("standard_metadata.enq_avg_qdepth").set(std_meta.enq_avg_qdepth);
  phv->get_field("standard_metadata.enq_avg_qdepth_bytes").set(std_meta.enq_avg_qdepth_bytes);
  phv->get_field("standard_metadata.enq_pkt_len").set(std_meta.enq_pkt_len);
  phv->get_field("standard_metadata.enq_pkt_len_bytes").set(std_meta.enq_pkt_len_bytes);
  phv->get_field("standard_metadata.enq_l3_proto").set(std_meta.enq_l3_proto);
  phv->get_field("standard_metadata.enq_flow_hash").set(std_meta.enq_flow_hash);
  // dequeue trigger metadata
  phv->get_field("standard_metadata.deq_trigger").set(std_meta.deq_trigger);
  phv->get_field("standard_metadata.deq_enq_timestamp").set(std_meta.deq_enq_timestamp);
  phv->get_field("standard_metadata.deq_qdepth").set(std_meta.deq_qdepth);
  phv->get_field("standard_metadata.deq_qdepth_bytes").set(std_meta.deq_qdepth_bytes);
  phv->get_field("standard_metadata.deq_avg_qdepth").set(std_meta.deq_avg_qdepth);
  phv->get_field("standard_metadata.deq_avg_qdepth_bytes").set(std_meta.deq_avg_qdepth_bytes);
  phv->get_field("standard_metadata.deq_timestamp").set(std_meta.deq_timestamp);
  phv->get_field("standard_metadata.deq_pkt_len").set(std_meta.deq_pkt_len);
  phv->get_field("standard_metadata.deq_pkt_len_bytes").set(std_meta.deq_pkt_len_bytes);
  phv->get_field("standard_metadata.deq_l3_proto").set(std_meta.deq_l3_proto);
  phv->get_field("standard_metadata.deq_flow_hash").set(std_meta.deq_flow_hash);

  phv->get_field("standard_metadata.trace_var1").set(std_meta.trace_var1);
  phv->get_field("standard_metadata.trace_var2").set(std_meta.trace_var2);
  phv->get_field("standard_metadata.trace_var3").set(std_meta.trace_var3);
  phv->get_field("standard_metadata.trace_var4").set(std_meta.trace_var4);


  std::cout << ns3_packet->ToString() << std::endl;

  // Ptr<Packet> copy = ns3_packet->Copy();

  // std::cout << ns3_packet->ToString() << std::endl;

  EthernetHeader ethHeader;
  if (ns3_packet->PeekHeader(ethHeader)) {
      // Mac48Address src = ethHeader.GetSource();
      // Mac48Address dst = ethHeader.GetDestination();
      // uint16_t ethertype = ethHeader.GetLengthType();
      // std::cout << "Ethernet Source: " << src << " Destination: " << dst << " EtherType: " << ethertype << std::endl;
      ns3_packet->RemoveHeader(ethHeader);
  }
  
  Ipv4Header ipHeader;
  if (ns3_packet->PeekHeader(ipHeader)) {
      // Ipv4Address src = ipHeader.GetSource();
      // Ipv4Address dst = ipHeader.GetDestination();
      // std::cout << "IP Source: " << src << " Destination: " << dst << std::endl;
      ns3_packet->RemoveHeader(ipHeader);
  }
  if (ipHeader.GetProtocol() == 17) {
      std::cout <<  "UDP Packet" << std::endl;
      UdpHeader udpHeader;
      if (ns3_packet->PeekHeader(udpHeader)) {
          // uint16_t srcPort = udpHeader.GetSourcePort();
          // uint16_t dstPort = udpHeader.GetDestinationPort();
          // std::cout << "UDP Source Port: " << srcPort << " Destination Port: " << dstPort << std::endl;
          ns3_packet->RemoveHeader(udpHeader);
      }
  } else {
    if (ipHeader.GetProtocol() == 6) {
      std::cout << "TCP Packet" << std::endl;
      TcpHeader tcpHeader;
      if (ns3_packet->PeekHeader(tcpHeader)) {
          // uint16_t srcPort = tcpHeader.GetSourcePort();
          // uint16_t dstPort = tcpHeader.GetDestinationPort();
          // std::cout << "TCP Source Port: " << srcPort << " Destination Port: " << dstPort << std::endl;
          ns3_packet->RemoveHeader(tcpHeader);
      }
    }
  }

  phv->get_field("ethernet.srcAddr").set(Mac48AddressToLongInt(ethHeader.GetSource()));
  phv->get_field("ethernet.dstAddr").set(Mac48AddressToLongInt(ethHeader.GetDestination()));
  phv->get_field("ethernet.etherType").set(ethHeader.GetLengthType());


  BMLOG_DEBUG_PKT(*packet, "Processing received packet");

  /* Invoke Parser */
  parser->parse(packet.get());

  /* Invoke Match-Action */
  mau->apply(packet.get());

  packet->reset_exit();

  /* Invoke Deparser */
  deparser->deparse(packet.get());

  /* Set trace variables */
  std_meta.trace_var1 = phv->get_field("standard_metadata.trace_var1").get_int();
  std_meta.trace_var2 = phv->get_field("standard_metadata.trace_var2").get_int();
  std_meta.trace_var3 = phv->get_field("standard_metadata.trace_var3").get_int();
  std_meta.trace_var4 = phv->get_field("standard_metadata.trace_var4").get_int();
  // uint16_t median = phv->get_field("stats._stats_Median5").get_int();

  uint64_t ethSource = phv->get_field("ethernet.srcAddr").get_uint64();
  uint64_t ethDest = phv->get_field("ethernet.dstAddr").get_uint64();
  uint16_t etherType = phv->get_field("ethernet.etherType").get_uint();
  uint16_t hash_posix = phv->get_field("scalars.hash_posix_0").get_uint();
  uint16_t median = phv->get_field("scalars.userMetadata._stats_Median5").get_uint();

  std::cout << "After Deparser:" << std::endl;
  std::cout << "Hash: " << hash_posix << std::endl;
  std::cout << "Traced hash: " << std_meta.trace_var1 << std::endl;
  std::cout << "Median: " << median << std::endl;
  std::cout << "Ethernet Source: " << ethSource << " Destination: " << ethDest << " EtherType: " << etherType << std::endl;


  /* Set drop and mark fields */
  int drop = phv->get_field("standard_metadata.drop").get_int();
  BMLOG_DEBUG_PKT(*packet, "Drop field is {}", drop);
  std_meta.drop = (drop != 0);

  int mark = phv->get_field("standard_metadata.mark").get_int();
  BMLOG_DEBUG_PKT(*packet, "Mark field is {}", mark);
  std_meta.mark = (mark != 0);

  BMELOG(packet_out, *packet);
  BMLOG_DEBUG_PKT(*packet, "Transmitting packet");

  return get_ns3_packet(std::move(packet));
}

std::unique_ptr<bm::Packet>
SimpleP4Pipe::get_bm_packet(Ptr<Packet> ns3_packet) {
  port_t port_num = 0; // unused
  int len = ns3_packet->GetSize();

  if (len > MAX_PKT_SIZE)  {
    BMLOG_DEBUG("Packet length {} exceeds MAX_PKT_SIZE", len);
    std::exit(1); // TODO(sibanez): set error code
  }
  ns3_packet->CopyData(ns2bm_buf, len);
  auto bm_packet = new_packet_ptr(port_num, packet_id++, len,
                               bm::PacketBuffer(MAX_PKT_SIZE, (char*)(ns2bm_buf), len));
  return bm_packet;
}

Ptr<Packet>
SimpleP4Pipe::get_ns3_packet(std::unique_ptr<bm::Packet> bm_packet) {
  char *bm_buf = bm_packet.get()->data();
  size_t len = bm_packet.get()->get_data_size();
  return Create<Packet> ((uint8_t*)(bm_buf), len);
}

}

