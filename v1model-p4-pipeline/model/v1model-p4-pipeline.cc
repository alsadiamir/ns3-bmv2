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
// #include <bm/SimpleSwitch.h>
// #include <bm/bm_sim/core/primitives.h>
// #include <simple_switch.h>

#include <unistd.h>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <chrono>
#include <thread>

#include "v1model-p4-pipeline.h"
#include "ns3/ipv4-header.h"
#include "ns3/ethernet-header.h"
#include "ns3/udp-header.h"
#include "ns3/tcp-header.h"

// NOTE: do not include "ns3/log.h" because of name conflict with LOG_DEBUG

#define PACKET_LENGTH_REG_IDX 0

extern int import_primitives();
// extern int import_primitives(SimpleSwitch *sswitch);

namespace ns3 {

  namespace {

    // std::string IntToIp(uint32_t ip) {
    //     std::ostringstream oss;
    //     oss << ((ip >> 24) & 0xFF) << "."
    //         << ((ip >> 16) & 0xFF) << "."
    //         << ((ip >> 8) & 0xFF) << "."
    //         << (ip & 0xFF);
    //     return oss.str();
    // }

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
  int V1ModelP4Pipe::thrift_port = 9090;
  bm::packet_id_t V1ModelP4Pipe::packet_id = 0;
  uint8_t V1ModelP4Pipe::ns2bm_buf[MAX_PKT_SIZE] = {};

  V1ModelP4Pipe::V1ModelP4Pipe (std::string jsonFile)
  {
    // Required fields
    add_required_field("standard_metadata", "ingress_port");
    add_required_field("standard_metadata", "egress_spec");
    add_required_field("standard_metadata", "egress_port");

    add_required_field("standard_metadata", "instance_type");
    add_required_field("standard_metadata", "packet_length");

    add_required_field("standard_metadata", "enq_timestamp");
    add_required_field("standard_metadata", "enq_qdepth");
    add_required_field("standard_metadata", "deq_timedelta");
    add_required_field("standard_metadata", "deq_qdepth");

    add_required_field("standard_metadata", "ingress_global_timestamp");
    add_required_field("standard_metadata", "egress_global_timestamp");
    add_required_field("standard_metadata", "mcast_grp");
    add_required_field("standard_metadata", "egress_rid");
    add_required_field("standard_metadata", "checksum_error");

    add_required_field("standard_metadata", "parser_error");
    add_required_field("standard_metadata", "priority");
    
    // add_required_field("scalars", "userMetadata._index7");
    // add_required_field("scalars", "userMetadata._hash_posix8");

    // add_required_field("ethernet", "srcAddr");
    // add_required_field("ethernet", "dstAddr");
    // add_required_field("ethernet", "etherType");

    add_required_field("ipv4", "srcAddr");
    add_required_field("ipv4", "dstAddr");

    // add_required_field("udp", "srcPort");
    // add_required_field("udp", "dstPort");

    add_required_field("tcp", "srcPort");
    add_required_field("tcp", "dstPort");
    add_required_field("tcp", "flags");

    force_arith_header("standard_metadata");
    force_arith_header("userMetadata");
    force_arith_header("scalars");
    force_arith_header("p2p");
    force_arith_header("ipv4");
    // force_arith_header("udp");
    force_arith_header("tcp");

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
  V1ModelP4Pipe::run_cli(std::string commandsFile) {
    int port = get_runtime_port();
    bm_runtime::start_server(this, port);
    start_and_return();

    std::this_thread::sleep_for(std::chrono::seconds(5));

    // Run the CLI commands to populate table entries
    std::string cmd = "/home/mininet/ns3-repos/ns-3-allinone/ns-3.29/src/bmv2-tools/run_bmv2_CLI --thrift_port " + std::to_string(port) + " " + commandsFile;
    std::system (cmd.c_str());
  }

  void
  V1ModelP4Pipe::start_and_return_() {

  }

  int
  V1ModelP4Pipe::receive_(port_t port_num, const char *buffer, int len)
  {
    return 0;
  }

  // Ptr<Packet>
  // V1ModelP4Pipe::process_pipeline(Ptr<Packet> ns3_packet, std_meta_t &std_meta, uint32_t index, uint32_t hash_posix) {

  Ptr<Packet>
  V1ModelP4Pipe::process_pipeline(Ptr<Packet> ns3_packet, std_meta_t &std_meta, uint32_t index, uint32_t hash_posix) {
    // uint32_t index = 0;
    // uint32_t hash_posix = 0;
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

    phv->get_field("standard_metadata.ingress_port").set(std_meta.ingress_port);
    phv->get_field("standard_metadata.egress_spec").set(std_meta.egress_spec);
    phv->get_field("standard_metadata.egress_port").set(std_meta.egress_port);
    phv->get_field("standard_metadata.instance_type").set(std_meta.instance_type);
    phv->get_field("standard_metadata.packet_length").set(std_meta.packet_length);
    phv->get_field("standard_metadata.enq_timestamp").set(std_meta.enq_timestamp);
    phv->get_field("standard_metadata.enq_qdepth").set(std_meta.enq_qdepth);
    phv->get_field("standard_metadata.deq_timedelta").set(std_meta.deq_timedelta);
    phv->get_field("standard_metadata.deq_qdepth").set(std_meta.deq_qdepth);
    phv->get_field("standard_metadata.ingress_global_timestamp").set(std_meta.ingress_global_timestamp);
    phv->get_field("standard_metadata.egress_global_timestamp").set(std_meta.egress_global_timestamp);
    phv->get_field("standard_metadata.mcast_grp").set(std_meta.mcast_grp);
    phv->get_field("standard_metadata.egress_rid").set(std_meta.egress_rid);
    phv->get_field("standard_metadata.checksum_error").set(std_meta.checksum_error);
    phv->get_field("standard_metadata.parser_error").set(std_meta.parser_error);
    phv->get_field("standard_metadata.priority").set(std_meta.priority);
    // phv->get_field("scalars.userMetadata._index7").set(index);
    // phv->get_field("scalars.userMetadata._hash_posix8").set(hash_posix);

    // std::cout << "BEFORE -- Index: " << index << " Hash posix: " << hash_posix << std::endl;

    /* Invoke Parser */
    parser->parse(packet.get());

    /* Invoke Match-Action */
    mau->apply(packet.get());

    packet->reset_exit();

    
    // std::cout << "Source Port: " << src_port << std::endl;

    /* Invoke Deparser */
    deparser->deparse(packet.get());

    // uint32_t dst_ip = phv->get_field("ipv4.dstAddr").get_uint();
    // uint32_t src_port = phv->get_field("tcp.srcPort").get_uint();
    // uint32_t dst_port = phv->get_field("tcp.dstPort").get_uint();
    // uint32_t seq_no = phv->get_field("tcp.seqNo").get_uint();
    // uint32_t ack_no = phv->get_field("tcp.ackNo").get_uint();
    // uint32_t dataOffset = phv->get_field("tcp.dataOffset").get_uint();
    // uint32_t reserved = phv->get_field("tcp.reserved").get_uint();
    // uint32_t flags = phv->get_field("tcp.flags").get_uint();
    // uint32_t counter_value = phv->get_field("scalars.userMetadata._counter_value6").get_uint();
    uint32_t egress_spec = phv->get_field("standard_metadata.egress_spec").get_uint();

    // if (flags == 2 || flags==16)
    // {
    //   std::cout << "IPv4 Header: " << std::endl;
    //   std::cout << "Destination IP: " << IntToIp(dst_ip) << std::endl;
    //   std::cout << "TCP Header: " << std::endl;
    //   std::cout << "Source Port: " << src_port << std::endl;
    //   std::cout << "Destination Port: " << dst_port << std::endl;
    //   std::cout << "Sequence Number: " << seq_no << std::endl;
    //   std::cout << "Acknowledgement Number: " << ack_no << std::endl;
    //   std::cout << "Data Offset: " << dataOffset << std::endl;
    //   std::cout << "Reserved: " << reserved << std::endl;
    //   std::cout << "Flags: " << flags << std::endl;
      // std::cout << "Counter Value: " << counter_value << std::endl;
    // }
    std::cout << "Egress Spec: " << egress_spec << std::endl;


    std_meta.egress_spec = egress_spec;
    BMELOG(packet_out, *packet);
    BMLOG_DEBUG_PKT(*packet, "Transmitting packet");

    return get_ns3_packet(std::move(packet));
  }

  std::unique_ptr<bm::Packet>
  V1ModelP4Pipe::get_bm_packet(Ptr<Packet> ns3_packet) {
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
  V1ModelP4Pipe::get_ns3_packet(std::unique_ptr<bm::Packet> bm_packet) {
    char *bm_buf = bm_packet->data();
    size_t len = bm_packet.get()->get_data_size();
    return Create<Packet> ((uint8_t*)(bm_buf), len);
  }

}
