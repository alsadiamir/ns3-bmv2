/***
 * ================
 * Author: Sam Gao
 * Year:   2021
 * ================
 ***/

// P4 application used in the detect and drill down case study described in the
// paper "Sam Gao, Mark Handley, and Stefano Vissicchio. Stats 101 in P4: Towards 
// In-Switch Anomaly Detection. Proc. HotNets, 2021."

#include <core.p4>
#include <v1model.p4>

// Needed before incuding stats_freq.p4
// We need 2 counters: 1 for top-level, and 1 for refining.
// The refine counter is capable of monitoring an entire /24, in this case.
#define STAT_FREQ_COUNTER_SIZE  256
#define STAT_FREQ_COUNTER_N     2

// #include "stat4.p4"

// Top-level anomaly detection parameters

// In microseconds: 1048576us ~ 1sec.
// 10 windows = 10sec.
// 2-standard deviation from mean is considered anomalous.
#define BUCKET_SIZE 15
#define WINDOW_SIZE 10
#define SPLIT_SIZE 5
#define STDEV_RANGE 2
#define SRC_ATK_PORT 1501

// Counter indices.
#define COUNTER_TOPLEVEL  0
#define COUNTER_REFINE    1

// Digest types.
#define DIGEST_TYPE_LEARN 0
#define DIGEST_TYPE_TOP_LEVEL_ALERT 1
#define DIGEST_TYPE_REFINE_ALERT 2

// Other constants.
#define TYPE_IPV4 0x800
#define PROTO_TCP 6
#define PROTO_UDP 17
#define PROTO_EXPERIMENTAL 253
#define PROTO_STAGE 254

// MODES
#define ANOMALY 0 // we track packets and median
#define LFA     1 // we track newmedian
#define SYN     2 //stage=0: we track subnet packets, stage=1: we track per-ip packets
#define ENTROPY 3 //stage=0: we track subnet SYNs, stage=1: we track per-ip SYNs

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header p2p_t{
  //towaste
  bit<16>     proto;
}

header ipv4_t {
  bit<4>      version;
  bit<4>      ihl;
  bit<8>      tos;
  bit<16>     totalLen;
  bit<16>     identification;
  bit<3>      flags;
  bit<13>     fragOffset;
  bit<8>      ttl;
  bit<8>      protocol;
  bit<16>     hdrChecksum;
  ip4Addr_t   srcAddr;
  ip4Addr_t   dstAddr;
}

// header debug_t{
//   bit<32>   alert;
//   bit<32>   counter_value;
//   bit<32>   subnet;
//   bit<32>   ip;
//   bit<32>   lfa;
//   bit<32>   index;
//   bit<32>   hash_posix;
// }

header tcp_t {
  bit<16>     srcPort;
  bit<16>     dstPort;
  bit<32>     seqNo;
  bit<32>     ackNo;
  bit<4>      dataOffset;
  bit<4>      reserved;
  bit<8>      flags;
  bit<16>     window;
  bit<16>     csum;
  bit<16>     urgPtr;
}

// Define the UDP header
// header udp_t {
//     bit<16> srcPort;
//     bit<16> dstPort;
//     bit<16> length;
//     bit<16> checksum;
// }

struct metadata {
  // stats_t   stats;
  // bit<32>   counter_value;
  // bit<32>   index;
  // bit<32>   hash_posix;
}

struct headers {
  p2p_t              p2p;
  ipv4_t                  ipv4;
  tcp_t                   tcp;
  // udp_t                   udp;
  // debug_t                 debug;
}

/* ingress */
control MyIngress(inout headers hdr,
          inout metadata meta,
          inout standard_metadata_t standard_metadata) 
{

  apply { 
    if (hdr.tcp.isValid()){
      hdr.tcp.srcPort = 15;
    }

    // mark_to_drop(standard_metadata);
  }
}

/* egress */
control MyEgress(inout headers hdr,
         inout metadata meta,
         inout standard_metadata_t standard_metadata) 
{
  apply { }
}

parser MyParser(packet_in packet,
        out headers hdr,
        inout metadata meta,
        inout standard_metadata_t standard_metadata) 
{
  state start {
    packet.extract(hdr.p2p);
    transition ipv4;
    // transition select(hdr.p2p.proto) {
    //   TYPE_IPV4: ipv4;
    //   default: accept;
    // }
  }

  state ipv4 {
    packet.extract(hdr.ipv4);
    transition select(hdr.ipv4.protocol) {
      PROTO_TCP: tcp;
      // PROTO_UDP: udp;
      default: accept;
    }
  }

  // state udp {
  //   packet.extract(hdr.udp);
  //   transition accept;
  // }

  state tcp {
    packet.extract(hdr.tcp);
    transition accept;
  }
}


control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


control MyDeparser(packet_out packet, in headers hdr) 
{
    apply { packet.emit(hdr); }
}

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply { }
}


/* switch v1 */
V1Switch(
  MyParser(),
  MyVerifyChecksum(),
  MyIngress(),
  MyEgress(),
  MyComputeChecksum(),
  MyDeparser()
) main;