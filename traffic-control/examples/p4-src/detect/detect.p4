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

#include "stat4.p4"



// Top-level anomaly detection parameters

// In microseconds: 1048576us ~ 1sec.
// 10 windows = 10sec.
// 2-standard deviation from mean is considered anomalous.
#define BUCKET_SIZE 20
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

header ethernet_t {
  macAddr_t dstAddr;
  macAddr_t srcAddr;
  bit<16>   etherType;
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

header stage_transfer_t{
  bit<8>      mode;
  bit<8>      stage;
  bit<16>     median;
  bit<32>     detected_subnet;
  bit<32>     detected_ip;
}

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
header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

struct learn_t {
  bit<8>  digestType;
  bit<48> srcAddr;
  bit<9>  ingress_port;
}

struct alert_top_t {
  bit<8>  digestType;
  bit<16> lastBucket;
  bit<16> N;
  bit<32> meanNX;
  bit<32> stdevNX;
}

struct alert_refine_t {
  bit<8>  digestType;
  bit<32> alertCounterIdx;
}

struct monitor_t {
  bit<32> nval;
  bit<32> cmp;
  bit<32> Xsum;
  bit<32> VarNX;
  bit<32> StdNX;
  bit<16> val0;
  bit<16> val1;
  bit<16> val2;
  bit<16> val3;
  bit<16> val4;
  bit<16> val5;
}

struct metadata {
  bit<4>          ihlRem;
  bit<4>          tcpRem;
  bit<16>         tcpLen;
  bit<32>         counter_value;
  bit<48>         bucket_stamp;
  bit<48>         last_stamp;
  stats_t         stats;
  learn_t         learn;
  alert_top_t     alert;
  alert_refine_t  alert_refine;
  monitor_t       monitor;
}

struct bitmap {
  bit<1> flow;

}

struct headers {
  ethernet_t              ethernet;
  ipv4_t                  ipv4;
  tcp_t                   tcp;
  udp_t                   udp;
  stage_transfer_t        stage_transfer;
}

/* ingress */
control MyIngress(inout headers hdr,
          inout metadata meta,
          inout standard_metadata_t standard_metadata) 
{

  // The time-based sliding window is only used for top-level search.    
  register<bit<32>>(1)  next_bucket;
  register<bit<48>>(1)  last_bucket_stamp;
  // register<bit<48>>(2)  timestamps;
  register<bit<8>>(1)   stage_s;
  // register<bit<1>>(2)   blocks;

  register<bit<16>>(2)  median_s;
  register<bit<32>>(1)  d_subnet;
  register<bit<32>>(1)  d_ip;
  register<bit<256>>(8) distinctFlows;
  register<bit<1>>(1) isLfa;
  register<bit<8>>(1) mode_s;
  register<bit<8>>(1) path_s;

  register<bit<16>>(1) ticks_s;
  register<bit<8>>(1) rotate_s;
  register<bit<8>>(1) packet_track;
  register<bit<16>>(1) attack_packet_count;
  register<bit<16>>(1) peak_packet_count;
  register<bit<32>>(1) peak_nval;

  // Normal L2 learning tables
  action drop() {
    mark_to_drop(standard_metadata);
  }

  // action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
  //       standard_metadata.egress_spec = port;
  //       hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
  //       hdr.ethernet.dstAddr = dstAddr;
  //       hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
  // }

  // action forward(bit<9> egress_port) {
  //   standard_metadata.egress_spec = egress_port;
  // }

  // action dst_routing(bit<9> first_port, bit<9> second_port) {
  //   bit<2> port;
  //   hash(port, HashAlgorithm.crc32, 2w0, {hdr.ipv4.dstAddr}, 2w2);
  //   if(port == 0){
  //     standard_metadata.egress_spec = (bit<9>) first_port;
  //   } else{
  //     standard_metadata.egress_spec = (bit<9>) second_port;
  //   }   
  // }

  // action flow_forward(bit<9> first_port, bit<9> second_port, bit<9> third_port) {
  //   bit<2> port;
  //   hash(port, HashAlgorithm.crc16, 2w0, {hdr.ipv4.srcAddr}, 2w3);
  //   if(port == 0){
  //     standard_metadata.egress_spec = (bit<9>) first_port;
  //   }   
  //   if(port == 1){
  //     standard_metadata.egress_spec = (bit<9>) second_port;
  //   }
  //   if(port == 2){
  //     standard_metadata.egress_spec = (bit<9>) third_port;
  //   }
  // }

  // action lfa_forward(bit<9> port) {
  //   standard_metadata.egress_spec = port; 
  // }

  // table lfa_fwd {
  //       key = {
  //           hdr.tcp.srcPort: exact;
  //       }
  //       actions = {
  //           lfa_forward;
  //           drop;
  //           NoAction;
  //       }
  //       size = 1024;
  //       default_action = NoAction();
  // }



  // table ipv4_lpm {
  //       key = {
  //           hdr.ipv4.srcAddr: lpm;
  //           // hdr.tcp.srcPort: exact;
  //       }
  //       actions = {
  //           ipv4_forward;     
  //           flow_forward;
  //           lfa_forward;
  //           forward;
  //           drop;
  //           NoAction;
  //       }
  //       size = 1024;
  //       default_action =  NoAction();
  // }

  action track_time() {
    // ?
  }

  // Sets refined tracking counter value.
  action track (bit<32> counter_value) {
    meta.counter_value = counter_value;
  }

  table window_track {
    key = {
      hdr.ipv4.dstAddr: lpm;
    }
    actions = {
      track_time;
      NoAction;
    }
    size = 16;
    default_action = NoAction;
  }

  // table anomaly_track {
  //   key = {
  //     hdr.ipv4.dstAddr: lpm;
  //   }
  //   actions = {
  //     track_time;
  //     NoAction;
  //   }
  //   size = 16;
  //   default_action = NoAction;
  // }

  table entropy_track {
    key = {
      hdr.ipv4.dstAddr: lpm;
    }
    actions = {
      track_time;
      NoAction;
    }
    size = 16;
    default_action = NoAction;
  }

  table syn_track {
    key = {
      hdr.ipv4.dstAddr: lpm;
    }
    actions = {
      track_time;
      NoAction;
    }
    size = 16;
    default_action = NoAction;
  }

  action set_tracked_subnet() {
    bit<32> ip_byte_selected;
    ip_byte_selected = hdr.ipv4.dstAddr >> 8;
    ip_byte_selected = hdr.ipv4.dstAddr << 16;
    ip_byte_selected = ip_byte_selected >> 24;
    meta.counter_value = ip_byte_selected; 
  }

  action set_tracked_ip() {
    bit<32> ip_start;
    bit<32> ip_byte_selected;
    bit<32> detected_subnet;
    ip_start = hdr.ipv4.dstAddr >> 8;
    ip_start = ip_start << 8;

    d_subnet.read(detected_subnet, 0);
    if(ip_start == detected_subnet){
      ip_byte_selected = hdr.ipv4.dstAddr - detected_subnet;
      meta.counter_value = ip_byte_selected;
    }    
  }

  table dest_prefix_track {
    key = {
      hdr.ipv4.dstAddr: lpm;
    }
    actions = {
      track;
      NoAction;
    }
    size = 1024;
    default_action = NoAction;
  }

  apply { 
    @atomic { 
      bit<8> stage;
      bit<8> mode;
      bit<16> median;
      bit<16> tmpMedian;
      bit<24> subnetStart;
      bit<32> subnet;

      bit<48> bucket_stamp;
      //bit<64> bucket_stamp = 0;
      bit<32> detected_subnet;
      bit<32> detected_ip;
      bit<48> last_stamp;
      bit<1> lfa;
      bit<8> next;
      bit<8> path;

      bit<16> ticks;
      bit<8> rotate;
      bit<8> pkt_track;
      bit<16> atk_pkt_count;
      bit<16> peak_pkt_count;
      bit<32> peak;
      
    
      // Default no-match value.
      meta.counter_value = 0xdeadbeef;
      bucket_stamp = standard_metadata.ingress_global_timestamp >> BUCKET_SIZE;
      stage_s.read(stage, 0);
      mode_s.read(mode, 0);
      path_s.read(path, 0);
      median_s.read(median, 0);
      ticks_s.read(ticks, 0);

      d_subnet.read(detected_subnet, 0);
      d_ip.read(detected_ip, 0);
      last_bucket_stamp.read(last_stamp, 0);
      isLfa.read(lfa, 0);
      rotate_s.read(rotate, 0);
      packet_track.read(pkt_track, 0);
      attack_packet_count.read(atk_pkt_count, 0);
      peak_packet_count.read(peak_pkt_count, 0);
      peak_nval.read(peak, 0);

      meta.bucket_stamp = bucket_stamp;
      meta.last_stamp = last_stamp;



      //FORWARDING
      if(hdr.tcp.isValid()){
        //TRACK ATTACK
        if(pkt_track == 1){
          if(hdr.tcp.dstPort == 1600){
            attack_packet_count.write(0, atk_pkt_count+1);
          }
        }
        // ipv4_lpm.apply();
      }
      
      //rotate stages
      if (rotate == 1 && bucket_stamp > last_stamp) {
        if(stage > 0) {
          if(mode != LFA && mode != ANOMALY){
            // Current bucket interval elapsed. Finalize the bucket and increment.
            last_bucket_stamp.write(0, bucket_stamp);
            ticks_s.write(0, ticks + 1); //change mode each x ticks
          }
          if(ticks == WINDOW_SIZE){
            distinctFlows.write(0,0);
            distinctFlows.write(1,0);
            distinctFlows.write(2,0);
            distinctFlows.write(3,0);
            distinctFlows.write(4,0);
            distinctFlows.write(5,0);
            distinctFlows.write(6,0);
            distinctFlows.write(7,0);
            stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE), 0);
            stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 1, 0);
            stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 2, 0);
            stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 3, 0);
            stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 4, 0);
            stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 5, 0);
            stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 6, 0);
            stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 7, 0);
            stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 8, 0);
            stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 9, 0);
            stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 10, 0);
            // stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 11, 0);
            // stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 12, 0);
            // stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 13, 0);
            // stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 14, 0);
            // stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 15, 0);
            // stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 16, 0);
            // stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 17, 0);
            // stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 18, 0);
            // stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 19, 0);
            // stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 20, 0);
            // stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 21, 0);
            // stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 22, 0);
            // stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 23, 0);
            // stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 24, 0);
            if(mode == LFA) { 
              if(lfa == 0){
                mode_s.write(0, SYN);
              }
            }
            if(mode == SYN) { 
              //check if alert was sent
              if(detected_subnet == 0){
                mode_s.write(0, ENTROPY);
              }
            }
            if(mode == ENTROPY) { 
              //check if first alert was sent
              if(detected_subnet == 0){
                mode_s.write(0, LFA);
              }
            }
          } else{
            ticks_s.write(0, ticks + 1);
          }
        }
        if(ticks == WINDOW_SIZE){
          ticks_s.write(0, 0);
        }
      }  

      //stage transfer
      if(hdr.stage_transfer.isValid()){
        //just save the stage info to registers
        //if one mode is detected, let's stick with that one
        stats_freq_internal.read(tmpMedian, (COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + meta.stats.Median);
        if(tmpMedian > 0 && median == 0 && hdr.stage_transfer.median > 0){
          median_s.write(0, tmpMedian);  
        }
        if(hdr.stage_transfer.stage > stage){
          stage_s.write(0, hdr.stage_transfer.stage);
          if(hdr.stage_transfer.mode == 0 && mode == 0 && hdr.stage_transfer.stage == 1){
            distinctFlows.write(0,0);
            distinctFlows.write(1,0);
            distinctFlows.write(2,0);
            distinctFlows.write(3,0);
            distinctFlows.write(4,0);
            distinctFlows.write(5,0);
            distinctFlows.write(6,0);
            distinctFlows.write(7,0); 
            stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE), 0);
            stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 1, 0);
            stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 2, 0);
            stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 3, 0);
            stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 4, 0);
            stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 5, 0);
            stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 6, 0);
            stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 7, 0);
            stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 8, 0);
            stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 9, 0);
            stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 10, 0);
            // stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 11, 0);
            // stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 12, 0);
            // stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 13, 0);
            // stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 14, 0);
            // stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 15, 0);
            // stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 16, 0);
            // stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 17, 0);
            // stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 18, 0);
            // stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 19, 0);
            // stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 20, 0);
            // stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 21, 0);
            // stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 22, 0);
            // stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 23, 0);
            // stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 24, 0);
            mode_s.write(0, path);
          } 
          if(hdr.stage_transfer.mode != mode){ //we avoid resetting state if the mode is already set correctly
            distinctFlows.write(0,0);
            distinctFlows.write(1,0);
            distinctFlows.write(2,0);
            distinctFlows.write(3,0);
            distinctFlows.write(4,0);
            distinctFlows.write(5,0);
            distinctFlows.write(6,0);
            distinctFlows.write(7,0); 
            stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE), 0);
            stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 1, 0);
            stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 2, 0);
            stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 3, 0);
            stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 4, 0);
            stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 5, 0);
            stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 6, 0);
            stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 7, 0);
            stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 8, 0);
            stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 9, 0);
            stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 10, 0);
            // stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 11, 0);
            // stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 12, 0);
            // stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 13, 0);
            // stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 14, 0);
            // stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 15, 0);
            // stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 16, 0);
            // stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 17, 0);
            // stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 18, 0);
            // stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 19, 0);
            // stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 20, 0);
            // stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 21, 0);
            // stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 22, 0);
            // stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 23, 0);
            // stats_freq_internal.write((COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + 24, 0);
            mode_s.write(0, hdr.stage_transfer.mode);
          }
        }
        if(hdr.stage_transfer.detected_subnet > 0) {
          subnetStart = (bit<16>) 0x0a00 ++ (bit<8>) (hdr.stage_transfer.detected_subnet);
          subnet = subnetStart ++ (bit<8>) 0;
          d_subnet.write(0, subnet);
        }
        if(hdr.stage_transfer.detected_ip > 0) {
          d_ip.write(0, hdr.stage_transfer.detected_ip);
        }
        mode_s.read(mode, 0);
        if(mode != LFA){
          hdr.stage_transfer.setInvalid();
        }
      }

      //SET COUNTER
      if (hdr.ipv4.isValid() && window_track.apply().hit) {
        dest_prefix_track.apply();
        switch (mode) {
          ANOMALY: {
            bit<16> tmp;
            bit<32> bucket_idx;
            next_bucket.read(bucket_idx, 0);

            //grab CVAL
            bit<16> cval;
            read_bucket(cval, bucket_idx, COUNTER_TOPLEVEL);
            stats_get_data(meta.stats, COUNTER_TOPLEVEL);

            //grab NVAL
            bit<32> nval = (bit<32>)cval * meta.stats.N;
            last_bucket_stamp.read(last_stamp, 0);

            //FLOW COUNTING
            bit<256> tmpDistinctFlowsByte;
            bit<256> tmpDistinctFlowsByteTmp;
            bit<1> tmpDistinctFlowsBit;
            bit<256> tmpDistinctFlowsCurrent;
            bit<8> hash_posix;
            bit<32> index;

            if (bucket_idx == WINDOW_SIZE) {
              bucket_idx = 0;
            }

            stats_get_data(meta.stats, COUNTER_REFINE);
            stats_freq_internal.read(tmp, (COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + meta.stats.Median);

            //register flows
            hash(index, HashAlgorithm.crc32,  32w0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr}, 32w8);
            //hash and then put to data structure
            hash(hash_posix, HashAlgorithm.crc32, 32w0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr}, 32w256);

            distinctFlows.read(tmpDistinctFlowsCurrent, index);        
            tmpDistinctFlowsByte = tmpDistinctFlowsCurrent << hash_posix;
            // log_msg("bit_first_shift={}", {tmpDistinctFlowsByte});
            tmpDistinctFlowsByte = tmpDistinctFlowsByte >> 255;
            // log_msg("bit_s={}", {tmpDistinctFlowsByte});
            // log_msg("index={}", {index});
            // log_msg("hash_posix={}", {hash_posix});

            if(tmpDistinctFlowsByte == 0){
              median_90_tick(COUNTER_REFINE);
              stats_push_freq(tmp, bucket_idx, COUNTER_REFINE); 
              tmpDistinctFlowsByte = 1;
              tmpDistinctFlowsByte = tmpDistinctFlowsByte << 255;
              // log_msg("bit_shifted={}", {tmpDistinctFlowsByte});
              tmpDistinctFlowsByte = tmpDistinctFlowsByte >> hash_posix;
              // log_msg("bit_modified={}", {tmpDistinctFlowsByte});
              tmpDistinctFlowsCurrent = tmpDistinctFlowsCurrent + tmpDistinctFlowsByte;
              // tmpDistinctFlowsCurrent[hash_posix] = 1;
              distinctFlows.write(index, tmpDistinctFlowsCurrent);
            }

            if (bucket_stamp > last_stamp) {
              //fix here
              distinctFlows.write(0,0);
              distinctFlows.write(1,0);
              distinctFlows.write(2,0);
              distinctFlows.write(3,0);
              distinctFlows.write(4,0);
              distinctFlows.write(5,0);
              distinctFlows.write(6,0);
              distinctFlows.write(7,0);            

              // Current bucket interval elapsed. Finalize the bucket and increment.
              last_bucket_stamp.write(0, bucket_stamp);

              // Single-tail: only raise an alert if the amount of traffic is high.
              if (nval > meta.stats.Xsum + (STDEV_RANGE * meta.stats.StdNX)) { // compare Nx
                // Exceeds defined threshold.
                // Send digest so that the controller can populate the second counter.

                meta.alert.digestType = DIGEST_TYPE_TOP_LEVEL_ALERT;

                drop_bucket(bucket_idx, COUNTER_TOPLEVEL);
                if(hdr.tcp.isValid()){
                  // hdr.ipv4.protocol = PROTO_STAGE;
                  hdr.tcp.srcPort=SRC_ATK_PORT;
                  hdr.stage_transfer.setValid();     
                  hdr.stage_transfer.stage = 1;
                  hdr.stage_transfer.mode = 0; //start from LFA monitoring
                  stats_freq_internal.read(median, (COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + meta.stats.Median);
                  hdr.stage_transfer.median = median;
                  hdr.stage_transfer.detected_subnet = 0;
                  hdr.stage_transfer.detected_ip = 0;
                  // clone3(CloneType.I2E, 32w250, {});
                  // clone3(CloneType.I2E, 32w251, {});
                  // clone3(CloneType.I2E, 32w252, {});
                }            
              }

              if(nval > peak){
                //every time a bigger nval is detected, we reset the peak count
                peak_nval.write(0, nval);
                peak_packet_count.write(0, 0);
              } else{
                if(peak_pkt_count == 0){
                  peak_packet_count.write(0, atk_pkt_count);
                }
              }

              // Push bucket.
              bucket_idx = bucket_idx + 1;

              // Wrap last bucket index around if window is full.
              if (bucket_idx == WINDOW_SIZE) {
                bucket_idx = 0;
              }
              
              // Ensure the new bucket is clean.
              drop_bucket(bucket_idx, COUNTER_TOPLEVEL);
              drop_bucket(bucket_idx, COUNTER_REFINE);
              next_bucket.write(0, bucket_idx);
              //update rotation
              if(ticks<WINDOW_SIZE){
                ticks_s.write(0, ticks + 1); //change mode each x ticks
              }
            }

            // Increment the packets bucket
            stats_push_freq(tmp, bucket_idx, COUNTER_TOPLEVEL);
          }
          SYN: { 
              switch (stage) {
                1: { //track subnets - 1
                  set_tracked_subnet();
                }
                2: { //track ips - 2
                  set_tracked_ip();
                }
                default: { 
                  //do nothing
                }
              }
              bit<16> tmp;
              if (meta.counter_value != 0xdeadbeef && hdr.tcp.isValid() && hdr.tcp.flags == 2 && syn_track.apply().hit) {
                stats_push_freq(tmp, meta.counter_value, COUNTER_REFINE);
                stats_get_data(meta.stats, COUNTER_REFINE);

                bit<32> nval = (bit<32>)tmp * meta.stats.N;
                bit<48> ts_0;
                bit<48> ts_1;

                // Identify the heavy flow destination.
                if (nval > meta.stats.Xsum + (STDEV_RANGE * meta.stats.StdNX)) {
                  if(stage == 1){
                    if(hdr.tcp.isValid()){
                      // hdr.ipv4.protocol = PROTO_STAGE;
                      hdr.tcp.srcPort=SRC_ATK_PORT;
                      hdr.stage_transfer.setValid();
                      hdr.stage_transfer.stage = 2;
                      hdr.stage_transfer.mode = SYN;
                      stats_freq_internal.read(median, (COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + meta.stats.Median);
                      hdr.stage_transfer.median = median;
                      hdr.stage_transfer.detected_subnet = meta.counter_value;
                      hdr.stage_transfer.detected_ip = 0;
                      // clone3(CloneType.I2E, 32w250, {});
                    }
                    stats_clear(COUNTER_TOPLEVEL); 
                    subnetStart = (bit<16>) 0x0a00 ++ (bit<8>) (hdr.stage_transfer.detected_subnet);
                    subnet = subnetStart ++ (bit<8>) 0;
                    d_subnet.write(0, subnet);      
                  } else if(stage == 2){
                    if(hdr.tcp.isValid()){
                      subnet = hdr.ipv4.dstAddr >> 8;
                      subnet = subnet << 8;
                      if(subnet == detected_subnet){
                        d_ip.write(0, meta.counter_value);
                        packet_track.write(0, 0);
                      }
                    }
                  }
                  // if(nval > peak){
                  //   peak_nval.write(0, nval);
                  //   peak_packet_count.write(0, atk_pkt_count+1);
                  // }
                } 
                // else {
                //   if(nval < peak && peak_pkt_count == 0) {
                //     peak_packet_count.write(0, atk_pkt_count+1);
                //   }
                // }
              } 
          }
          ENTROPY: { 
            //get the stage
            switch (stage) {
              1: { //track subnets - 1
                set_tracked_subnet();
              }
              2: { //track ips - 2
                set_tracked_ip();
              }
              default: { 
                //do nothing
              }
            }
            // run_entropy(stage, saved_block_1);
            bit<16> tmp;
            if (meta.counter_value != 0xdeadbeef && hdr.tcp.isValid() && entropy_track.apply().hit) {
              stats_push_freq(tmp, meta.counter_value, COUNTER_REFINE);
              stats_get_data(meta.stats, COUNTER_REFINE);

              bit<32> nval = (bit<32>)tmp * meta.stats.N;
              bit<48> ts_0;
              bit<48> ts_1;

              // Identify the heavy flow destination.
              if (nval > meta.stats.Xsum + (STDEV_RANGE * meta.stats.StdNX)) {
                if(stage == 1){
                  if(hdr.tcp.isValid()){
                    // hdr.ipv4.protocol = PROTO_STAGE;
                    meta.alert.digestType = 2;
                    hdr.tcp.srcPort=SRC_ATK_PORT;
                    hdr.stage_transfer.setValid();
                    hdr.stage_transfer.stage = 2;
                    hdr.stage_transfer.mode = ENTROPY;
                    stats_freq_internal.read(median, (COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + meta.stats.Median);
                    hdr.stage_transfer.median = median;
                    hdr.stage_transfer.detected_subnet = meta.counter_value;
                    hdr.stage_transfer.detected_ip = 0;
                    // clone3(CloneType.I2E, 32w250, {});
                  }
                  stats_clear(COUNTER_TOPLEVEL);
                  subnetStart = (bit<16>) 0x0a00 ++ (bit<8>) (hdr.stage_transfer.detected_subnet);
                  subnet = subnetStart ++ (bit<8>) 0;
                  d_subnet.write(0, subnet);        
                } else if(stage == 2){
                  subnet = hdr.ipv4.dstAddr >> 8;
                  subnet = subnet << 8;
                  if(subnet == detected_subnet){
                    d_ip.write(0, meta.counter_value);
                    packet_track.write(0, 0);
                  }
                }
                // if(nval > peak){
                //   peak_nval.write(0, nval);
                //   peak_packet_count.write(0, atk_pkt_count+1);
                // }
              } 
              // else {
              //   if(nval < peak && peak_pkt_count == 0) {
              //     peak_packet_count.write(0, atk_pkt_count+1);
              //   }
              // }
            }
          }
          LFA: { 
            // run_lfa(median);
            bit<16> tmp;
            bit<32> bucket_idx;
            bit<1> tmpDistinctFlowsBit;
            bit<256> tmpDistinctFlowsByte;
            bit<256> tmpDistinctFlowsCurrent;
            bit<8> hash_posix;
            bit<32> index;
            bit<32> data_offset = COUNTER_REFINE * 4;
            bit<16> newmedian;
            bit<16> bigmedian;

            next_bucket.read(bucket_idx, 0);
            last_bucket_stamp.read(last_stamp, 0);
            median_s.read(bigmedian, 1);

            if(hdr.tcp.isValid()){
              stats_get_data(meta.stats, COUNTER_REFINE);
              stats_freq_internal.read(newmedian, (COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + meta.stats.Median);

              if(median!=0 && newmedian!=0 && 
                newmedian > median) {
                isLfa.write(0,1);
                median_s.write(1, newmedian);
                packet_track.write(0, 0);
                // if((bit<32>)newmedian > peak){
                //   peak_nval.write(0, (bit<32>)newmedian);
                //   peak_packet_count.write(0, atk_pkt_count+1);
                // }
              } 
              // else {
              //   //track peak
              //   if(bigmedian > 0 && newmedian < peak && peak_pkt_count == 0 && atk_pkt_count > 0){
              //     peak_packet_count.write(0, atk_pkt_count+1);
              //   }
              // }
              
              // && saved_stage == 1
              hash(index, HashAlgorithm.crc32,  32w0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr}, 32w8);
              //hash and then put to data structure
              hash(hash_posix, HashAlgorithm.crc32, 32w0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr}, 32w256); // must be interpreted as 256-ix

              distinctFlows.read(tmpDistinctFlowsCurrent, index);        
              tmpDistinctFlowsByte = tmpDistinctFlowsCurrent << hash_posix;
              // log_msg("bit_first_shift={}", {tmpDistinctFlowsByte});
              tmpDistinctFlowsByte = tmpDistinctFlowsByte >> 255;
              // tmpDistinctFlowsByte = tmpDistinctFlowsCurrent[hash_posix:hash_posix];
              // log_msg("bit={}", {tmpDistinctFlowsByte});
              // log_msg("index={}", {index});
              // log_msg("hash_posix={}", {hash_posix});

              if(tmpDistinctFlowsByte == 0){
                median_90_tick(COUNTER_REFINE);
                stats_push_freq(tmp, bucket_idx, COUNTER_REFINE); 
                tmpDistinctFlowsByte = 1;
                tmpDistinctFlowsByte = tmpDistinctFlowsByte << 255;
                // log_msg("bit_shifted={}", {tmpDistinctFlowsByte});
                tmpDistinctFlowsByte = tmpDistinctFlowsByte >> hash_posix;
                // log_msg("bit_modified={}", {tmpDistinctFlowsByte});
                tmpDistinctFlowsCurrent = tmpDistinctFlowsCurrent + tmpDistinctFlowsByte;
                // tmpDistinctFlowsCurrent[hash_posix] = 1;
                distinctFlows.write(index, tmpDistinctFlowsCurrent);
              }
              if (bucket_stamp > last_stamp) {
                //fix here
                distinctFlows.write(0,0);
                distinctFlows.write(1,0);
                distinctFlows.write(2,0);
                distinctFlows.write(3,0);
                distinctFlows.write(4,0);
                distinctFlows.write(5,0);
                distinctFlows.write(6,0);
                distinctFlows.write(7,0);

                // Current bucket interval elapsed. Finalize the bucket and increment.
                last_bucket_stamp.write(0, bucket_stamp);

                // Push bucket.
                bucket_idx = bucket_idx + 1;

                // Wrap last bucket index around if window is full.
                if (bucket_idx == WINDOW_SIZE) {
                  bucket_idx = 0;
                }
                
                // Ensure the new bucket is clean.
                drop_bucket(bucket_idx, COUNTER_REFINE);
                next_bucket.write(0, bucket_idx);
                //update rotation
                if(ticks<WINDOW_SIZE){
                  ticks_s.write(0, ticks + 1); //change mode each x ticks
                }
              }
            }
          }
          default: { 
            //do nothing
          }
        }
      }
    } 
  }
}

/* egress */
control MyEgress(inout headers hdr,
         inout metadata meta,
         inout standard_metadata_t standard_metadata) 
{
  apply { }
}

/* parsing */
parser MyParser(packet_in packet,
        out headers hdr,
        inout metadata meta,
        inout standard_metadata_t standard_metadata) 
{
  state start {
    packet.extract(hdr.ethernet);
    transition select(hdr.ethernet.etherType) {
      TYPE_IPV4: ipv4;
      default: accept;
    }
  }

  state ipv4 {
    packet.extract(hdr.ipv4);
    meta.ihlRem = hdr.ipv4.ihl - 4w5;
    meta.tcpLen = hdr.ipv4.totalLen - ((bit<16>)hdr.ipv4.ihl * 4);
    transition select(hdr.ipv4.protocol) {
      // PROTO_STAGE: stage_transfer;
      PROTO_TCP: tcp;
      PROTO_UDP: udp;
      default: accept;
    }
  }

  state udp {
    packet.extract(hdr.udp);
    transition select(hdr.udp.srcPort) {
      // we attach stage_transfer only if packet is from specific port - not the best option but it works
      SRC_ATK_PORT: stage_transfer;
      default: accept;
    }
  }

  state tcp {
    packet.extract(hdr.tcp);
    transition select(hdr.tcp.srcPort) {
      // we attach stage_transfer only if packet is from specific port - not the best option but it works
      SRC_ATK_PORT: stage_transfer;
      default: accept;
    }
  }

  state stage_transfer {
    packet.extract(hdr.stage_transfer);
    transition accept;
  }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


control MyDeparser(packet_out packet, in headers hdr) 
{
  apply {
    packet.emit(hdr.ethernet);
    packet.emit(hdr.ipv4);
    packet.emit(hdr.tcp);
    packet.emit(hdr.udp);
    packet.emit(hdr.stage_transfer);
  }
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