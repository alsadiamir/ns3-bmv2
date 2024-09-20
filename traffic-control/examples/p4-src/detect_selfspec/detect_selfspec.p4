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
header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

struct metadata {
  stats_t   stats;
  bit<32>   counter_value;
  bit<32>   index;
  bit<32>   hash_posix;
}

struct headers {
  ethernet_t              ethernet;
  ipv4_t                  ipv4;
  tcp_t                   tcp;
  udp_t                   udp;
  // debug_t                 debug;
}

/* ingress */
control MyIngress(inout headers hdr,
          inout metadata meta,
          inout standard_metadata_t standard_metadata) 
{

  // The time-based sliding window is only used for top-level search.    
  register<bit<32>>(1)  next_bucket;
  register<bit<48>>(1)  last_bucket_stamp;
  register<bit<8>>(1)   stage_s;

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

  action reset_counters() {
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
  }

  // action set_debug(bit<32> alert, bit<32> counter_value, bit<32> subnet, bit<32> ip, bit<32> lfa) {
  //   hdr.debug.setValid();
  //   hdr.debug.alert = alert;
  //   hdr.debug.counter_value = counter_value;
  //   hdr.debug.subnet = subnet;
  //   hdr.debug.ip = ip;
  //   hdr.debug.lfa = lfa;
  // }

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

    bit<8> stage;
    bit<8> mode;
    bit<16> median;
    bit<16> tmpMedian;
    bit<24> subnetStart;
    bit<32> subnet;
    bit<32> ip;

    bit<48> bucket_stamp;
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

    // hdr.debug.setInvalid();     
  
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

    //SET COUNTER
    if (hdr.ipv4.isValid() && window_track.apply().hit) {
      dest_prefix_track.apply();
      // d_subnet.write(0, hdr.ipv4.dstAddr);
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
          tmpDistinctFlowsByte = tmpDistinctFlowsByte >> 255;

          if(tmpDistinctFlowsByte == 0){
            median_90_tick(COUNTER_REFINE);
            stats_push_freq(tmp, bucket_idx, COUNTER_REFINE); 
            tmpDistinctFlowsByte = 1;
            tmpDistinctFlowsByte = tmpDistinctFlowsByte << 255;
            tmpDistinctFlowsByte = tmpDistinctFlowsByte >> hash_posix;
            tmpDistinctFlowsCurrent = tmpDistinctFlowsCurrent + tmpDistinctFlowsByte;
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

              drop_bucket(bucket_idx, COUNTER_TOPLEVEL);
              if(hdr.tcp.isValid()){
                // hdr.ipv4.protocol = PROTO_STAGE;
                // set_debug(ANOMALY, meta.counter_value, 0, 0, 0);
                stats_freq_internal.read(median, (COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + meta.stats.Median);
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
            subnet = hdr.ipv4.dstAddr >> 8;
            subnet = subnet << 8;
            ip = hdr.ipv4.dstAddr << 24;
            ip = ip >> 24;
            
            if(subnet == detected_subnet && detected_ip == ip){
              drop();
            }
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
                  stage_s.write(0, 2);
                  stats_clear(COUNTER_TOPLEVEL);
                  reset_counters();
                  subnetStart = (bit<16>) 0x0a01 ++ (bit<8>) (meta.counter_value);
                  subnet = subnetStart ++ (bit<8>) 0;
                  d_subnet.write(0, subnet);  
                  // if(detected_subnet == 0){
                  //   set_debug(SYN, meta.counter_value, subnet, 0, 0);
                  // }      
                } else if(stage == 2){
                  subnet = hdr.ipv4.dstAddr >> 8;
                  subnet = subnet << 8;
                  if(subnet == detected_subnet && detected_ip == 0){
                    d_ip.write(0, meta.counter_value);
                    // set_debug(SYN, meta.counter_value, subnet, meta.counter_value, 0);
                  }
                }
              } 
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

            // Identify the heavy flow destination.
            if (nval > meta.stats.Xsum + (STDEV_RANGE * meta.stats.StdNX)) {
              if(stage == 1){
                stage_s.write(0, 2);
                stats_clear(COUNTER_TOPLEVEL);
                reset_counters();
                subnetStart = (bit<16>) 0x0a01 ++ (bit<8>) (meta.counter_value);
                subnet = subnetStart ++ (bit<8>) 0;
                d_subnet.write(0, subnet);   
                // if(detected_subnet == 0){
                //   set_debug(ENTROPY, meta.counter_value, subnet, 0, 0);
                // }   
              } else if(stage == 2){
                subnet = hdr.ipv4.dstAddr >> 8;
                subnet = subnet << 8;
                // if(subnet == detected_subnet && detected_ip == 0){
                //   d_ip.write(0, meta.counter_value);
                //   set_debug(ENTROPY, meta.counter_value, subnet, meta.counter_value, 0);
                // }
              }
            } 
          }
        }
        LFA: { 
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
              // set_debug(LFA, (bit<32>)newmedian, 0, 0, 1);
              isLfa.write(0,1);
              median_s.write(1, newmedian);
              // packet_track.write(0, 0);
            } 
            
            // // && saved_stage == 1
            // hash(index, HashAlgorithm.crc32,  32w0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr}, 32w8);
            // //hash and then put to data structure
            // hash(hash_posix, HashAlgorithm.crc32, 32w0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr}, 32w256); // must be interpreted as 256-ix

            // bit<32> dst = hdr.ipv4.dstAddr;
            // dst = dst << 8;
            // dst = dst >> 8;

            // && saved_stage == 1
            // hash(index, HashAlgorithm.crc32,  32w0, {dst}, 32w8);
            //hash and then put to data structure
            // hash(hash_posix, HashAlgorithm.crc32, 32w0, {dst}, 32w256); // must be interpreted as 256-ix

            // hdr.debug.index = meta.index;
            // hdr.debug.hash_posix = meta.hash_posix;

            distinctFlows.read(tmpDistinctFlowsCurrent, meta.index);        
            tmpDistinctFlowsByte = tmpDistinctFlowsCurrent << (bit<8>) meta.hash_posix;
            tmpDistinctFlowsByte = tmpDistinctFlowsByte >> 255;

            if(tmpDistinctFlowsByte == 0){
              median_tick(COUNTER_REFINE);
              stats_push_freq(tmp, bucket_idx, COUNTER_REFINE); 
              tmpDistinctFlowsByte = 1;
              tmpDistinctFlowsByte = tmpDistinctFlowsByte << 255;
              tmpDistinctFlowsByte = tmpDistinctFlowsByte >> (bit<8>) meta.hash_posix;
              tmpDistinctFlowsCurrent = tmpDistinctFlowsCurrent + tmpDistinctFlowsByte;
              distinctFlows.write(meta.index, tmpDistinctFlowsCurrent);
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
              // if(ticks<WINDOW_SIZE){
              //   ticks_s.write(0, ticks + 1); //change mode each x ticks
              // }
            }
          }
        }
        default: { 
          //do nothing
        }
      }
    standard_metadata.egress_spec = 1;
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
    transition select(hdr.ipv4.protocol) {
      PROTO_TCP: tcp;
      PROTO_UDP: udp;
      default: accept;
    }
  }

  state udp {
    packet.extract(hdr.udp);
    transition accept;
  }

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
  apply {
    packet.emit(hdr);
    // packet.emit(hdr.debug);
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