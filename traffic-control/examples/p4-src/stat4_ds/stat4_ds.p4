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

#define WINDOW_SIZE 10
#define SPLIT_SIZE 5
#define STDEV_RANGE 2
#define STDEV_RANGE_DESPEC 20

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
#define HASH_SEED_1 32w12345
#define HASH_SEED_2 32w67890

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
  bit<1>    bit_value;
}

struct headers {
  p2p_t              p2p;
  ipv4_t             ipv4;
  tcp_t              tcp;
  udp_t                   udp;
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
  register<bit<32>>(1)  index_median_s;
  register<bit<32>>(1)  d_subnet;
  register<bit<32>>(1)  d_ip;
  register<bit<256>>(8) distinctFlows;
  register<bit<1>>(1) isLfa;
  register<bit<8>>(1) mode_s;
  register<bit<8>>(1) stat_s;
  register<bit<8>>(1) path_s;

  register<bit<8>>(1)  counter_value_s;
  register<bit<1>>(1)  sent_s;
  register<bit<3>>(1)  reset_s;
  register<bit<2>>(1)  specialize_s;
  register<bit<32>>(1) packets_s;
  register<bit<32>>(1) current_spec_packets_s;
  register<bit<32>>(2) bins_after_attack_s;
  register<bit<32>>(1) nval_packets_s;
  register<bit<32>>(1) nval_flows_s;
  register<bit<8>>(1) bucket_size_s;
  register<bit<32>>(1) delay_s;
  register<bit<1>>(1) policy_s; 
  register<bit<2>>(1) type_attack_s;
  register<bit<2>>(1) dec_trend_s;
  register<bit<32>>(4) nval_despec;
  register<bit<16>>(10) tmp_stats_freq_internal;
  register<bit<32>>(1) tmp_spike_despec_s;
  register<bit<32>>(1) tcp_count_s;
  register<bit<32>>(1) udp_count_s;

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

  action set_tracked_subnet() {
    meta.counter_value = (bit<32>) hdr.ipv4.dstAddr[15:8]; 
  }

  action set_tracked_ip() {
    bit<24> subnetStart;
    bit<32> subnet;
    bit<32> detected_subnet;
    bit<32> last_byte;

    subnetStart = hdr.ipv4.dstAddr[31:8];
    subnet = subnetStart ++ (bit<8>) 0;

    d_subnet.read(detected_subnet, 0);
    if(subnet == detected_subnet){
      last_byte = (bit<32>)hdr.ipv4.dstAddr[7:0];
      meta.counter_value = last_byte - 2;
    }    
  }

  action backup_counters(bit<32> idx){
    bit<16> tmp_c;
    stats_freq_internal.read(tmp_c, (idx * STAT_FREQ_COUNTER_SIZE) + 0);
    tmp_stats_freq_internal.write(0, tmp_c);
    stats_freq_internal.read(tmp_c, (idx * STAT_FREQ_COUNTER_SIZE) + 1);
    tmp_stats_freq_internal.write(1, tmp_c);
    stats_freq_internal.read(tmp_c, (idx * STAT_FREQ_COUNTER_SIZE) + 2);
    tmp_stats_freq_internal.write(2, tmp_c);
    stats_freq_internal.read(tmp_c, (idx * STAT_FREQ_COUNTER_SIZE) + 3);
    tmp_stats_freq_internal.write(3, tmp_c);
    stats_freq_internal.read(tmp_c, (idx * STAT_FREQ_COUNTER_SIZE) + 4);
    tmp_stats_freq_internal.write(4, tmp_c);
    stats_freq_internal.read(tmp_c, (idx * STAT_FREQ_COUNTER_SIZE) + 5);
    tmp_stats_freq_internal.write(5, tmp_c);
    stats_freq_internal.read(tmp_c, (idx * STAT_FREQ_COUNTER_SIZE) + 6);
    tmp_stats_freq_internal.write(6, tmp_c);
    stats_freq_internal.read(tmp_c, (idx * STAT_FREQ_COUNTER_SIZE) + 7);
    tmp_stats_freq_internal.write(7, tmp_c);
    stats_freq_internal.read(tmp_c, (idx * STAT_FREQ_COUNTER_SIZE) + 8);
    tmp_stats_freq_internal.write(8, tmp_c);
    stats_freq_internal.read(tmp_c, (idx * STAT_FREQ_COUNTER_SIZE) + 9);
    tmp_stats_freq_internal.write(9, tmp_c);
  }

  action reset_counters(bit<32> idx) { 
    stats_freq_internal.write((idx * STAT_FREQ_COUNTER_SIZE), 0);
    stats_freq_internal.write((idx * STAT_FREQ_COUNTER_SIZE) + 1, 0);
    stats_freq_internal.write((idx * STAT_FREQ_COUNTER_SIZE) + 2, 0);
    stats_freq_internal.write((idx * STAT_FREQ_COUNTER_SIZE) + 3, 0);
    stats_freq_internal.write((idx * STAT_FREQ_COUNTER_SIZE) + 4, 0);
    stats_freq_internal.write((idx * STAT_FREQ_COUNTER_SIZE) + 5, 0);
    stats_freq_internal.write((idx * STAT_FREQ_COUNTER_SIZE) + 6, 0);
    stats_freq_internal.write((idx * STAT_FREQ_COUNTER_SIZE) + 7, 0);
    stats_freq_internal.write((idx * STAT_FREQ_COUNTER_SIZE) + 8, 0);
    stats_freq_internal.write((idx * STAT_FREQ_COUNTER_SIZE) + 9, 0);
    stats_freq_internal.write((idx * STAT_FREQ_COUNTER_SIZE) + 10, 0);
    stats_last_clear.write((idx * STAT_FREQ_COUNTER_SIZE), 0);
    stats_last_clear.write((idx * STAT_FREQ_COUNTER_SIZE) + 1, 0);
    stats_last_clear.write((idx * STAT_FREQ_COUNTER_SIZE) + 2, 0);
    stats_last_clear.write((idx * STAT_FREQ_COUNTER_SIZE) + 3, 0);
    stats_last_clear.write((idx * STAT_FREQ_COUNTER_SIZE) + 4, 0);
    stats_last_clear.write((idx * STAT_FREQ_COUNTER_SIZE) + 5, 0);
    stats_last_clear.write((idx * STAT_FREQ_COUNTER_SIZE) + 6, 0);
    stats_last_clear.write((idx * STAT_FREQ_COUNTER_SIZE) + 7, 0);
    stats_last_clear.write((idx * STAT_FREQ_COUNTER_SIZE) + 8, 0);
    stats_last_clear.write((idx * STAT_FREQ_COUNTER_SIZE) + 9, 0);
    stats_last_clear.write((idx * STAT_FREQ_COUNTER_SIZE) + 10, 0);
  }

  action hash_subnet(bit<32> h_sub) {
    meta.counter_value = h_sub;
  }

  action extract_bit(bit<32> index, bit<8> hash_posix) {
    bit<256> reg_val;
    distinctFlows.read(reg_val, index);  // Read the register (index 0)
    bit<256> maskreg = 1;
    maskreg = maskreg << hash_posix;  // Correctly shift within bit<256>
    if( (reg_val & maskreg) != 0){
      meta.bit_value = 1;
    }
  }

  action set_bit(bit<32> index, bit<8> hash_posix) {
    bit<256> reg_val;
    distinctFlows.read(reg_val, index);  // Read current register value
    bit<256> maskreg = 1;
    maskreg = maskreg << hash_posix;  // Correctly shift within bit<256>
    reg_val = reg_val | maskreg;  // Set bit i to 1
    distinctFlows.write(index, reg_val);  // Write back to the register
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

  table prefix_hash {
    key = {
      hdr.ipv4.dstAddr: lpm;
    }
    actions = {
      hash_subnet;
      NoAction;
    }
    size = 16;
    default_action = NoAction;
  }  

  apply { 

    bit<8> stage;
    bit<8> mode;
    bit<8> stat;
    bit<16> median1;
    bit<16> median2;
    bit<32> index_median;
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
    bit<1> sent;
    bit<3> reset;
    bit<2> specialize;
    bit<32> packets;
    bit<32> current_spec_packets;
    bit<32> bins_start;
    bit<32> bins_after_attack;
    bit<1> policy;
    bit<9> egress_prio; 
    bit<32> saved_nval;
    bit<32> saved_flows_nval;
    bit<32> median_tmp;
    bit<8> bucket_size;
    bit<32> delay;

    bit<32> spike_index_anomaly;
    bit<32> spike_index_entropy;
    bit<32> bucket_idx;
    bit<2> type_attack;
    bit<2> dec_trend;
    bit<32> tmp_spike_despec;
    bit<32> tcp_count;
    bit<32> udp_count;

    type_attack_s.read(type_attack, 0);
    next_bucket.read(bucket_idx, 0);
    
    // Default no-match value.
    meta.counter_value = 0xdeadbeef;
    bucket_size_s.read(bucket_size, 0);
    bucket_stamp = standard_metadata.ingress_global_timestamp >> bucket_size;
    stage_s.read(stage, 0);
    mode_s.read(mode, 0);
    stat_s.read(stat, 0);
    path_s.read(path, 0);
    median_s.read(median1, 0);
    median_s.read(median2, 1);
    index_median_s.read(index_median, 0);
    nval_packets_s.read(saved_nval, 0);
    nval_flows_s.read(saved_flows_nval, 0);

    d_subnet.read(detected_subnet, 0);
    d_ip.read(detected_ip, 0);
    last_bucket_stamp.read(last_stamp, 0);
    isLfa.read(lfa, 0);
    packets_s.read(packets, 0);
    current_spec_packets_s.read(current_spec_packets, 0);
    bins_after_attack_s.read(bins_start, 0);
    bins_after_attack_s.read(bins_after_attack, 1);
    sent_s.read(sent, 0);
    specialize_s.read(specialize, 0);
    reset_s.read(reset, 0);
    policy_s.read(policy, 0);
    delay_s.read(delay, 0);
    dec_trend_s.read(dec_trend, 0);
    tmp_spike_despec_s.read(tmp_spike_despec, 0);
    tcp_count_s.read(tcp_count, 0);
    udp_count_s.read(udp_count, 0);

    if(hdr.udp.isValid()){
      udp_count_s.write(0, udp_count + 1);
    } else if(hdr.tcp.isValid()){
      tcp_count_s.write(0, tcp_count + 1);
    }

    //SET COUNTER
    if (hdr.ipv4.isValid()) {
      dest_prefix_track.apply();

      if(hdr.ipv4.tos == 17 && mode != ANOMALY){ //reset stat4 - spike ended
        reset_counters(COUNTER_TOPLEVEL);
        mode_s.write(0, ANOMALY);
        mode = ANOMALY;
        stage_s.write(0, 0);
        stage = 0;
        stats_clear(COUNTER_TOPLEVEL);

        d_subnet.write(0, 0);
        detected_subnet = 0;
        d_ip.write(0, 0);
        detected_ip = 0;
        hdr.ipv4.tos = 0;
        packets_s.write(0, 0);
        current_spec_packets_s.write(0, 0);
        bins_after_attack_s.write(0, 0);
        bins_after_attack_s.write(1, 0);
        bins_after_attack = 0;
        bins_start = 0;
        current_spec_packets = 0;
        isLfa.write(0, 0);
        standard_metadata.priority = 3;
      } else{
        if(hdr.ipv4.tos == 16 && mode != ENTROPY){
          reset_counters(COUNTER_TOPLEVEL);
          mode_s.write(0, ENTROPY);
          mode = ENTROPY;
          stage_s.write(0, 1);
          stage = 1;
          hdr.ipv4.tos = 0;
        }
      }
      // bit<1> right_detection = ((detected_subnet != 0 && detected_ip != 0 && type_attack == 1) || 
      //    (lfa == 1 && type_attack == 2)) ? (bit<1>) 1 : 0;
      if(current_spec_packets != 0){
        current_spec_packets_s.write(0, current_spec_packets+1);
      }
      if(hdr.udp.isValid()){
       if(current_spec_packets == 0){
          current_spec_packets_s.write(0, 1);
        }      
        if(bins_start == 0){
          bins_after_attack_s.write(0, bins_after_attack);
        }
      }

      standard_metadata.egress_spec = 3;
      bit<16> tmp;
      bit<16> cval; //used for both flows and packets
      bit<32> nval; //used for both flows and packets

      switch (mode) {
        ANOMALY: { 
          //PACKET counting
          //increment packets
          stats_push_freq(tmp, bucket_idx, COUNTER_TOPLEVEL);

          //LFA
          //update flows
          //FLOW counting
          bit<1> tmpDistinctFlowsBit;
          bit<256> tmpDistinctFlowsByteTmp;
          bit<256> tmpDistinctFlowsByte;
          bit<256> tmpDistinctFlowsCurrent;
          bit<8> hash_posix;
          bit<32> index;
          bit<16> srcPort = 0;
          bit<16> dstPort = 0;

          if(hdr.udp.isValid()){
            srcPort = hdr.udp.srcPort;
            dstPort = hdr.udp.dstPort;
          } else{
            if(hdr.tcp.isValid()){
              srcPort = hdr.tcp.srcPort;
              dstPort = hdr.tcp.dstPort;
            }
          }
          
          //register flows
          hash(index, HashAlgorithm.crc32, HASH_SEED_1, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, srcPort, dstPort}, 32w8);
          index = index & 0x7;
          //hash and then put to data structure
          hash(hash_posix, HashAlgorithm.crc32, HASH_SEED_2, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, srcPort, dstPort}, 8w255);

          bit<256> reg_val;
          distinctFlows.read(reg_val, index);  // Read the register (index 0)
          bit<256> maskreg = 1;
          maskreg = maskreg << hash_posix;  // Correctly shift within bit<256>
          if( (reg_val & maskreg) != 0){
            meta.bit_value = 1; // do not update
          }
          
          if(meta.bit_value == 0){
            //increment flows
            stats_push_freq(tmp, bucket_idx, COUNTER_REFINE);
            reg_val = reg_val | maskreg;  // Set bit i to 1
            distinctFlows.write(index, reg_val);  // Write back to the register
          }
          
          if(bucket_stamp > last_stamp) {
            if(reset > 0 && reset < 2){
              if(reset==1){
                backup_counters(COUNTER_TOPLEVEL);
              }
              reset = reset + 1;
              reset_s.write(0, reset); // we wait a bit before resetting
            }
            last_bucket_stamp.write(0, bucket_stamp);
            
            //LFA
            distinctFlows.write(0,0);
            distinctFlows.write(1,0);
            distinctFlows.write(2,0);
            distinctFlows.write(3,0);
            distinctFlows.write(4,0);
            distinctFlows.write(5,0);
            distinctFlows.write(6,0);
            distinctFlows.write(7,0);            

            //grab CVAL
            read_bucket(cval, bucket_idx, COUNTER_REFINE);
            stats_get_data(meta.stats, COUNTER_REFINE);

            //compute NVAL
            nval = (bit<32>)cval * meta.stats.N;
            stats_freq_internal.read(tmpMedian, (COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + meta.stats.Median);

            // if (median1 > 0 && median2 > 0 && median2 > median1 && tmpMedian > median2 && index_median == 0 && meta.stats.N == 10) { // compare Nx
            if (nval > meta.stats.Xsum + (STDEV_RANGE * meta.stats.StdNX)) { // compare Nx
              if(nval > saved_flows_nval){ //packet spike update
                nval_flows_s.write(0, nval);
              } 
              // standard_metadata.priority = 7;
              // isLfa.write(0, 1);
            }
            
            // Ensure the new bucket is clean.
            
            median_s.write(index_median, tmpMedian);  
            index_median = index_median + 1;
            if(index_median == 2){
              index_median = 0;
            } 
            index_median_s.write(0, index_median); 
            //END LFA

            //check packets
            //grab CVAL
            read_bucket(cval, bucket_idx, COUNTER_TOPLEVEL);
            stats_get_data(meta.stats, COUNTER_TOPLEVEL);
            //compute NVAL
            nval = (bit<32>)cval * meta.stats.N;
            if (nval > meta.stats.Xsum + (STDEV_RANGE * meta.stats.StdNX)) { // compare Nx
              if(nval > saved_nval){ //packet spike update
                nval_packets_s.write(0, nval);
              } 
              sent_s.write(0, 1);
              // sent=1;
              specialize_s.write(0, 1);
              specialize=1;
              if(packets == 0){
                packets_s.write(0,(bit<32>)cval);
              }
              
              standard_metadata.priority = 4;
            }

            if(sent == 1){
              // read_bucket(cval, bucket_idx, COUNTER_TOPLEVEL);
              // stats_get_data(meta.stats, COUNTER_TOPLEVEL);
              // //compute NVAL
              // nval = (bit<32>)cval * meta.stats.N;
              // saved_nval = saved_nval >> 1;
              bit<32> thr;
              if(10*meta.stats.Xsum < STDEV_RANGE_DESPEC * meta.stats.StdNX){
                thr = 0;
              } else {
                thr = 10*meta.stats.Xsum - (STDEV_RANGE_DESPEC * meta.stats.StdNX);
              }
              if(dec_trend == 0) {
                if(10*nval < thr){
                  dec_trend_s.write(0, dec_trend + 1);
                  tmp_spike_despec_s.write(0, 10*nval);
                } else {
                  dec_trend_s.write(0, 0);
                  tmp_spike_despec_s.write(0, 0);
                }
              } else if(dec_trend == 1) {
                if(10*nval <= tmp_spike_despec){
                  dec_trend_s.write(0, dec_trend + 1);
                  
                  nval_despec.write(0, 10*nval);
                  nval_despec.write(1, thr);
                  nval_despec.write(2, 10*meta.stats.Xsum);
                  nval_despec.write(3, STDEV_RANGE_DESPEC * meta.stats.StdNX);
                } else {
                  dec_trend_s.write(0, 0);
                  tmp_spike_despec_s.write(0, 0);
                }
              } else if(dec_trend == 2) {
                // if(10*nval < thr){
                  reset = 1;
                  reset_s.write(0, reset);
                  sent_s.write(0, 0);
                  tmp_spike_despec_s.write(0, 0);
                  dec_trend_s.write(0, 0);
                // } 
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
            //LFA
            drop_bucket(bucket_idx, COUNTER_REFINE);
            //END LFA
            next_bucket.write(0, bucket_idx);
      
            bins_after_attack_s.write(1, bins_after_attack + 1);
            
          }

          if(specialize == 1 && hdr.ipv4.dstAddr != 0x0b000001 && hdr.ipv4.dstAddr != 0x0a000001){
            hdr.ipv4.tos = 16;      
            specialize_s.write(0, 0);
            standard_metadata.egress_spec = 0; //we use queue = 1 for specialization messages            
          }

          if(reset == 2){
            if(hdr.ipv4.dstAddr != 0x0b000001 && hdr.ipv4.dstAddr != 0x0a000001){
              hdr.ipv4.tos = 17;
              nval_packets_s.write(0, 0);
              isLfa.write(0, 0);
              reset_s.write(0, 0);
              standard_metadata.egress_spec = 0; //we use queue = 1 for specialization messages
              current_spec_packets_s.write(0, 0);
              bins_after_attack_s.write(1, 0);
              bins_after_attack_s.write(0, 0);
              bins_after_attack = 0;
              bins_start = 0;
              current_spec_packets = 0;
              // standard_metadata.priority = 3;
            }
          }
        }
        ENTROPY: { 
          bit<32> ip_byte_selected;
          ip_byte_selected = hdr.ipv4.dstAddr; 
          ip_byte_selected = ip_byte_selected >> 8;
          ip_byte_selected = ip_byte_selected << 16;
          ip_byte_selected = ip_byte_selected >> 24;
          counter_value_s.write(0, hdr.ipv4.dstAddr[23:16]);
          subnet = hdr.ipv4.dstAddr >> 8;
          subnet = subnet << 8;
          ip = hdr.ipv4.dstAddr << 24;
          ip = ip >> 24;
          
          //get the stage
          switch (stage) {
            1: { //track subnets - 1
              set_tracked_subnet();
              prefix_hash.apply();
            }
            2: { //track ips - 2
              set_tracked_ip();
            }
            default: { 
              //do nothing
            }
          }

          if(delay > 0){
            if(stat == SYN){
              if(hdr.tcp.isValid() && hdr.tcp.flags == 0x02){
                packets_s.write(0, packets + 1);
              }  
            } else{
              packets_s.write(0, packets + 1);
            }            
          }
          //keep going - check syn and normal packets
          bit<1> track_stat = 0;
          if(stat == SYN){
            if(hdr.tcp.isValid() && hdr.tcp.flags == 0x02){
              track_stat = 1;
            }  
          } else{
            track_stat = 1;
          } 
          
          if (meta.counter_value != 0xdeadbeef && hdr.ipv4.isValid()) {
            //LFA
            //update flows
            //FLOW counting
            bit<1> tmpDistinctFlowsBit;
            bit<256> tmpDistinctFlowsByteTmp;
            bit<256> tmpDistinctFlowsByte;
            bit<256> tmpDistinctFlowsCurrent;
            bit<8> hash_posix;
            bit<32> index;
            bit<16> srcPort = 0;
            bit<16> dstPort = 0;

            if(hdr.udp.isValid()){
              srcPort = hdr.udp.srcPort;
              dstPort = hdr.udp.dstPort;
            } else{
              if(hdr.tcp.isValid()){
                srcPort = hdr.tcp.srcPort;
                dstPort = hdr.tcp.dstPort;
              }
            }

            //register flows
            hash(index, HashAlgorithm.crc32, HASH_SEED_2, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, srcPort, dstPort}, 32w8);
            index = index & 0x7;
            //hash and then put to data structure
            hash(hash_posix, HashAlgorithm.crc32, HASH_SEED_2, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, srcPort, dstPort}, 8w255);

            bit<256> reg_val;
            distinctFlows.read(reg_val, index);  // Read the register (index 0)
            bit<256> maskreg = 1;
            maskreg = maskreg << hash_posix;  // Correctly shift within bit<256>
            if( (reg_val & maskreg) != 0){
              meta.bit_value = 1; // do not update
            }
          
            if(meta.bit_value == 0){
              //increment flows
              stats_push_freq(tmp, bucket_idx, COUNTER_REFINE);
              reg_val = reg_val | maskreg;  // Set bit i to 1
              distinctFlows.write(index, reg_val);  // Write back to the register
            }

            if(bucket_stamp > last_stamp) {
              last_bucket_stamp.write(0, bucket_stamp);
              //LFA
              distinctFlows.write(0,0);
              distinctFlows.write(1,0);
              distinctFlows.write(2,0);
              distinctFlows.write(3,0);
              distinctFlows.write(4,0);
              distinctFlows.write(5,0);
              distinctFlows.write(6,0);
              distinctFlows.write(7,0);

              //grab CVAL
              read_bucket(cval, bucket_idx, COUNTER_REFINE);
              stats_get_data(meta.stats, COUNTER_REFINE);

              //compute NVAL
              nval = (bit<32>)cval * meta.stats.N;
              stats_freq_internal.read(tmpMedian, (COUNTER_REFINE * STAT_FREQ_COUNTER_SIZE) + meta.stats.Median);

              // if (median1 > 0 && median2 > 0 && median2 > median1 && tmpMedian > median2 && index_median == 0 && meta.stats.N == 10) { // compare Nx
              if (nval > meta.stats.Xsum + (STDEV_RANGE * meta.stats.StdNX)) { // compare Nx
                if(nval > saved_flows_nval){ //packet spike update
                  nval_flows_s.write(0, nval);
                } 
                standard_metadata.priority = 7;
                bins_after_attack_s.write(0, bins_after_attack);
                isLfa.write(0, 1);
              }
              
              // Ensure the new bucket is clean.
              
              median_s.write(index_median, tmpMedian);  
              index_median = index_median + 1;
              if(index_median == 2){
                index_median = 0;
              } 
              index_median_s.write(0, index_median); 
              //END LFA

              // Push bucket.
              bucket_idx = bucket_idx + 1;

              // Wrap last bucket index around if window is full.
              if (bucket_idx == WINDOW_SIZE) {
                bucket_idx = 0;
              }
              drop_bucket(bucket_idx, COUNTER_REFINE);
              next_bucket.write(0, bucket_idx);   
              bins_after_attack_s.write(1, bins_after_attack + 1);
                   
            }

            if(packets >= delay && track_stat == 1){
              stats_push_freq(tmp, meta.counter_value, COUNTER_TOPLEVEL);
              stats_get_data(meta.stats, COUNTER_TOPLEVEL);
              
              if(stage == 2){
                meta.stats.N = 10;
              }

              nval = (bit<32>)tmp * meta.stats.N;

              if(stage == 1){
                if (nval > meta.stats.Xsum + (STDEV_RANGE * meta.stats.StdNX)) {
                  stage_s.write(0, 2);
                  stage=2;
                  reset_counters(COUNTER_TOPLEVEL);
                  stats_clear(COUNTER_TOPLEVEL);
                  subnetStart = hdr.ipv4.dstAddr[31:8];
                  subnet = subnetStart ++ (bit<8>) 0;
                  d_subnet.write(0, subnet); 
                  if(detected_subnet == 0){
                    standard_metadata.priority = 5;
                  } 
                  //current_spec_packets_s.write(0, 0);
                }
              } else if(stage == 2){
                if (nval > meta.stats.Xsum + (STDEV_RANGE * meta.stats.StdNX) && tmp > 10) {
                  subnet = hdr.ipv4.dstAddr >> 8;
                  subnet = subnet << 8;
                  if(subnet == detected_subnet && detected_ip == 0){
                    d_ip.write(0, meta.counter_value+2);
                  }
                  if(detected_ip == 0){
                    standard_metadata.priority = 6;
                  }
                }
              }
            }
          }
          if (policy == 0) { //deprio
            if((subnet == detected_subnet && detected_ip == ip) || (lfa == 1 && hdr.udp.isValid())){
              standard_metadata.egress_spec = 3; //malicious
            } 
            else{
              standard_metadata.egress_spec = 0;
            }
          } 
          if (policy == 1) { //drop
            if((subnet == detected_subnet && detected_ip == ip) || (lfa == 1 && hdr.udp.isValid())){
              drop();
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
    packet.extract(hdr.p2p);
    transition ipv4;
  }

  state ipv4 {
    packet.extract(hdr.ipv4);
    transition select(hdr.ipv4.protocol) {
      PROTO_TCP: tcp;
      PROTO_UDP: udp;
      default: accept;
    }
  }

  state tcp {
    packet.extract(hdr.tcp);
    transition accept;
  }

  state udp {
    packet.extract(hdr.udp);
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