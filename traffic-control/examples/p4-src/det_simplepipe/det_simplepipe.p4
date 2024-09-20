/***
 * ================
 * Author: Sam Gao
 * Year:   2021
 * ================
 ***/

// A simple p4 switch that simply spits out 5 32 bit values in response to a single 32 bit value arriving
// with ethertype 0x88b5 (IEEE Std 802 - Local Experimental Ethertype 1).

#include <core.p4>
// #include <v1model.p4>
#include "v1model.p4"

// Needed before incuding stats_freq.p4.
#define STAT_FREQ_COUNTER_SIZE 600
#define STAT_FREQ_COUNTER_N 1

#include "stat4.p4"

#define BUCKET_SIZE 20
#define WINDOW_SIZE 10
#define STDEV_RANGE 2

// Counter indices.
#define COUNTER_TOPLEVEL  0
#define COUNTER_REFINE    1

// Other constants.
#define TYPE_IPV4 0x800
#define PROTO_TCP 6
#define PROTO_UDP 17
#define PROTO_EXPERIMENTAL 253
#define PROTO_STAGE 254

/* data types */
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

/* headers */
header ethernet_t {
    macAddr_t   dstAddr;
    macAddr_t   srcAddr;
    bit<16>     etherType;
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


@name("headers")
struct headers {
    ethernet_t  ethernet;
    // ipv4_t  ipv4;
    // tcp_t   tcp;
}

struct metadata {
    stats_t         stats;
}


/* checksum */
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}


/* ingress */
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    // The time-based sliding window is only used for top-level search.    
    register<bit<32>>(1)  next_bucket;
    register<bit<64>>(1)  last_bucket_stamp;
    register<bit<256>>(8) distinctFlows;
    register<bit<16>>(1) peak_packet_count;
    register<bit<32>>(1) peak_nval;    


    apply {
        //trying anomaly now

        bit<64> bucket_stamp = (bit<64>) standard_metadata.timestamp >> BUCKET_SIZE;      
        bit<64> last_stamp;
        bit<16> median;
        bit<16> atk_pkt_count = 0;
        bit<16> peak_pkt_count = 0;
        bit<32> peak = 0;

        if (hdr.ethernet.isValid()) {
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
            hash(index, HashAlgorithm.crc32,  32w0, {hdr.ethernet.srcAddr, hdr.ethernet.dstAddr}, 32w8);
            //hash and then put to data structure
            hash(hash_posix, HashAlgorithm.crc32, 32w0, {hdr.ethernet.srcAddr, hdr.ethernet.dstAddr}, 32w256);

            standard_metadata.trace_var1 = index;
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
              if (cval > 100 && nval > meta.stats.Xsum + (STDEV_RANGE * meta.stats.StdNX)) { // compare Nx
                // Exceeds defined threshold.
                // Send digest so that the controller can populate the second counter.
                drop_bucket(bucket_idx, COUNTER_TOPLEVEL);
                if(hdr.ethernet.isValid()){
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
            }

            // Increment the packets bucket
            stats_push_freq(tmp, bucket_idx, COUNTER_TOPLEVEL);
      }
    }
}

/* egress */
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

/* parsing */
parser MyParser(packet_in packet,
        out headers hdr,
        inout metadata meta,
        inout standard_metadata_t standard_metadata) 
{
//   state start {
//     packet.extract(hdr.ethernet);
//     transition select(hdr.ethernet.etherType) {
//       TYPE_IPV4: ipv4;
//       default: accept;
//     }
//   }

//   state ipv4 {
//     packet.extract(hdr.ipv4);
//     transition select(hdr.ipv4.protocol) {
//       PROTO_TCP: tcp;
//       default: accept;
//     }
//   }

//   state tcp {
//     packet.extract(hdr.tcp);
//     transition accept;
//   }

    state start {
        packet.extract(hdr.ethernet);
        transition accept;
    }    

}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        // packet.emit(hdr.ipv4);
        // packet.emit(hdr.tcp);
    }
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
