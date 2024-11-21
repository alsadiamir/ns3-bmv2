/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
*************************************************************************/

#define NUM_EGRESS_PORTS    512
#define NUM_CLUSTERS        4

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

typedef bit<9>  PortId_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<32> QueueId_t;

header p2p_h{
  //towaste
  bit<16>     proto;
}

header ipv4_h {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> len;
    bit<16> id;
    bit<3>  flags;
    bit<13> frag_offset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<8> dst0;
    bit<8> dst1;
    bit<8> dst2;
    bit<8> dst3;
}

header transport_h {
    bit<16> sport;
    bit<16> dport;
}

header resubmit_h {
    bit<8> cluster_id;
    bit<8> update_activated;
}

// @pa_container_size("ingress", "meta.rs.cluster_id", 8)
// @pa_container_size("ingress", "meta.rs.update_activated", 8)

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

/* All the headers we plan to process in the ingress */
struct headers {
    p2p_h p2p;
    ipv4_h ipv4;
    transport_h  transport;
}

/* All intermediate results that need to be available 
 * to all P4-programmable components in ingress
 */
struct metadata { // We will have to initialize them
    bit<8> cluster_id;
    bit<8> update_activated;

    /* Cluster 1 */
    bit<32> cluster1_dst0_distance;  
    bit<32> cluster1_dst1_distance;
    bit<32> cluster1_dst2_distance;
    bit<32> cluster1_dst3_distance;

    /* Cluster 2 */
    bit<32> cluster2_dst0_distance;  
    bit<32> cluster2_dst1_distance;
    bit<32> cluster2_dst2_distance;
    bit<32> cluster2_dst3_distance;

    /* Cluster 3 */
    bit<32> cluster3_dst0_distance;  
    bit<32> cluster3_dst1_distance;
    bit<32> cluster3_dst2_distance;
    bit<32> cluster3_dst3_distance;

    /* Cluster 4 */
    bit<32> cluster4_dst0_distance;  
    bit<32> cluster4_dst1_distance;
    bit<32> cluster4_dst2_distance;
    bit<32> cluster4_dst3_distance;

    // Distance helpers
    bit<32> min_d1_d2;
    bit<32> min_d3_d4;
    bit<32> min_d1_d2_d3_d4;
    
    // Initialization
    bit<8> init_counter_value;
    bit<1> resubmit_type;

    QueueId_t qid;
}

parser MyParser(packet_in packet,
        out headers hdr,
        inout metadata meta,
        inout standard_metadata_t standard_metadata)  
{

    state start {
        
        // /* Mandatory code required by Tofino Architecture */
        // pkt.extract(ig_intr_md);

        // /* We hardcode the egress port (all packets towards port 140) */
        // standard_metadata.egress_spec = 140;

        /* Cluster 1 */
        meta.cluster1_dst0_distance = 0;
        meta.cluster1_dst1_distance = 0;
        meta.cluster1_dst2_distance = 0;
        meta.cluster1_dst3_distance = 0;

        /* Cluster 2 */
        meta.cluster2_dst0_distance = 0;
        meta.cluster2_dst1_distance = 0;
        meta.cluster2_dst2_distance = 0;
        meta.cluster2_dst3_distance = 0;

        /* Cluster 3 */
        meta.cluster3_dst0_distance = 0;
        meta.cluster3_dst1_distance = 0;
        meta.cluster3_dst2_distance = 0;
        meta.cluster3_dst3_distance = 0;

        /* Cluster 4 */
        meta.cluster4_dst0_distance = 0;
        meta.cluster4_dst1_distance = 0;
        meta.cluster4_dst2_distance = 0;
        meta.cluster4_dst3_distance = 0;

        // Distance helpers
        meta.min_d1_d2 = 0;
        meta.min_d3_d4 = 0;
        meta.min_d1_d2_d3_d4 = 0;

        packet.extract(hdr.p2p);
        /* Parser start point */
        transition parse_ipv4;
    }

    /* We only parse layer 4 if the packet is a first fragment (frag_offset == 0) and if ipv4 header contains no options (ihl == 5) */
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.frag_offset, hdr.ipv4.protocol, hdr.ipv4.ihl) {
            (0, 6, 5)  : parse_transport;
            (0, 17, 5) : parse_transport;
            default : accept;
        }
    }

    state parse_transport {
        packet.extract(hdr.transport);
        transition accept;
    }
}

control MyIngress(inout headers hdr,
          inout metadata meta,
          inout standard_metadata_t standard_metadata)
{   

    action drop() {
        mark_to_drop(standard_metadata);
    }

    /* Define variables, actions and tables here */
    action set_qid(QueueId_t qid) {
        meta.qid = qid;
    }

    /* Define variables, actions and tables here */
    action set_prio_egress(bit<9> prio) {
        standard_metadata.egress_spec = prio;
    }

    table cluster_to_prio {
        key = {
            meta.cluster_id : exact;
        }
        actions = {          
            set_qid;
            set_prio_egress;
            drop;
        }
        default_action = set_qid(0); // Lowest-priority queue.
        size = NUM_CLUSTERS;
    }

    //only monitoring one port
    register<bit<32>>(4) cluster1_min; // MIN dst0, dst1, dst2, dst3
    register<bit<32>>(4) cluster1_max; // MAX dst0, dst1, dst2, dst3
    register<bit<32>>(4) cluster2_min; // MIN dst0, dst1, dst2, dst3
    register<bit<32>>(4) cluster2_max; // MAX dst0, dst1, dst2, dst3
    register<bit<32>>(4) cluster3_min; // MIN dst0, dst1, dst2, dst3
    register<bit<32>>(4) cluster3_max; // MAX dst0, dst1, dst2, dst3
    register<bit<32>>(4) cluster4_min; // MIN dst0, dst1, dst2, dst3
    register<bit<32>>(4) cluster4_max; // MAX dst0, dst1, dst2, dst3
    /* Tables and actions to count the traffic of each cluster */
    register<bit<32>>(4) bytes_counter;
    /* Register to be used as counter for cluster initialization */
    register<bit<32>>(1) init_counter;
    /* Register to be used as counter to determine when to update clusters */
    register<bit<32>>(1) updateclusters_counter;

    action merge_dst1_to_dst0() {
        meta.cluster1_dst0_distance = meta.cluster1_dst0_distance + meta.cluster1_dst1_distance;
        meta.cluster2_dst0_distance = meta.cluster2_dst0_distance + meta.cluster2_dst1_distance;
        meta.cluster3_dst0_distance = meta.cluster3_dst0_distance + meta.cluster3_dst1_distance;
        meta.cluster4_dst0_distance = meta.cluster4_dst0_distance + meta.cluster4_dst1_distance;
    }

    action merge_dst2_to_dst0() {
        meta.cluster1_dst0_distance = meta.cluster1_dst0_distance + meta.cluster1_dst2_distance;
        meta.cluster2_dst0_distance = meta.cluster2_dst0_distance + meta.cluster2_dst2_distance;
        meta.cluster3_dst0_distance = meta.cluster3_dst0_distance + meta.cluster3_dst2_distance;
        meta.cluster4_dst0_distance = meta.cluster4_dst0_distance + meta.cluster4_dst2_distance;
    }

    action merge_dst3_to_dst0() {
        meta.cluster1_dst0_distance = meta.cluster1_dst0_distance + meta.cluster1_dst3_distance;
        meta.cluster2_dst0_distance = meta.cluster2_dst0_distance + meta.cluster2_dst3_distance;
        meta.cluster3_dst0_distance = meta.cluster3_dst0_distance + meta.cluster3_dst3_distance;
        meta.cluster4_dst0_distance = meta.cluster4_dst0_distance + meta.cluster4_dst3_distance;
    }

    action compute_min_first() {
        if (meta.cluster1_dst0_distance < meta.cluster2_dst0_distance) {
            meta.min_d1_d2 = meta.cluster1_dst0_distance;
        } else {
            meta.min_d1_d2 = meta.cluster2_dst0_distance;
        }

        if (meta.cluster3_dst0_distance < meta.cluster4_dst0_distance) {
            meta.min_d3_d4 = meta.cluster3_dst0_distance;
        } else {
            meta.min_d3_d4 = meta.cluster4_dst0_distance;
        }
    }

    action compute_min_second() {
        if (meta.min_d1_d2 < meta.min_d3_d4) {
            meta.min_d1_d2_d3_d4 = meta.min_d1_d2;
        } else {
            meta.min_d1_d2_d3_d4 = meta.min_d3_d4;
        }
    }

    action init_count(inout bit<32> data) {
        bit<8> current_value = 0;
        if (data < 5) {
            current_value = (bit<8>)data; // Cast data to 8 bits
        }
        data = data + 1; // Increment the register value
        meta.init_counter_value = current_value;
    }

    action updateclusters_count(inout bit<32> data) {
        bit<8> current_value = 0;
        if (data < 100) {
            data = data + 1; // Increment the register value
            current_value = (bit<8>)0; // Update activated is not set
        } else {
            data = 0; // Reset the counter
            current_value = (bit<8>)1; // Update activated is set
        }
        meta.update_activated = current_value;
    }

    // table bytes_count {
    //     key = {
    //         meta.cluster_id : exact;
    //     }
    //     actions = {
    //         count_bytes;
    //     }
    //     default_action = count_bytes; // Lowest-priority queue.
    //     size = NUM_CLUSTERS;
    // }

    /* Define the processing algorithm here */
    apply {
        /* Stage 0 */
        bit<32> data0;
        bit<32> data1;
        bit<32> data2;
        bit<32> data3;
        bit<32> distance = 0;
        bit<32> dst0 = (bit<32>)hdr.ipv4.dst0;  // Assuming `dst0` is the first 32 bits of the IPv4 destination
        bit<32> dst1 = (bit<32>)hdr.ipv4.dst1;  // Assuming `dst1` is the second 32 bits of the IPv4 destination
        bit<32> dst2 = (bit<32>)hdr.ipv4.dst2;  // Assuming `dst2` is the third 32 bits of the IPv4 destination
        bit<32> dst3 = (bit<32>)hdr.ipv4.dst3;  // Assuming `dst3` is the fourth 32 bits of the IPv4 destination

        bit<32> register_value;
        bit<8> current_value;
        bit<32> tmp;

        // If all headers are valid and metadata ready, we run the clustering algorithm
        if (hdr.ipv4.isValid()) {
            if (standard_metadata.priority == 0){ 

                // Read the value from the register for dst0
                cluster1_min.read(data0, 0);
                cluster1_min.read(data1, 1);
                cluster1_min.read(data2, 2);
                cluster1_min.read(data3, 3);              
                // Perform the comparison and compute the distance
                if (dst0 < data0) {
                    distance = data0 - dst0;
                    // Here, you can do something with the `distance` (e.g., store it in metadata, or use it for further processing)
                    meta.cluster1_dst0_distance = distance;  // Store in metadata if needed
                }
                if (dst1 < data1) {
                    distance = data1 - dst1;
                    meta.cluster1_dst1_distance = distance;
                }
                if (dst2 < data2) {
                    distance = data2 - dst2;
                    meta.cluster1_dst2_distance = distance;
                }
                if (dst3 < data3) {
                    distance = data3 - dst3;
                    meta.cluster1_dst3_distance = distance;
                }

                cluster2_min.read(data0, 0);
                cluster2_min.read(data1, 1);
                cluster2_min.read(data2, 2);
                cluster2_min.read(data3, 3);
                if (dst0 < data0) {
                    distance = data0 - dst0;
                    meta.cluster2_dst0_distance = distance;
                }
                if (dst1 < data1) {
                    distance = data1 - dst1;
                    meta.cluster2_dst1_distance = distance;
                }
                if (dst2 < data2) {
                    distance = data2 - dst2;
                    meta.cluster2_dst2_distance = distance;
                }
                if (dst3 < data3) {
                    distance = data3 - dst3;
                    meta.cluster2_dst3_distance = distance;
                }

                cluster3_min.read(data0, 0);
                cluster3_min.read(data1, 1);
                cluster3_min.read(data2, 2);
                cluster3_min.read(data3, 3);
                if (dst0 < data0) {
                    distance = data0 - dst0;
                    meta.cluster3_dst0_distance = distance;
                }
                if (dst1 < data1) {
                    distance = data1 - dst1;
                    meta.cluster3_dst1_distance = distance;
                }
                if (dst2 < data2) {
                    distance = data2 - dst2;
                    meta.cluster3_dst2_distance = distance;
                }
                if (dst3 < data3) {
                    distance = data3 - dst3;
                    meta.cluster3_dst3_distance = distance;
                }

                cluster4_min.read(data0, 0);
                cluster4_min.read(data1, 1);
                cluster4_min.read(data2, 2);
                cluster4_min.read(data3, 3);
                if (dst0 < data0) {
                    distance = data0 - dst0;
                    meta.cluster4_dst0_distance = distance;
                }
                if (dst1 < data1) {
                    distance = data1 - dst1;
                    meta.cluster4_dst1_distance = distance;
                }
                if (dst2 < data2) {
                    distance = data2 - dst2;
                    meta.cluster4_dst2_distance = distance;
                }
                if (dst3 < data3) {
                    distance = data3 - dst3;
                    meta.cluster4_dst3_distance = distance;
                }

                /* CLUSTER 1 */
                cluster1_max.read(data0, 0);
                cluster1_max.read(data1, 1);
                cluster1_max.read(data2, 2);
                if (meta.cluster1_dst0_distance == 0) {                   
                    // Perform the comparison and compute the distance
                    if (dst0 > data0) {
                        distance = dst0 - data0;
                    }
                    // Here, you can do something with the `distance` (e.g., store it in metadata, or use it for further processing)
                    meta.cluster1_dst0_distance = distance;  // Store in metadata if needed
                }
                if (meta.cluster1_dst1_distance == 0) {
                    if (dst1 > data1) {
                        distance = dst1 - data1;
                    }
                    meta.cluster1_dst1_distance = distance;
                }
                if (meta.cluster1_dst2_distance == 0) {
                    if (dst2 > data2) {
                        distance = dst2 - data2;
                    }
                    meta.cluster1_dst2_distance = distance;
                }

                /* CLUSTER 2 */
                cluster2_max.read(data0, 0);
                cluster2_max.read(data1, 1);
                cluster2_max.read(data2, 2);
                if (meta.cluster2_dst0_distance == 0) {
                    // Perform the comparison and compute the distance
                    if (dst0 > data0) {
                        distance = dst0 - data0;
                    }
                    // Here, you can do something with the `distance` (e.g., store it in metadata, or use it for further processing)
                    meta.cluster2_dst0_distance = distance;  // Store in metadata if needed
                }
                if (meta.cluster2_dst1_distance == 0) {
                    if (dst1 > data1) {
                        distance = dst1 - data1;
                    }
                    meta.cluster2_dst1_distance = distance;
                }
                if (meta.cluster2_dst2_distance == 0) {
                    if (dst2 > data2) {
                        distance = dst2 - data2;
                    }
                    meta.cluster2_dst2_distance = distance;
                }

                /* CLUSTER 3 */
                cluster3_max.read(data0, 0);
                cluster3_max.read(data1, 1);
                cluster3_max.read(data2, 2);
                if (meta.cluster3_dst0_distance == 0) {
                    // Perform the comparison and compute the distance
                    if (dst0 > data0) {
                        distance = dst0 - data0;
                    }
                    // Here, you can do something with the `distance` (e.g., store it in metadata, or use it for further processing)
                    meta.cluster3_dst0_distance = distance;  // Store in metadata if needed
                }
                if (meta.cluster3_dst1_distance == 0) {
                    if (dst1 > data1) {
                        distance = dst1 - data1;
                    }
                    meta.cluster3_dst1_distance = distance;
                }
                if (meta.cluster3_dst2_distance == 0) {
                    if (dst2 > data2) {
                        distance = dst2 - data2;
                    }
                    meta.cluster3_dst2_distance = distance;
                }

                /* CLUSTER 4 */
                cluster4_max.read(data0, 0);
                cluster4_max.read(data1, 1);
                cluster4_max.read(data2, 2);
                if (meta.cluster4_dst0_distance == 0) {
                    // Perform the comparison and compute the distance
                    if (dst0 > data0) {
                        distance = dst0 - data0;
                    }
                    // Here, you can do something with the `distance` (e.g., store it in metadata, or use it for further processing)
                    meta.cluster4_dst0_distance = distance;  // Store in metadata if needed
                }
                if (meta.cluster4_dst1_distance == 0) {
                    if (dst1 > data1) {
                        distance = dst1 - data1;
                    }
                    meta.cluster4_dst1_distance = distance;
                }
                if (meta.cluster4_dst2_distance == 0) {
                    if (dst2 > data2) {
                        distance = dst2 - data2;
                    }
                    meta.cluster4_dst2_distance = distance;
                }
                //merge_dst1_to_dst0_1_2();
                //merge_dst1_to_dst0_3_4();
                merge_dst1_to_dst0();

                cluster1_max.read(data3, 3);
                if (meta.cluster1_dst3_distance == 0) {
                    if (dst3 > data3) {
                        distance = dst3 - data3;
                    }
                    meta.cluster1_dst3_distance = distance;
                }

                cluster2_max.read(data3, 3);
                if (meta.cluster2_dst3_distance == 0) {
                    if (dst3 > data3) {
                        distance = dst3 - data3;
                    }
                    meta.cluster2_dst3_distance = distance;
                }

                cluster3_max.read(data3, 3);
                if (meta.cluster3_dst3_distance == 0) {
                    if (dst3 > data3) {
                        distance = dst3 - data3;
                    }
                    meta.cluster3_dst3_distance = distance;
                }

                cluster4_max.read(data3, 3);
                if (meta.cluster4_dst3_distance == 0) {
                    if (dst3 > data3) {
                        distance = dst3 - data3;
                    }
                    meta.cluster4_dst3_distance = distance;
                }

                merge_dst2_to_dst0();
                /* Stage 8 */
                merge_dst3_to_dst0();
                /* Stage 9 */
                compute_min_first();
                /* Stage 10 */
                compute_min_second();

                // Read the register value corresponding to the egress port
                init_counter.read(register_value, 0);
                // Apply the action to calculate the current value
                init_count(register_value);
                // Write the updated value back to the register
                init_counter.write(0, register_value);

                // Read the register value corresponding to the egress port
                updateclusters_counter.read(register_value, 0);
                // Apply the action to calculate if the update is activated
                updateclusters_count(register_value);
                // Write the updated value back to the register
                updateclusters_counter.write(0, register_value);

                /* Stage 11 */
                if (meta.min_d1_d2_d3_d4 == meta.cluster1_dst0_distance && meta.init_counter_value == 0) {
                    /* We select cluster 1. Get prio from cluster 1 */
                    meta.cluster_id = 1;
                } else if (meta.min_d1_d2_d3_d4 == meta.cluster2_dst0_distance && meta.init_counter_value == 0) {
                    /* We select cluster 2. Get prio from cluster 2 */
                    meta.cluster_id = 2;
                } else if (meta.min_d1_d2_d3_d4 ==  meta.cluster3_dst0_distance && meta.init_counter_value == 0) {
                    /* We select cluster 3. Get prio from cluster 3 */
                    meta.cluster_id = 3;
                } else if (meta.min_d1_d2_d3_d4 ==  meta.cluster4_dst0_distance && meta.init_counter_value == 0) {
                    /* We select cluster 4. Get prio from cluster 4 */
                    meta.cluster_id = 4;
                } else {
                    meta.cluster_id = meta.init_counter_value;
                    meta.update_activated = 1;
                }
                standard_metadata.priority = 1;

            } else {
                standard_metadata.priority = 0;
                // Resubmitted packet
                if (meta.update_activated == 1) {
                    if (meta.cluster_id == 1) {
                        cluster1_min.read(data0, 0);
                        if (dst0 < data0) {
                            distance = data0 - dst0;
                            cluster1_min.write(0, distance);
                        }
                        cluster1_min.read(data1, 1);
                        if (dst1 < data1) {
                            distance = data1 - dst1;
                            cluster1_min.write(1, distance);
                        }
                        cluster2_min.read(data2, 2);
                        if (dst2 < data2) {
                            distance = data2 - dst2;
                            cluster1_min.write(2, distance);
                        }
                        cluster2_min.read(data3, 3);
                        if (dst3 < data3) {
                            distance = data3 - dst3;
                            cluster1_min.write(3, distance);
                        }
                        cluster1_max.read(data0, 0);
                        if (dst0 > data0) {
                            distance = dst0 - data0;
                            cluster1_max.write(0, distance);
                        }
                        cluster1_max.read(data1, 1);
                        if (dst1 > data1) {
                            distance = dst1 - data1;
                            cluster1_max.write(1, distance);
                        }
                        cluster1_max.read(data2, 2);
                        if (dst2 > data2) {
                            distance = dst2 - data2;
                            cluster1_max.write(2, distance);
                        }
                        cluster1_max.read(data3, 3);
                        if (dst3 > data3) {
                            distance = dst3 - data3;
                            cluster1_max.write(3, distance);
                        }
                    }
                    if (meta.cluster_id == 2) {
                        cluster2_min.read(data0, 0);
                        if (dst0 < data0) {
                            distance = data0 - dst0;
                            cluster2_min.write(0, distance);
                        }
                        cluster2_min.read(data1, 1);
                        if (dst1 < data1) {
                            distance = data1 - dst1;
                            cluster2_min.write(1, distance);
                        }
                        cluster2_min.read(data2, 2);
                        if (dst2 < data2) {
                            distance = data2 - dst2;
                            cluster2_min.write(2, distance);
                        }
                        cluster2_min.read(data3, 3);
                        if (dst3 < data3) {
                            distance = data3 - dst3;
                            cluster2_min.write(3, distance);
                        }
                        cluster2_max.read(data0, 0);
                        if (dst0 > data0) {
                            distance = dst0 - data0;
                            cluster2_max.write(0, distance);
                        }
                        cluster2_max.read(data1, 1);
                        if (dst1 > data1) {
                            distance = dst1 - data1;
                            cluster2_max.write(1, distance);
                        }
                        cluster2_max.read(data2, 2);
                        if (dst2 > data2) {
                            distance = dst2 - data2;
                            cluster2_max.write(2, distance);
                        }
                        cluster2_max.read(data3, 3);
                        if (dst3 > data3) {
                            distance = dst3 - data3;
                            cluster2_max.write(3, distance);
                        }
                    }
                    if (meta.cluster_id == 3) {
                        cluster3_min.read(data0, 0);
                        if (dst0 < data0) {
                            distance = data0 - dst0;
                            cluster3_min.write(0, distance);
                        }
                        cluster3_min.read(data1, 1);
                        if (dst1 < data1) {
                            distance = data1 - dst1;
                            cluster3_min.write(1, distance);
                        }
                        cluster3_min.read(data2, 2);
                        if (dst2 < data2) {
                            distance = data2 - dst2;
                            cluster3_min.write(2, distance);
                        }
                        cluster3_min.read(data3, 3);
                        if (dst3 < data3) {
                            distance = data3 - dst3;
                            cluster3_min.write(3, distance);
                        }
                        cluster3_max.read(data0, 0);
                        if (dst0 > data0) {
                            distance = dst0 - data0;
                            cluster3_max.write(0, distance);
                        }
                        cluster3_max.read(data1, 1);
                        if (dst1 > data1) {
                            distance = dst1 - data1;
                            cluster3_max.write(1, distance);
                        }
                        cluster3_max.read(data2, 2);
                        if (dst2 > data2) {
                            distance = dst2 - data2;
                            cluster3_max.write(2, distance);
                        }
                        cluster3_max.read(data3, 3);
                        if (dst3 > data3) {
                            distance = dst3 - data3;
                            cluster3_max.write(3, distance);
                        }
                    }
                    if (meta.cluster_id == 4) {
                        cluster4_min.read(data0, 0);
                        if (dst0 < data0) {
                            distance = data0 - dst0;
                            cluster4_min.write(0, distance);
                        }
                        cluster4_min.read(data1, 1);
                        if (dst1 < data1) {
                            distance = data1 - dst1;
                            cluster4_min.write(1, distance);
                        }
                        cluster4_min.read(data2, 2);
                        if (dst2 < data2) {
                            distance = data2 - dst2;
                            cluster4_min.write(2, distance);
                        }
                        cluster4_min.read(data3, 3);
                        if (dst3 < data3) {
                            distance = data3 - dst3;
                            cluster4_min.write(3, distance);
                        }
                        cluster4_max.read(data0, 0);
                        if (dst0 > data0) {
                            distance = dst0 - data0;
                            cluster4_max.write(0, distance);
                        }
                        cluster4_max.read(data1, 1);
                        if (dst1 > data1) {
                            distance = dst1 - data1;
                            cluster4_max.write(1, distance);
                        }
                        cluster4_max.read(data2, 2);
                        if (dst2 > data2) {
                            distance = dst2 - data2;
                            cluster4_max.write(2, distance);
                        }
                        cluster4_max.read(data3, 3);
                        if (dst3 > data3) {
                            distance = dst3 - data3;
                            cluster4_max.write(3, distance);
                        }
                    }
                }                

                /* Stage 8: Get the priority and forward the resubmitted packet */
                cluster_to_prio.apply();

                /* Stage 9: Compute the amount of traffic mapped to each cluster */
                // bytes_counter.read(tmp, 0);
                // bytes_counter.write(0, tmp + 1);
                bit<32> current_count;
                bit<32> idx = (bit<32>) meta.cluster_id - 1;
            
                // Read the current counter value
                bytes_counter.read(current_count, idx);

                // Add the packet's byte count
                current_count = current_count + standard_metadata.packet_length;

                // Write back the updated count
                bytes_counter.write(idx, current_count);
            }
        }
    }
}


/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

control MyEgress(inout headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata)  {

    apply {
    }

}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}

control MyDeparser(packet_out packet, in headers hdr) {

    // Resubmit() do_resubmit;
    apply {
        packet.emit(hdr); // If the header is valid, will emit it. If not valid, will just jump to the next one.
    }
}

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply { }
}


/*************************************************************************
 ****************  F I N A L  P A C K A G E    ***************************
 *************************************************************************/
 
V1Switch(
  MyParser(),
  MyVerifyChecksum(),
  MyIngress(),
  MyEgress(),
  MyComputeChecksum(),
  MyDeparser()
) main;