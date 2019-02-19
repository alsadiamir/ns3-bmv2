/* -*- P4_16 -*- */
#include <core.p4>
#include "enq_pipe.p4"
#include "dummy_blocks.p4"

/* Least Attained Service:
 * The flows with the least number of bytes serviced so far are given higher priority
 */

#define NUM_FLOWS 3
#define NUM_PRIORITIES 3
#define MAX_PKTS 3

control EnqueueLogic(inout headers hdr,
                     inout metadata meta,
                     inout standard_metadata_t standard_metadata) {

    bit<32> flow_id;
    bit<32> deq_windowID;
    bit<32> cur_windowID;
    bit<32> last_windowID;
    bit<32> pkt_count;
    register<bit<32>>(1) cur_window_reg;
    register<bit<32>>(NUM_FLOWS) last_window_reg;
    register<bit<32>>(NUM_FLOWS) pkt_count_reg;

    table enq_debug {
        key = {
            standard_metadata.enq_trigger : exact;
            standard_metadata.pkt_len : exact;
            standard_metadata.flow_hash : exact;
            standard_metadata.buffer_id : exact;
            standard_metadata.partition_id : exact;
            standard_metadata.partition_size : exact;
            standard_metadata.partition_max_size : exact;
            standard_metadata.timestamp : exact;
            standard_metadata.is_leaf : exact;
            standard_metadata.child_node_id : exact;
            standard_metadata.child_pifo_id : exact;
            standard_metadata.deq_trigger : exact;
            standard_metadata.deq_rank : exact;
            standard_metadata.deq_tx_time : exact;
            standard_metadata.deq_tx_delta : exact;
            standard_metadata.deq_user_meta : exact; // new
            standard_metadata.deq_pkt_len : exact;
            standard_metadata.deq_flow_hash : exact;
            standard_metadata.deq_buffer_id : exact;
            standard_metadata.deq_partition_id : exact;
            standard_metadata.deq_partition_size : exact;
            standard_metadata.deq_partition_max_size : exact;
        }
        actions = {
            NoAction;
        }
        const default_action = NoAction;
        size = 1;
    }

    apply {
        enq_debug.apply();

        enq_flow_id = standard_metadata.buffer_id;
        deq_flow_id = standard_metadata.deq_buffer_id;

        // update service_count
        /* NOTE: requires dual port service_count register because the enqueue
           and dequeue packets could belong to different flows
         */
        @atomic {
            if (standard_metadata.deq_trigger == 1) {
                service_count_reg.read(service_count, deq_flow_id);
                service_count = service_count + standard_metadata.deq_pkt_len;
                service_count_reg.write(deq_flow_id, service_count);
            }
            service_count_reg.read(service_count, enq_flow_id);
        }

        // set the outputs
        standard_metadata.rank = service_count;
        standard_metadata.pifo_id = 0;

    }
}

V1Switch(
DummyParser(),
DummyVerifyChecksum(),
EnqueueLogic(),
DummyEgress(),
DummyComputeChecksum(),
DummyDeparser()
) main;
