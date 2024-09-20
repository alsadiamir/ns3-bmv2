/***
 * ================
 * Author: Sam Gao
 * Year:   2021
 * ================
 ***/

// Library for in-switch computation of statistical measures of arbitrary distributions.
// In the following, we focus on frequency distributions, where each element of the 
// distributions represents the frequency of a value of interest extracted from
// packets. Non-frequency distributions can be easily supported by changing how N, 
// Xsum and Xsum_sq are updated. For further details, we refer to the paper 
//  "Sam Gao, Mark Handley, and Stefano Vissicchio. Stats 101 in P4: Towards 
// In-Switch Anomaly Detection. Proc. HotNets, 2021."


#include <core.p4>
#include "simple_pipe.p4"

/***
 * stats_data:
 * [0]: N
 * [1]: Xsum = Ybar
 * [2]: Xsum_sq
 * [3]: Last clear request (initially 0).
 * where Y = NX. We can calculate Nx quite simply for any new x we want to compare
 * with the existing values, so this allows us to do comparisons.
 **
 * median_data:
 * [0]: Median bin
 * [1]: Higher-count.
 * [2]: Lower-count.
 ***/

register<bit<32>>(4 * STAT_FREQ_COUNTER_N) stats_data;
register<bit<32>>(4 * STAT_FREQ_COUNTER_N) median_data;
register<bit<16>>(STAT_FREQ_COUNTER_SIZE * STAT_FREQ_COUNTER_N) stats_freq_internal;
register<bit<32>>(STAT_FREQ_COUNTER_SIZE * STAT_FREQ_COUNTER_N) stats_last_clear;


action read_bucket(out bit<16> val, bit<32> idx, bit<32> counter_idx) {
    bit<32> val_write = (counter_idx * STAT_FREQ_COUNTER_SIZE) + idx; // offset
    stats_freq_internal.read(val, val_write);
}

// zeros a single bucket, dropping its values from Xsum and Xsum_sq.
action drop_bucket(bit<32> idx, bit<32> counter_idx) {
    bit<32> val_write = (counter_idx * STAT_FREQ_COUNTER_SIZE) + idx; // offset
    bit<32> data_offset = counter_idx * 4;
    bit<32> tmp;
    bit<16> val;
    stats_freq_internal.read(val, val_write);

    stats_data.read(tmp, data_offset);
    if (val > 0) {
        tmp = tmp - 1;
    }
    stats_data.write(data_offset, tmp);

    stats_data.read(tmp, data_offset + 1);
    tmp = tmp - (bit<32>)val;
    stats_data.write(data_offset + 1, tmp);

    stats_data.read(tmp, data_offset + 2);
    tmp = tmp - ((bit<32>)val * (bit<32>)val);
    stats_data.write(data_offset + 2, tmp);

    stats_freq_internal.write(val_write, 0);

    // Median updating.
    median_data.read(tmp, data_offset);
    bit<32> up;
    bit<32> down;
    median_data.read(up, data_offset + 1);
    median_data.read(down, data_offset + 2);
    if (idx < tmp) {
        // Modify bottom value.
        down = down - (bit<32>)val;
    } else if (idx > tmp) {
        // Modify top value.
        up = up - (bit<32>)val;
    }
    
    median_data.write(data_offset + 1, up);
    median_data.write(data_offset + 2, down);
}

// zeros all buckets, as well as the relevant sums.
action stats_clear(bit<32> counter_idx) {
    bit<32> data_offset = counter_idx * 4;

    stats_data.write(data_offset, 0);
    stats_data.write(data_offset + 1, 0);
    stats_data.write(data_offset + 2, 0);

    median_data.write(data_offset, 0);
    median_data.write(data_offset + 1, 0);
    median_data.write(data_offset + 2, 0);

    bit<32> ts;
    stats_data.read(ts, data_offset + 3);
    stats_data.write(data_offset + 3, ts + 1);
}

action stats_push_freq(out bit<16> freq_value, bit<32> idx, bit<32> counter_idx) {
    bit<32> val_write = (counter_idx * STAT_FREQ_COUNTER_SIZE) + idx; // offset
    bit<32> tmp;
    bit<32> ts;
    bit<32> ts_actual;
    bit<32> data_offset = counter_idx * 4;

    // ** Critical section stat_data

    stats_data.read(tmp, data_offset + 1);
    tmp = tmp + 1;
    stats_data.write(data_offset + 1, tmp);

    stats_data.read(tmp, data_offset + 2);
    stats_freq_internal.read(freq_value, val_write);
    
    // Check if we need to clear the value before using it.
    stats_last_clear.read(ts_actual, val_write);
    stats_data.read(ts, data_offset + 3);
    if (ts_actual < ts) {
        freq_value = 0; // account for clear
    }
    stats_last_clear.write(val_write, ts);

    stats_freq_internal.write(val_write, freq_value + 1);

    /***
     * Derivation:
     * Xsum_sq_new = Xsum_sq - X^2 + (X + 1)^2
     *             = Xsum_sq + 2X + 1
     ***/  
    tmp = tmp + (bit<32>)(freq_value * 16w2) + 32w1;
    stats_data.write(data_offset + 2, tmp);

    // Update N.
    stats_data.read(tmp, data_offset);
    if (freq_value == 0) { // new contender
        tmp = tmp + 1;
    }
    stats_data.write(data_offset, tmp);

    // Compute VarNX and StdNX in request instead to minimize time spent here.

    // Median updating.
    median_data.read(tmp, data_offset);
    bit<32> up;
    bit<32> down;
    median_data.read(up, data_offset + 1);
    median_data.read(down, data_offset + 2);
    if (idx < tmp) {
        // Increment bottom value if bumping below current median.
        down = down + 1;
    }
    if (idx > tmp) {
        // Increment top value if bumping above current median.
        up = up + 1;
    }
    median_data.write(data_offset + 1, up);
    median_data.write(data_offset + 2, down);
}

action median_tick(bit<32> counter_idx){
    bit<32> data_offset = counter_idx * 4;
    bit<32> tmp;
    bit<16> data;
    bit<32> up;
    bit<32> down;
    bit<2> dir = 0;

    median_data.read(tmp, data_offset);
    median_data.read(up, data_offset + 1);
    median_data.read(down, data_offset + 2);
    bit<32> val_read = (counter_idx * STAT_FREQ_COUNTER_SIZE) + tmp; // offset

    stats_freq_internal.read(data, val_read);
    if (down > up + (bit<32>)data) {
        // Bottom heavy - move index down.
        tmp = tmp - 1;
        up = up + (bit<32>)data;
        dir = 1;
    } 
    if (up > down + (bit<32>)data) {
        // Top heavy - move index up.
        tmp = tmp + 1;
        down = down + (bit<32>)data;
        dir = 2;
    }

    // Read new median bin - the index changed.
    val_read = (counter_idx * STAT_FREQ_COUNTER_SIZE) + tmp;
    stats_freq_internal.read(data, val_read);
    if (dir == 1) {
        down = down - (bit<32>)data;
    } 
    if (dir == 2) {
        up = up - (bit<32>)data;
    }
    median_data.write(data_offset, tmp);
    median_data.write(data_offset + 1, up);
    median_data.write(data_offset + 2, down);
}

action median_90_tick(bit<32> counter_idx){
    bit<32> data_offset = counter_idx * 4;
    bit<32> tmp;
    bit<16> data;
    bit<32> up;
    bit<32> down;
    bit<2> dir = 0;

    median_data.read(tmp, data_offset);
    median_data.read(up, data_offset + 1);
    median_data.read(down, data_offset + 2);
    bit<32> val_read = (counter_idx * STAT_FREQ_COUNTER_SIZE) + tmp; // offset
    stats_freq_internal.read(data, val_read);

    if (down > 9*up + (bit<32>)data) {
        // Bottom heavy - move index down.
        tmp = tmp - 1;
        up = up + (bit<32>)data;
        dir = 1;
    } 
    if (up > 9*down + (bit<32>)data) {
        // Top heavy - move index up.
        tmp = tmp + 1;
        down = down + (bit<32>)data;
        dir = 2;
    }

    // Read new median bin - the index changed.
    val_read = (counter_idx * STAT_FREQ_COUNTER_SIZE) + tmp;
    stats_freq_internal.read(data, val_read);
    if (dir == 1) {
        down = down - (bit<32>)data;
    } 
    if (dir == 2) {
        up = up - (bit<32>)data;
    }
    median_data.write(data_offset, tmp);
    median_data.write(data_offset + 1, up);
    median_data.write(data_offset + 2, down);
}

struct stats_t {
    bit<32> N;
    bit<32> Xsum;
    bit<32> Xsum_sq;
    bit<32> VarNX;
    bit<32> StdNX;
    bit<32> Median;
}

// Allows extracting the stats about the data currently pushed in so far.
action stats_get_data(out stats_t stat_struct, bit<32> counter_idx) {
    stats_data.read(stat_struct.N, (counter_idx * 4));
    stats_data.read(stat_struct.Xsum, (counter_idx * 4) + 1);
    stats_data.read(stat_struct.Xsum_sq, (counter_idx * 4) + 2);

    /***
    * Derivation:
    * Var(NX) = E[(NX)^2] - E[NX]^2
    *         = Sum((NX)^2)/N - (Xsum)^2
    *         = N^2/N Xsum_sq - (Xsum)^2
    *         = N(Xsum_sq) - (Xsum)^2
    ***/
    stat_struct.VarNX = stat_struct.N * stat_struct.Xsum_sq - (stat_struct.Xsum * stat_struct.Xsum);

    // Approximation of sqrt(N), similar to:
    // https://github.com/EOSIO/logchain/blob/master/doc/sqrt.md
    bit<32> stdY = stat_struct.VarNX;

    if (stdY > 1) {
        bit<8> msb_x = 0;
        // Unrolled MSB matching up to 2^31 -  this is probably slow.
        // We can use a LPM match table for this, but we don't have the luxury of jumping
        // into a table... There also aren't any P4 primitives for MSB matching, sadly.
        // De Bruijn also requires an LUT, and hence isn't applicable here (it would take
        // as much table space as an LPM).
        
        if      (stdY & 0b10000000000000000000000000000000 != 0) msb_x = 31;
        else if (stdY & 0b1000000000000000000000000000000  != 0) msb_x = 30;
        else if (stdY & 0b100000000000000000000000000000   != 0) msb_x = 29;
        else if (stdY & 0b10000000000000000000000000000    != 0) msb_x = 28;
        else if (stdY & 0b1000000000000000000000000000     != 0) msb_x = 27;
        else if (stdY & 0b100000000000000000000000000      != 0) msb_x = 26;
        else if (stdY & 0b10000000000000000000000000       != 0) msb_x = 25;
        else if (stdY & 0b1000000000000000000000000        != 0) msb_x = 24;
        else if (stdY & 0b100000000000000000000000         != 0) msb_x = 23;
        else if (stdY & 0b10000000000000000000000          != 0) msb_x = 22;
        else if (stdY & 0b1000000000000000000000           != 0) msb_x = 21;
        else if (stdY & 0b100000000000000000000            != 0) msb_x = 20;
        else if (stdY & 0b10000000000000000000             != 0) msb_x = 19;
        else if (stdY & 0b1000000000000000000              != 0) msb_x = 18;
        else if (stdY & 0b100000000000000000               != 0) msb_x = 17;
        else if (stdY & 0b10000000000000000                != 0) msb_x = 16;
        else if (stdY & 0b1000000000000000                 != 0) msb_x = 15;
        else if (stdY & 0b100000000000000                  != 0) msb_x = 14;
        else if (stdY & 0b10000000000000                   != 0) msb_x = 13;
        else if (stdY & 0b1000000000000                    != 0) msb_x = 12;
        else if (stdY & 0b100000000000                     != 0) msb_x = 11;
        else if (stdY & 0b10000000000                      != 0) msb_x = 10;
        else if (stdY & 0b1000000000                       != 0) msb_x = 9;
        else if (stdY & 0b100000000                        != 0) msb_x = 8;
        else if (stdY & 0b10000000                         != 0) msb_x = 7;
        else if (stdY & 0b1000000                          != 0) msb_x = 6;
        else if (stdY & 0b100000                           != 0) msb_x = 5;
        else if (stdY & 0b10000                            != 0) msb_x = 4;
        else if (stdY & 0b1000                             != 0) msb_x = 3;
        else if (stdY & 0b100                              != 0) msb_x = 2;
        else if (stdY & 0b10                               != 0) msb_x = 1;

        bit<8> msb_z = msb_x >> 1;
        bit<32> mantissa_mask = (32w1 << msb_x) - 1;
        bit<32> mantissa_z_hi = 0;
        if (msb_x & 1 != 0) {
            mantissa_z_hi = (32w1 << msb_z);
        }

        bit<32> mantissa_z_lo = (stdY & mantissa_mask) >> (msb_x - msb_z);
        stdY = (32w1 << msb_z) | ((mantissa_z_hi | mantissa_z_lo) >> 1);
    }
    stat_struct.StdNX = stdY;

    median_data.read(stat_struct.Median, (counter_idx * 4));
}