var k = 28;
var num_entries_per_table = 1 << k;
var honest_bits_per_entry = 29.45;
var honest_plot_size_bytes = num_entries_per_table * honest_bits_per_entry / 8;

//var base_plot_id_filter = 4096;
var default_scan_filter_bits = 11;
var use_t2_pairing_strength = false;


var device_params_5090 = {
    g_hashes_per_ms: 9925926,       // the g(x) function
    pair_hashes_per_ms: 9925926,     // once we have a match, the hash to pair them to get next meta
    target_hashes_per_ms: 9925926,      // given a left side pairing, time to hash (meta + mi) target bits
    sloths_per_ms: 0 // 9925926         // time to do sloth encoding
};

var device_params_pi5 = {
    g_hashes_per_ms: 74362,       // the g(x) function
    pair_hashes_per_ms: 74362,     // once we have a match, the hash to pair them to get next meta
    target_hashes_per_ms: 74362,      // given a left side pairing, time to hash (meta + mi) target bits
    sloths_per_ms: 0 // 9925926         // time to do sloth encoding
}
var default_plot_params = {
    scan_filter_bits: default_scan_filter_bits,
    strength_bits: 2,
    t1_match_bits: 2,
    t2_match_bits: 2,
    t3_match_bits: 4
};
var default_equipment_params = {
    gpu_w: 400,
    gpu_cost: 2000,
    gpu_name: "NVIDIA RTX 5090",
    storage_w_per_tb: 0.55,
    storage_cost_per_tb: 10
}
function get_plot_params(base_plot_id_filter, plot_strength_bits) {
    // strength 2 t1/2/3 match bits = 2,2,2
    // strength 3 t1/2/3 match bits = 3,2,2
    // strength 4 t1/2/3 match bits = 4,2,2
    // strength 5 t1/2/3 match bits = 5,2,2
    // strength 6 t1/2/3 match bits = 5,3,3
    // strength 7 t1/2/3 match bits = 5,4,4
    var t1_match_bits = 2;
    var t2_match_bits = 2 + plot_strength_bits - 2;
    var t3_match_bits = 2 + plot_strength_bits - 2;
    return {
        base_plot_id_filter: base_plot_id_filter,
        scan_filter_bits: default_scan_filter_bits,
        strength_bits: plot_strength_bits,
        t1_match_bits: t1_match_bits,
        t2_match_bits: t2_match_bits,
        t3_match_bits: t3_match_bits,
        effective_plot_id_filter: base_plot_id_filter * (1 << (plot_strength_bits - 2))
    }
}
function get_num_supported_plots_per_challenge(plot_params, challenge_time_ms) {
    return plot_params.effective_plot_id_filter * 9375 / challenge_time_ms;
}
function calc_attack_effectiveness(plot_params, equipment_params, challenge_time_ms, attacker_bits_per_entry) {
    console.log(`Calculating attack effectiveness with attacker bits per entry: ${attacker_bits_per_entry.toFixed(4)}`);
    console.table(plot_params);
    var num_supported_plots = get_num_supported_plots_per_challenge(plot_params, challenge_time_ms);
    var honest_farm_bytes = num_supported_plots * honest_plot_size_bytes;
    var attacker_compression = attacker_bits_per_entry / honest_bits_per_entry;
    var attacker_plot_bytes = attacker_compression * honest_plot_size_bytes;
    var attacker_farm_bytes = num_supported_plots * attacker_plot_bytes;

    // calculate saved bytes and gpu w per tb on those saved bytes. This will show if more effective
    // than honest farming.
    var attacker_saved_bytes = honest_farm_bytes - attacker_farm_bytes;
    var attacker_saved_TB = attacker_saved_bytes / (1000 * 1000 * 1000 * 1000);
    var attacker_gpu_w_per_tb_on_saved_bytes = equipment_params.gpu_w / (attacker_saved_TB);
    var attacker_gpu_cost_per_tb_on_saved_bytes = equipment_params.gpu_cost / (attacker_saved_TB);
    var attacker_w_per_tb_ratio_to_honest_w_per_tb = attacker_gpu_w_per_tb_on_saved_bytes / equipment_params.storage_w_per_tb;
    var attacker_cost_per_tb_relative_to_honest_cost_per_tb = attacker_gpu_cost_per_tb_on_saved_bytes / equipment_params.storage_cost_per_tb;
    var attacker_effectiveness = 1 / (attacker_w_per_tb_ratio_to_honest_w_per_tb * attacker_cost_per_tb_relative_to_honest_cost_per_tb);
    if (attacker_bits_per_entry >= honest_bits_per_entry) {
        attacker_effectiveness = 0;
    }
    if (challenge_time_ms > 9375) {
        attacker_effectiveness = 0;
    }

    var results = {
        attacker_effectiveness: attacker_effectiveness,
        "Attacker compression": attacker_compression,
        attacker_w_per_tb_ratio_to_honest_w_per_tb: attacker_w_per_tb_ratio_to_honest_w_per_tb,
        attacker_cost_per_tb_relative_to_honest_cost_per_tb: attacker_cost_per_tb_relative_to_honest_cost_per_tb,
        challenge_time_ms: challenge_time_ms,
        attacker_bits_per_entry: attacker_bits_per_entry,
        "Num supported plots per GPU": num_supported_plots,
        "Honest farm size (TB)": honest_farm_bytes / (1000 * 1000 * 1000 * 1000),
        "Attacker plot size (bytes)": attacker_plot_bytes,
        "Attacker farm size (TB)": attacker_farm_bytes / (1000 * 1000 * 1000 * 1000),
        "Attacker saved size (TB)": attacker_saved_TB,
        "Attacker GPU W per TB on saved bytes": attacker_gpu_w_per_tb_on_saved_bytes,
        "Attacker GPU cost per TB on saved bytes": attacker_gpu_cost_per_tb_on_saved_bytes,

    };
    console.table(results);
    return results;

}

const xsSetSizeData = {
    // set size: { t3 num entries for challenge scanned, unique Xs, unique Lxs }
    1: { numEntries: 4075, uniqueXs: 32595, uniqueLxs: 16299 },
    2: { numEntries: 8119, uniqueXs: 64941, uniqueLxs: 32472 },
    4: { numEntries: 16197, uniqueXs: 129503, uniqueLxs: 64762 },
    8: { numEntries: 32735, uniqueXs: 261619, uniqueLxs: 130850 },
    16: { numEntries: 65278, uniqueXs: 521316, uniqueLxs: 260778 },
    32: { numEntries: 131140, uniqueXs: 1045410, uniqueLxs: 523183 },
    64: { numEntries: 262153, uniqueXs: 2082761, uniqueLxs: 1043362 },
    128: { numEntries: 523812, uniqueXs: 4134025, uniqueLxs: 2074963 },
    256: { numEntries: 1047648, uniqueXs: 8158293, uniqueLxs: 4110615 },
    512: { numEntries: 2096448, uniqueXs: 15897282, uniqueLxs: 8069569 },
    1024: { numEntries: 4193845, uniqueXs: 30201842, uniqueLxs: 15550490 },
    2048: { numEntries: 8390753, uniqueXs: 54777027, uniqueLxs: 28947232 },
    4096: { numEntries: 16775355, uniqueXs: 91861059, uniqueLxs: 50722920 },
    8192: { numEntries: 33541075, uniqueXs: 137090460, uniqueLxs: 80664455 }
};
function getXsSetSizeData(setsCovered) {
    const keys = Object.keys(xsSetSizeData).map(Number).sort((a, b) => a - b);

    // Exact match
    if (xsSetSizeData[setsCovered]) {
        return xsSetSizeData[setsCovered];
    }

    // Below minimum → clamp
    if (setsCovered < keys[0]) {
        return xsSetSizeData[keys[0]];
    }

    // Above maximum → clamp
    if (setsCovered > keys[keys.length - 1]) {
        return xsSetSizeData[keys[keys.length - 1]];
    }

    // Find bounding keys for interpolation
    let lower = keys[0];
    let upper = keys[keys.length - 1];

    for (let i = 0; i < keys.length - 1; i++) {
        if (setsCovered > keys[i] && setsCovered < keys[i + 1]) {
            lower = keys[i];
            upper = keys[i + 1];
            break;
        }
    }

    const t = (setsCovered - lower) / (upper - lower);

    const lowData = xsSetSizeData[lower];
    const upData = xsSetSizeData[upper];

    function lerp(a, b, t) {
        return a + (b - a) * t;
    }

    return {
        numEntries: Math.round(lerp(lowData.numEntries, upData.numEntries, t)),
        uniqueXs: Math.round(lerp(lowData.uniqueXs, upData.uniqueXs, t)),
        uniqueLxs: Math.round(lerp(lowData.uniqueLxs, upData.uniqueLxs, t)),
        interpolated: true,
        from: [lower, upper]
    };
}

function get_g_time(device_params, num_hashes) {
    console.log("Calculating G time for num_hashes: " + num_hashes, device_params);
    return num_hashes / device_params.g_hashes_per_ms;
}
function get_t1_pairing_time(plot_params, device_params, num_hashes) {
    // get strength multiplier
    var strength_multiplier = 1 << plot_params.strength_bits;
    return (num_hashes * strength_multiplier) / device_params.pair_hashes_per_ms;
}
function get_t1_target_time(plot_params, device_params, num_hashes) {
    // get strength multiplier
    var strength_multiplier = 1 << plot_params.strength_bits;
    return (num_hashes * strength_multiplier) / device_params.target_hashes_per_ms;
}
function get_t2_pairing_time(plot_params, device_params, num_hashes) {
    return num_hashes / device_params.pair_hashes_per_ms;
}
function get_t2_target_time(plot_params, device_params, num_hashes) {
    return num_hashes / device_params.target_hashes_per_ms;
}
function get_t3_pairing_time(plot_params, device_params, num_hashes) {
    return num_hashes / device_params.pair_hashes_per_ms;
}
function get_t3_target_time(plot_params, device_params, num_hashes) {
    return num_hashes / device_params.target_hashes_per_ms;
}

function calc_validation_time(plot_params, device_params) {
    // validation is on 128 x's, which is 64 pairs.
    // Each x needs to do a g hash.
    // Each pair needs to do a target hash, and pairing hash.
    //  There are 64 T1 pairs, 32 T2 pairs, 16 T3 pairs.
    var num_xs = 128;
    var num_t1_pairs = 64;
    var num_t2_pairs = 32;
    var num_t3_pairs = 16;
    var g_hashes_time = get_g_time(device_params, num_xs);
    var t1_target_hashes_time = get_t1_target_time(plot_params, device_params, num_t1_pairs);
    var t1_pairing_hashes_time = get_t1_pairing_time(plot_params, device_params, num_t1_pairs);
    var t1_time = t1_target_hashes_time + t1_pairing_hashes_time;
    var t2_target_hashes_time = get_t2_target_time(plot_params, device_params, num_t2_pairs);
    var t2_pairing_hashes_time = get_t2_pairing_time(plot_params, device_params, num_t2_pairs);
    var t2_time = t2_target_hashes_time + t2_pairing_hashes_time;
    var t3_target_hashes_time = get_t3_target_time(plot_params, device_params, num_t3_pairs);
    var t3_pairing_hashes_time = get_t3_pairing_time(plot_params, device_params, num_t3_pairs);
    var t3_time = t3_target_hashes_time + t3_pairing_hashes_time;
    var total_time = g_hashes_time + t1_time + t2_time + t3_time;
    var results = {
        "G hashes": num_xs,
        "T1 target hashes": num_t1_pairs,
        "T1 pairing hashes": num_t1_pairs,
        "T2 target hashes": num_t2_pairs,
        "T2 pairing hashes": num_t2_pairs,
        "T3 target hashes": num_t3_pairs,
        "T3 pairing hashes": num_t3_pairs,
        "G time (ms)": g_hashes_time,
        "T1 time (ms)": t1_time,
        "T2 time (ms)": t2_time,
        "T3 time (ms)": t3_time,
        "Total validation time (ms)": total_time
    };
    console.table(results);
    return total_time;
}

function calc_plotting_time(plot_params, device_params) {
    var g_hashes = num_entries_per_table;
    var t1_target_hashes = num_entries_per_table * (1 << plot_params.t1_match_bits);
    var t1_pairing_hashes = num_entries_per_table; // t1 has special fast match function
    var t2_target_hashes = num_entries_per_table * (1 << plot_params.t2_match_bits);
    var t2_pairing_hashes = t2_target_hashes;
    if (use_t2_pairing_strength) {
        t2_pairing_hashes *= (1 << (plot_params.strength_bits - 2));
    }
    var t3_target_hashes = num_entries_per_table * (1 << plot_params.t3_match_bits);
    var t3_pairing_hashes = num_entries_per_table;
    var g_hashes_time = get_g_time(device_params, g_hashes);
    var t1_target_hashes_time = get_t1_target_time(plot_params, device_params, t1_target_hashes);
    var t1_pairing_hashes_time = get_t1_pairing_time(plot_params, device_params, t1_pairing_hashes);
    var t1_time = t1_target_hashes_time + t1_pairing_hashes_time;
    var t2_target_hashes_time = get_t2_target_time(plot_params, device_params, t2_target_hashes);
    var t2_pairing_hashes_time = get_t2_pairing_time(plot_params, device_params, t2_pairing_hashes);
    var t2_time = t2_target_hashes_time + t2_pairing_hashes_time;
    var t3_target_hashes_time = get_t3_target_time(plot_params, device_params, t3_target_hashes);
    var t3_pairing_hashes_time = get_t3_pairing_time(plot_params, device_params, t3_pairing_hashes);
    var t3_time = t3_target_hashes_time + t3_pairing_hashes_time;

    var total_time = g_hashes_time + t1_time + t2_time + t3_time;
    var results = {
        "T1 match bits": plot_params.t1_match_bits,
        "T2 match bits": plot_params.t2_match_bits,
        "T3 match bits": plot_params.t3_match_bits,
        "G hashes": Math.round(g_hashes),
        "T1 target hashes": Math.round(t1_target_hashes),
        "T1 pairing hashes": Math.round(t1_pairing_hashes),
        "T2 target hashes": Math.round(t2_target_hashes),
        "T2 pairing hashes": Math.round(t2_pairing_hashes),
        "T3 target hashes": Math.round(t3_target_hashes),
        "T3 pairing hashes": Math.round(t3_pairing_hashes),
        "G time (ms)": g_hashes_time,
        "T1 time (ms)": t1_time,
        "T2 time (ms)": t2_time,
        "T3 time (ms)": t3_time,
        "Total plotting time (ms)": total_time
    };

    console.table(results);
    return total_time;
}

function calc_pure_rental_attack(plot_params, device_params, netspace_EiB) {
    const plotting_time = calc_plotting_time(plot_params, device_params);
    console.log(`Calculating rental attack with plotting time: ${plotting_time.toFixed(2)} ms`);
    var plot_size_GiB = honest_plot_size_bytes / (1024 * 1024 * 1024);
    var netspace_GiB = netspace_EiB * 1024 * 1024 * 1024;
    var plots_needed_for_attack = netspace_GiB / plot_size_GiB;
    var num_supported_plots_per_challenge = 9375 / plotting_time;
    var spoofed_plots = num_supported_plots_per_challenge * plot_params.effective_plot_id_filter;
    var total_devices_needed_for_attack = plots_needed_for_attack / spoofed_plots;
    var results = {
        "Plot strength bits": plot_params.strength_bits,
        "Plotting time (ms)": plotting_time,
        "Effective plot ID filter": plot_params.effective_plot_id_filter,
        "Netspace (EiB)": netspace_EiB,
        "Netspace (GiB)": netspace_GiB,
        "Plot size (GiB)": plot_size_GiB,
        "Plots needed for attack": plots_needed_for_attack,
        "Num supported plots per challenge": num_supported_plots_per_challenge,
        "Spoofed plots per device": spoofed_plots,
        "Total devices needed for attack": total_devices_needed_for_attack
    };
    console.table(results);
    return total_devices_needed_for_attack;
}

// Reconstruction rental attack is similar to pure rental attack but we make a plotting pass and store
// the match bits for use in plot reconstruction to get the challenge results.
function calc_reconstruction_rental_attack(plot_params, device_params, netspace_EiB) {
    console.log(`Calculating reconstruction rental attack`);

    var data = calc_attack_strength_match_bits(plot_params, device_params);
    console.table(data);

    var reconstruction_plotting_time = data.challenge_time_ms;
    var attack_plot_bytes = data.attacker_bits_per_entry * num_entries_per_table / 8;
    var attack_plot_size_GiB = attack_plot_bytes / (1024 * 1024 * 1024);

    var plot_size_GiB = honest_plot_size_bytes / (1024 * 1024 * 1024);
    var netspace_GiB = netspace_EiB * 1024 * 1024 * 1024;
    var plots_needed_for_attack = netspace_GiB / plot_size_GiB;
    var num_supported_plots_per_challenge = 9375 * plot_params.effective_plot_id_filter / reconstruction_plotting_time;
    var total_devices_needed_for_attack = plots_needed_for_attack / num_supported_plots_per_challenge;
    var total_storage_needed_for_attack_PiB = plots_needed_for_attack * attack_plot_size_GiB / (1024 * 1024);
    var results = {
        "Plot strength bits": plot_params.strength_bits,
        "Reconstruction plotting time (ms)": reconstruction_plotting_time,
        "Effective plot ID filter": plot_params.effective_plot_id_filter,
        "Netspace (EiB)": netspace_EiB,
        "Netspace (GiB)": netspace_GiB,
        "Attack plot size (GiB)": attack_plot_size_GiB,
        "Plots needed for attack": plots_needed_for_attack,
        "Num supported plots per challenge": num_supported_plots_per_challenge,
        "Total devices needed for attack": total_devices_needed_for_attack,
        "Total storage needed for attack (PiB)": total_storage_needed_for_attack_PiB
    };
    console.table(results);
    return total_devices_needed_for_attack;
}

function calc_attack_collected_xs(challenge_sets_covered, plot_params, device_params) {
    const challenge_data = getXsSetSizeData(challenge_sets_covered);
    console.log(`Challenge sets covered: ${challenge_sets_covered}`);
    console.table(challenge_data);
    // get log2 of unique Xs and Lxs
    const log2_unique_xs = Math.log2(challenge_data.uniqueXs);
    console.log(`Log2 unique Xs: ${log2_unique_xs.toFixed(2)}`);
    const bits_per_xs_sorted = k - log2_unique_xs + 1.45;
    const bits_per_entry_xs = bits_per_xs_sorted * challenge_data.uniqueXs / challenge_data.numEntries;
    console.log(`Bits per x sorted: ${bits_per_xs_sorted.toFixed(4)}`);
    console.log(`Bits per entry (Xs unsorted): ${bits_per_entry_xs.toFixed(4)}`);
    const perc_of_honest_plot_xs = bits_per_entry_xs / honest_bits_per_entry * 100;
    console.log(`Percentage of honest plot size (Xs): ${perc_of_honest_plot_xs.toFixed(2)}%`);

    var g_hashes = challenge_data.uniqueXs;
    var t1_target_hashes = challenge_data.uniqueXs * (1 << plot_params.t1_match_bits);
    var t1_matches = challenge_data.uniqueXs / 2;
    var t1_pairing_hashes = t1_matches;

    var t2_target_hashes = t1_matches * (1 << plot_params.t2_match_bits);
    var t2_matches = challenge_data.uniqueXs / 4;
    var t2_pairing_hashes = t2_matches; // TODO: not clear what this should be,, as target hashes will have less than 100% collisions. This is best-case (minimum).


    var t3_target_hashes = t2_matches * (1 << plot_params.t3_match_bits);
    var t3_matches = challenge_data.uniqueXs / 8;
    var t3_pairing_hashes = t3_matches; // TODO: again, this is minimum possible.

    var g_hashes_time = get_g_time(device_params, g_hashes);
    console.log(`Calculating attack collected XS with ${g_hashes} G hashes`);
    console.log(`G hashes time: ${g_hashes_time.toFixed(2)} ms`);
    var t1_target_hashes_time = get_t1_target_time(plot_params, device_params, t1_target_hashes);
    var t1_pairing_hashes_time = get_t1_pairing_time(plot_params, device_params, t1_pairing_hashes);
    var t1_time = g_hashes_time + t1_target_hashes_time + t1_pairing_hashes_time;

    var t2_target_hashes_time = get_t2_target_time(plot_params, device_params, t2_target_hashes);
    var t2_pairing_hashes_time = get_t2_pairing_time(plot_params, device_params, t2_pairing_hashes);
    var t2_time = t2_target_hashes_time + t2_pairing_hashes_time;

    var t3_target_hashes_time = get_t3_target_time(plot_params, device_params, t3_target_hashes);
    var t3_pairing_hashes_time = get_t3_pairing_time(plot_params, device_params, t3_pairing_hashes);
    var t3_time = t3_target_hashes_time + t3_pairing_hashes_time;

    var challenge_solve_time = 2 * (t1_time + t2_time + t3_time); // 2 scan sets
    var results = {
        "Challenge sets covered": challenge_sets_covered,
        "T1 matches": Math.round(t1_matches),
        "T2 matches": Math.round(t2_matches),
        "T3 matches": Math.round(t3_matches),
        "T1 match bits": plot_params.t1_match_bits,
        "T2 match bits": plot_params.t2_match_bits,
        "T3 match bits": plot_params.t3_match_bits,
        "G hashes": Math.round(g_hashes),
        "T1 target hashes": Math.round(t1_target_hashes),
        "T1 pairing hashes": Math.round(t1_pairing_hashes),
        "T2 target hashes": Math.round(t2_target_hashes),
        "T2 pairing hashes": Math.round(t2_pairing_hashes),
        "T3 target hashes": Math.round(t3_target_hashes),
        "T3 pairing hashes": Math.round(t3_pairing_hashes),
        "G time (ms)": g_hashes_time,
        "T1 time (ms)": t1_time,
        "T2 time (ms)": t2_time,
        "T3 time (ms)": t3_time,
        "Challenge solve time (2 scan sets) (ms)": challenge_solve_time
    }
    console.table(results);


    return calc_attack_effectiveness(plot_params, default_equipment_params, challenge_solve_time, bits_per_entry_xs);

}

function calc_attack_collected_lxs(challenge_sets_covered, plot_params, device_params) {
    const challenge_data = getXsSetSizeData(challenge_sets_covered);
    console.log(`Challenge sets covered: ${challenge_sets_covered}`);
    console.table(challenge_data);
    // get log2 of unique Xs and Lxs
    const log2_unique_lxs = Math.log2(challenge_data.uniqueLxs);
    console.log(`Log2 unique Lxs: ${log2_unique_lxs.toFixed(2)}`);
    const bits_per_lxs_sorted = k - log2_unique_lxs + 1.45;
    const bits_per_entry_lxs = bits_per_lxs_sorted * challenge_data.uniqueLxs / challenge_data.numEntries;
    console.log(`Bits per entry (Lxs sorted): ${bits_per_lxs_sorted.toFixed(4)}`);
    console.log(`Bits per entry (Lxs unsorted): ${bits_per_entry_lxs.toFixed(4)}`);
    const perc_of_honest_plot_lxs = bits_per_entry_lxs / honest_bits_per_entry * 100;
    console.log(`Percentage of honest plot size (Lxs): ${perc_of_honest_plot_lxs.toFixed(2)}%`);

    // lx slightly different than x calculations, since we start from all g entries
    var all_g_hashes = num_entries_per_table;
    var lx_g_hashes = challenge_data.uniqueLxs;
    var t1_target_hashes = challenge_data.uniqueLxs * (1 << plot_params.t1_match_bits);
    var t1_pairing_hashes = challenge_data.uniqueLxs;
    var t1_matches = challenge_data.uniqueLxs;

    var t2_target_hashes = t1_matches * (1 << plot_params.t2_match_bits);
    var t2_pairing_hashes = challenge_data.uniqueLxs / 2; // TODO: this is somewhere between t2_target_hashes and t2_matches. We take min for now (best case).
    var t2_matches = challenge_data.uniqueLxs / 2;

    var t3_target_hashes = t2_matches * (1 << plot_params.t3_match_bits);
    var t3_pairing_hashes = challenge_data.numEntries; // TODO: this is somewhere between t3_target_hashes and t3_matches, we take min (best case).
    var t3_matches = challenge_data.numEntries;

    var g_hashes_time = get_g_time(device_params, all_g_hashes);
    var lx_g_hashes_time = get_g_time(device_params, lx_g_hashes);
    var t1_target_hashes_time = get_t1_target_time(plot_params, device_params, t1_target_hashes);
    var t1_pairing_hashes_time = get_t1_pairing_time(plot_params, device_params, t1_pairing_hashes);
    var t1_time = lx_g_hashes_time + t1_target_hashes_time + t1_pairing_hashes_time;

    var t2_target_hashes_time = get_t2_target_time(plot_params, device_params, t2_target_hashes);
    var t2_pairing_hashes_time = get_t2_pairing_time(plot_params, device_params, t2_pairing_hashes);
    var t2_time = t2_target_hashes_time + t2_pairing_hashes_time;

    var t3_target_hashes_time = get_t3_target_time(plot_params, device_params, t3_target_hashes);
    var t3_pairing_hashes_time = get_t3_pairing_time(plot_params, device_params, t3_pairing_hashes);
    var t3_time = t3_target_hashes_time + t3_pairing_hashes_time;

    var challenge_solve_time = g_hashes_time + 2 * (t1_time + t2_time + t3_time); // 2 scan sets

    var results = {
        "Challenge sets covered": challenge_sets_covered,
        "T1 matches": Math.round(t1_matches),
        "T2 matches": Math.round(t2_matches),
        "T3 matches": Math.round(t3_matches),
        "T1 match bits": plot_params.t1_match_bits,
        "T2 match bits": plot_params.t2_match_bits,
        "T3 match bits": plot_params.t3_match_bits,
        "G hashes (all)": Math.round(all_g_hashes),
        "G hashes (Lxs)": Math.round(lx_g_hashes),
        "T1 target hashes": Math.round(t1_target_hashes),
        "T1 pairing hashes": Math.round(t1_pairing_hashes),
        "T2 target hashes": Math.round(t2_target_hashes),
        "T2 pairing hashes": Math.round(t2_pairing_hashes),
        "T3 target hashes": Math.round(t3_target_hashes),
        "T3 pairing hashes": Math.round(t3_pairing_hashes),
        "G time (ms)": g_hashes_time,
        "T1 time (ms)": t1_time,
        "T2 time (ms)": t2_time,
        "T3 time (ms)": t3_time,
        "Challenge solve time (2 scan sets) (ms)": challenge_solve_time
    };

    console.table(results);

    return calc_attack_effectiveness(plot_params, default_equipment_params, challenge_solve_time, bits_per_entry_lxs);
}

function get_n_in_m_buckets(n, m) {
    var pow = Math.pow(1 - (1 / m), n);
    return m * (1 - pow);
}

// observations: T3 match bits no effect, #PF to scan leads into bit saturation for T2, beyond 4096 no effect as bits are already at zero. If you bit drop on x2 with smaller group size you get same effect -- i.e. scan 512 with 1 bit drop same result as scan 1024 with no bit drop. G function weights on lower strengths then flattens out after plot strength 7 or so. If we increased T1 match bits w/ strength then we get consistent W/TB as we up strength, but solver becomes impractical much sooner. We should be able to tune PF scan size down -- it reduces min. hdd load w/ grouping (but makes indexing trickier) and reduces security but this can be paired with min. security from other attacks.
function calc_attack_challenge_components_bit_dropping(plot_params, device_params, drop_bits) {
    var proof_fragments_to_scan = 1 << plot_params.scan_filter_bits;
    console.log(`Calculating attack challenge components with pf: ${proof_fragments_to_scan}bit dropping: ${drop_bits} bits`);
    console.table(plot_params);

    var total_bit_dropped_lxs = proof_fragments_to_scan * 4;
    console.log(`Total bit dropped Lxs: ${total_bit_dropped_lxs}`);

    const possible_bit_dropped_groups = Math.pow(2, 14 - drop_bits);
    console.log(`Possible bit dropped groups: ${possible_bit_dropped_groups}`);

    const avg_unique_lx_groups = get_n_in_m_buckets(total_bit_dropped_lxs, possible_bit_dropped_groups);
    console.log(`Avg. unique lx groups: ${avg_unique_lx_groups.toFixed(2)}`);

    const log2_unique_lxs = Math.log2(avg_unique_lx_groups);
    console.log(`Log2 unique Lxs: ${log2_unique_lxs.toFixed(2)}`);
    const bits_per_lxs_sorted = k / 2 - drop_bits - log2_unique_lxs + 1.45;
    const bits_per_entry_lxs = bits_per_lxs_sorted * avg_unique_lx_groups / proof_fragments_to_scan;
    console.log(`Bits per x in Lxs sorted: ${bits_per_lxs_sorted.toFixed(4)}`);
    console.log(`Bits per entry (Lxs sorted for # proof fragments): ${bits_per_entry_lxs.toFixed(4)}`);
    const perc_of_honest_plot_lxs = bits_per_entry_lxs / honest_bits_per_entry * 100;
    console.log(`Percentage of honest plot size (Lxs): ${perc_of_honest_plot_lxs.toFixed(2)}%`);

    // g time is full since we always scan all g entries
    var g_hashes = num_entries_per_table;
    var t1_target_hashes = avg_unique_lx_groups * Math.pow(2, 14 + drop_bits) * (1 << plot_params.t1_match_bits);
    var t1_matches = avg_unique_lx_groups * Math.pow(2, 14 + drop_bits);
    var t1_pairing_hashes = t1_matches * (1 << plot_params.t1_match_bits); // pairing hashes inversely must filter to reach matches.

    var t2_target_hashes = t1_matches * (1 << plot_params.t2_match_bits);
    var t2_matches = (t1_matches / num_entries_per_table) * (t1_matches / num_entries_per_table) * num_entries_per_table;
    t2_matches = get_n_in_m_buckets(t2_matches, num_entries_per_table);
    var t2_pairing_hashes = t2_matches * (1 << plot_params.t2_match_bits); // pairing hashes inversely must filter to reach matches.

    var t3_target_hashes = t2_matches * (1 << plot_params.t3_match_bits);
    var t3_matches = (t2_matches / num_entries_per_table) * (t2_matches / num_entries_per_table) * num_entries_per_table;
    t3_matches = get_n_in_m_buckets(t3_matches, num_entries_per_table);
    var t3_pairing_hashes = t3_matches * (1 << plot_params.t3_match_bits); // pairing hashes inversely must filter to reach matches.

    var g_hashes_time = get_g_time(device_params, g_hashes);
    var t1_target_hashes_time = get_t1_target_time(plot_params, device_params, t1_target_hashes);
    var t1_pairing_hashes_time = get_t1_pairing_time(plot_params, device_params, t1_pairing_hashes);
    var t1_time = t1_target_hashes_time + t1_pairing_hashes_time;

    var t2_target_hashes_time = get_t2_target_time(plot_params, device_params, t2_target_hashes);
    var t2_pairing_hashes_time = get_t2_pairing_time(plot_params, device_params, t2_pairing_hashes);
    var t2_time = t2_target_hashes_time + t2_pairing_hashes_time;

    var t3_target_hashes_time = get_t3_target_time(plot_params, device_params, t3_target_hashes);
    var t3_pairing_hashes_time = get_t3_pairing_time(plot_params, device_params, t3_pairing_hashes);
    var t3_time = t3_target_hashes_time + t3_pairing_hashes_time;

    var challenge_solve_time = g_hashes_time + 2 * (t1_time + t2_time + t3_time); // 2 scan sets
    // NOTE that T3 entries must be then Feistel'd and filtered to within the scan PFs, though we see this as "free" work.

    const results = {
        "Proof fragments to scan": proof_fragments_to_scan,
        "Drop bits": drop_bits,
        "Possible bit dropped groups": possible_bit_dropped_groups,
        "Avg. unique lx groups": avg_unique_lx_groups.toFixed(2),
        "Bits per x in Lxs sorted": bits_per_lxs_sorted.toFixed(4),
        "Bits per entry (Lxs sorted for # proof fragments)": bits_per_entry_lxs.toFixed(4),
        "T1 matches": Math.round(t1_matches),
        "T2 matches": Math.round(t2_matches),
        "T3 matches": Math.round(t3_matches),
        "T1 match bits": plot_params.t1_match_bits,
        "T2 match bits": plot_params.t2_match_bits,
        "T3 match bits": plot_params.t3_match_bits,
        "G hashes": Math.round(g_hashes),
        "T1 target hashes": Math.round(t1_target_hashes),
        "T1 pairing hashes": Math.round(t1_pairing_hashes),
        "T2 target hashes": Math.round(t2_target_hashes),
        "T2 pairing hashes": Math.round(t2_pairing_hashes),
        "T3 target hashes": Math.round(t3_target_hashes),
        "T3 pairing hashes": Math.round(t3_pairing_hashes),
        "G time (ms)": g_hashes_time.toFixed(2),
        "T1 time (ms)": t1_time.toFixed(2),
        "T2 time (ms)": t2_time.toFixed(2),
        "T3 time (ms)": t3_time.toFixed(2),
        "Challenge solve time (2 scan sets) (ms)": challenge_solve_time.toFixed(2)
    };

    console.table(results);

    return calc_attack_effectiveness(plot_params, default_equipment_params, challenge_solve_time, bits_per_entry_lxs);

}


function calc_attack_proof_fragments_drop_bits(plot_params, device_params, bits_dropped) {
    // see markdown proof_fragments.md for derivation
    var strength_multiplier = 1 << (plot_params.strength_bits);
    console.log(`Calculating attack with proof fragments drop bits: ${bits_dropped}, strength multiplier: ${strength_multiplier}`);
    var total_proof_fragments_in_scan = 1 << plot_params.scan_filter_bits;
    var total_proof_fragments_in_challenge = total_proof_fragments_in_scan * 2; // 2 scan sets
    console.log('Total proof fragments in challenge: ' + total_proof_fragments_in_challenge);
    var proof_fragments_in_chain = 60;
    proof_fragments_in_chain = get_n_in_m_buckets(proof_fragments_in_chain, total_proof_fragments_in_challenge);
    console.log(`Proof fragments in chaining after filtering: ${proof_fragments_in_chain.toFixed(2)}`);
    const e = Math.E;
    var c = 2 - 1/e;
    var q = (1 - 1/e)*(1 - 1/e);
    const n_pf_candidates = Math.pow(2, bits_dropped);
    var expected_2_to_the_14_x_groups_per_pf = ((n_pf_candidates-1)*((n_pf_candidates)*c+4)/(2*(n_pf_candidates)));
    var total_expected_2_to_the_14_x_groups = proof_fragments_in_chain * expected_2_to_the_14_x_groups_per_pf;
    total_expected_2_to_the_14_x_groups = get_n_in_m_buckets(total_expected_2_to_the_14_x_groups, Math.pow(2,14));


    console.log(`Expected 2^14 x groups for ${bits_dropped} bits dropped: ${total_expected_2_to_the_14_x_groups.toFixed(2)}`);
    var expected_x12345678_validations_per_pf = (((n_pf_candidates-1)/2)*q)+((n_pf_candidates-1)/(n_pf_candidates))
    var total_expected_x12345678_validations = proof_fragments_in_chain * expected_x12345678_validations_per_pf;
    console.log(`Expected total x1..8 validations for ${bits_dropped} bits dropped: ${total_expected_x12345678_validations.toFixed(2)}`);

    var g_hashes = num_entries_per_table;
    var t1_target_hashes = total_expected_2_to_the_14_x_groups * Math.pow(2, 14) * (1 << plot_params.t1_match_bits);
    var t1_pairing_hashes = total_expected_2_to_the_14_x_groups * Math.pow(2, 14);
    var t1_matches = t1_pairing_hashes;

    // for validation, we have x1..4 on L, and x5..8 on R, and we get match bits from L, so we only do one target hash on that match index for validation
    var t2_target_hashes = t1_matches * (1 << plot_params.t2_match_bits);
    var t2_pairing_hashes = total_expected_2_to_the_14_x_groups;

    var t3_target_hashes = expected_x12345678_validations_per_pf;
    var t3_pairing_hashes = expected_x12345678_validations_per_pf;

    // no t3 work to do, since we assume we find all valid proof fragments once we've validated x1...x8.
    var g_time = get_g_time(device_params, g_hashes);
    var t1_target_hashes_time = get_t1_target_time(plot_params, device_params, t1_target_hashes);
    var t1_pairing_hashes_time = get_t1_pairing_time(plot_params, device_params, t1_pairing_hashes);
    var t1_time = t1_target_hashes_time + t1_pairing_hashes_time;

    var t2_target_hashes_time = get_t2_target_time(plot_params, device_params, t2_target_hashes);
    var t2_pairing_hashes_time = get_t2_pairing_time(plot_params, device_params, t2_pairing_hashes);
    var t2_time = t2_target_hashes_time + t2_pairing_hashes_time;

    var t3_target_hashes_time = get_t3_target_time(plot_params, device_params, t3_target_hashes);
    var t3_pairing_hashes_time = get_t3_pairing_time(plot_params, device_params, t3_pairing_hashes);
    var t3_time = t3_target_hashes_time + t3_pairing_hashes_time;

    var challenge_solve_time = g_time + 2 * (t1_time + t2_time); // 2 scan sets

    var bits_per_entry_proof_fragments = k - bits_dropped + 1.45;

    var results = {
        "Bits dropped": bits_dropped,
        "Expected 2^14 x groups": total_expected_2_to_the_14_x_groups.toFixed(2),
        "Expected x1..8 validations": total_expected_x12345678_validations.toFixed(2),
        "Bits per entry (proof fragments)": bits_per_entry_proof_fragments.toFixed(4),
        "T1 match bits": plot_params.t1_match_bits,
        "T2 match bits": plot_params.t2_match_bits,
        "T3 match bits": plot_params.t3_match_bits,
        "G hashes": Math.round(g_hashes),
        "T1 target hashes": Math.round(t1_target_hashes),
        "T1 pairing hashes": Math.round(t1_pairing_hashes),
        "T2 target hashes": Math.round(t2_target_hashes),
        "T2 pairing hashes": Math.round(t2_pairing_hashes),
        "T3 target hashes": Math.round(t3_target_hashes),
        "T3 pairing hashes": Math.round(t3_pairing_hashes),
        "G time (ms)": g_time.toFixed(2),
        "T1 time (ms)": t1_time.toFixed(2),
        "T2 time (ms)": t2_time.toFixed(2),
        "T3 time (ms)": t3_time.toFixed(2),
        "Challenge solve time (ms)": challenge_solve_time.toFixed(2),
    };
    console.table(results);

    return calc_attack_effectiveness(plot_params, default_equipment_params, challenge_solve_time, bits_per_entry_proof_fragments);


}

function calc_attack_strength_match_bits(plot_params, device_params) {
    console.log(`Calculating attack strength match bits`);
    console.table(plot_params);

    const bits_per_entry = plot_params.t1_match_bits + plot_params.t2_match_bits + plot_params.t3_match_bits;
    console.log(`Bits per entry (match bits total): ${bits_per_entry.toFixed(4)}`);

    var all_g_hashes = num_entries_per_table;

    var t1_target_hashes = num_entries_per_table;
    var t1_pairing_hashes = num_entries_per_table;

    var t2_target_hashes = num_entries_per_table;
    var t2_pairing_hashes = num_entries_per_table;

    var t3_target_hashes = num_entries_per_table;
    var t3_pairing_hashes = num_entries_per_table;

    var g_time = get_g_time(device_params, all_g_hashes);
    var t1_target_hashes_time = get_t1_target_time(plot_params, device_params, t1_target_hashes);
    var t1_pairing_hashes_time = get_t1_pairing_time(plot_params, device_params, t1_pairing_hashes);
    var t1_time = t1_target_hashes_time + t1_pairing_hashes_time;

    var t2_target_hashes_time = get_t2_target_time(plot_params, device_params, t2_target_hashes);
    var t2_pairing_hashes_time = get_t2_pairing_time(plot_params, device_params, t2_pairing_hashes);
    var t2_time = t2_target_hashes_time + t2_pairing_hashes_time;

    var t3_target_hashes_time = get_t3_target_time(plot_params, device_params, t3_target_hashes);
    var t3_pairing_hashes_time = get_t3_pairing_time(plot_params, device_params, t3_pairing_hashes);
    var t3_time = t3_target_hashes_time + t3_pairing_hashes_time;

    var challenge_solve_time = g_time + t1_time + t2_time + t3_time; // whole table reconstruction

    var results = {
        "T1 match bits": plot_params.t1_match_bits,
        "T2 match bits": plot_params.t2_match_bits,
        "T3 match bits": plot_params.t3_match_bits,
        "Bits per entry (match bits total)": bits_per_entry.toFixed(4),
        "G hashes": Math.round(all_g_hashes),
        "T1 target hashes": Math.round(t1_target_hashes),
        "T1 pairing hashes": Math.round(t1_pairing_hashes),
        "T2 target hashes": Math.round(t2_target_hashes),
        "T2 pairing hashes": Math.round(t2_pairing_hashes),
        "T3 target hashes": Math.round(t3_target_hashes),
        "T3 pairing hashes": Math.round(t3_pairing_hashes),
        "G time (ms)": g_time.toFixed(2),
        "T1 time (ms)": t1_time.toFixed(2),
        "T2 time (ms)": t2_time.toFixed(2),
        "T3 time (ms)": t3_time.toFixed(2),
        "Challenge solve time (ms)": challenge_solve_time.toFixed(2),
    };
    console.table(results);

    return calc_attack_effectiveness(plot_params, default_equipment_params, challenge_solve_time, bits_per_entry);

}


function get_highest_effectiveness_challenge_components_attack(plot_params, device_params) {
    console.log(`Searching for highest effectiveness challenge components attack`);
    console.table(plot_params);
    var scan_filter_bits = plot_params.scan_filter_bits;
    var best_drop_bits = -6;
    var best_strength_bits = 2;
    var best_effectiveness = 0.0;
    for (var drop_bits = -8; drop_bits < 8; drop_bits++) {
        for (var strength_bits = 2; strength_bits < 13; strength_bits++) {
            var test_plot_params = get_plot_params(plot_params.base_plot_id_filter, strength_bits);
            test_plot_params.scan_filter_bits = scan_filter_bits;
            var result = calc_attack_challenge_components_bit_dropping(test_plot_params, device_params, drop_bits);
            var effectiveness = result.attacker_effectiveness;
            console.log(`Drop bits: ${drop_bits} Strength bits: ${strength_bits} Effectiveness: ${effectiveness.toFixed(6)}`);
            if (effectiveness > best_effectiveness) {
                best_effectiveness = effectiveness;
                best_drop_bits = drop_bits;
                best_strength_bits = strength_bits;
            }
        }
    }
    console.log(`Best drop bits: ${best_drop_bits} Best strength bits: ${best_strength_bits} Best effectiveness: ${best_effectiveness.toFixed(6)}`);
    return {
        best_drop_bits : best_drop_bits,
        best_strength_bits: best_strength_bits,
        best_effectiveness: best_effectiveness
    };
}

function get_highest_effective_collected_xs_attack(plot_params, device_params) {
    console.log(`Searching for highest effectiveness collected xs attack`);
    console.table(plot_params);
    var best_challenge_sets_covered = 1;
    var best_effectiveness = 0.0;
    var best_strength = 2;
    var max_challenge_sets_bits_covered = 13;
    for (var challenge_set_bits_covered = 1; challenge_set_bits_covered <= max_challenge_sets_bits_covered; challenge_set_bits_covered++) {
        for (var strength = 2; strength < 14; strength++) {
            var test_plot_params = get_plot_params(plot_params.base_plot_id_filter, strength);
            test_plot_params.scan_filter_bits = plot_params.scan_filter_bits;
            var result = calc_attack_collected_xs(1 << challenge_set_bits_covered, test_plot_params, device_params);
            var effectiveness = result.attacker_effectiveness;
            console.log(`Challenge sets covered: ${1 << challenge_set_bits_covered} Strength: ${strength} Effectiveness: ${effectiveness.toFixed(6)}`);
            if (effectiveness > best_effectiveness) {
                best_effectiveness = effectiveness;
                best_challenge_sets_covered = 1 << challenge_set_bits_covered;
                best_strength = strength;
            }
        }
    }
    console.log(`Best challenge sets covered: ${best_challenge_sets_covered} Best effectiveness: ${best_effectiveness.toFixed(6)}`);
    return {
        best_challenge_sets_covered : best_challenge_sets_covered,
        best_effectiveness: best_effectiveness,
        best_strength: best_strength
    };

}

function get_highest_effective_collected_lxs_attack(plot_params, device_params) {
    console.log(`Searching for highest effectiveness collected lxs attack`);
    console.table(plot_params);
    var best_challenge_sets_covered = 1;
    var best_effectiveness = 0.0;
    var best_strength = 2;
    var max_challenge_sets_bits_covered = 13;
    for (var challenge_set_bits_covered = 1; challenge_set_bits_covered <= max_challenge_sets_bits_covered; challenge_set_bits_covered++) {
        for (var strength = 2; strength < 14; strength++) {
            var test_plot_params = get_plot_params(plot_params.base_plot_id_filter, strength);
            test_plot_params.scan_filter_bits = plot_params.scan_filter_bits;
            var result = calc_attack_collected_lxs(1 << challenge_set_bits_covered, test_plot_params, device_params);
            var effectiveness = result.attacker_effectiveness;
            console.log(`Challenge sets covered: ${1 << challenge_set_bits_covered} Strength: ${strength} Effectiveness: ${effectiveness.toFixed(6)}`);
            if (effectiveness > best_effectiveness) {
                best_effectiveness = effectiveness;
                best_challenge_sets_covered = 1 << challenge_set_bits_covered;
                best_strength = strength;
            }
        }
    }
    console.log(`Best challenge sets covered: ${best_challenge_sets_covered} Best effectiveness: ${best_effectiveness.toFixed(6)}`);
    return {
        best_challenge_sets_covered : best_challenge_sets_covered,
        best_effectiveness: best_effectiveness,
        best_strength: best_strength
    };

}

function get_highest_effective_proof_fragments_drop_bits_attack(plot_params, device_params) {
    console.log(`Searching for highest effectiveness proof fragments drop bits attack`);
    console.table(plot_params);
    var best_bits_dropped = -6;
    var best_effectiveness = 0.0;
    for (var bits_dropped = -8; bits_dropped < 8; bits_dropped++) {
        for (var strength = 2; strength < 13; strength++) {
            var test_plot_params = get_plot_params(plot_params.base_plot_id_filter, strength);
            test_plot_params.scan_filter_bits = plot_params.scan_filter_bits;
            var result = calc_attack_proof_fragments_drop_bits(test_plot_params, device_params, bits_dropped);
            var effectiveness = result.attacker_effectiveness;
            console.log(`Bits dropped: ${bits_dropped} Strength bits: ${strength} Effectiveness: ${effectiveness.toFixed(6)}`);
            if (effectiveness > best_effectiveness) {
                best_effectiveness = effectiveness;
                best_bits_dropped = bits_dropped;
                best_strength = strength;
            }
        }
    }
    console.log(`Best bits dropped: ${best_bits_dropped} Best strength bits: ${best_strength} Best effectiveness: ${best_effectiveness.toFixed(6)}`);
    return {
        best_bits_dropped : best_bits_dropped,
        best_strength: best_strength,
        best_effectiveness: best_effectiveness
    };
}

function get_highest_effective_strength_match_bits_attack(plot_params, device_params) {
    console.log(`Searching for highest effectiveness strength match bits attack`);
    console.table(plot_params);
    var best_strength = 2;
    var best_effectiveness = 0.0;
    for (var strength = 2; strength < 14; strength++) {
        var test_plot_params = get_plot_params(plot_params.base_plot_id_filter, strength);
        test_plot_params.scan_filter_bits = plot_params.scan_filter_bits;
        var result = calc_attack_strength_match_bits(test_plot_params, device_params);
        var effectiveness = result.attacker_effectiveness;
        console.log(`Strength bits: ${strength} Effectiveness: ${effectiveness.toFixed(6)}`);
        if (effectiveness > best_effectiveness) {
            best_effectiveness = effectiveness;
            best_strength = strength;
        }
    }
    console.log(`Best strength bits: ${best_strength} Best effectiveness: ${best_effectiveness.toFixed(6)}`);
    return {
        best_strength: best_strength,
        best_effectiveness: best_effectiveness
    };
}
