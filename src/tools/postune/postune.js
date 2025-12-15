var k = 28;
var num_entries_per_table = 1 << k;
var honest_bits_per_entry = 29.45;
var honest_plot_size_bytes = num_entries_per_table * honest_bits_per_entry / 8;

var base_plot_id_filter = 4096;
var plot_strength_bits = 2;
function get_plot_strength() { return 1 << plot_strenth_bits; };
function get_plot_id_filter() { return base_plot_id_filter * (1 << (plot_strength_bits - 2)); };
var device_params_5090 = {
    g_hashes_per_ms: 9925926,       // the g(x) function
    pair_hashes_per_ms: 9925926,     // once we have a match, the hash to pair them to get next meta
    target_hashes_per_ms: 9925926,      // given a left side pairing, time to hash (meta + mi) target bits
    sloths_per_ms: 9925926         // time to do sloth encoding
};
var default_plot_params = {
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
    return {
        strength_bits: plot_strength_bits,
        t1_match_bits: 2,
        t2_match_bits: 2 + (plot_strength_bits - 2),
        t3_match_bits: 4 + (plot_strength_bits - 2),
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

    var results = {
        challenge_time_ms: challenge_time_ms,
        attacker_bits_per_entry: attacker_bits_per_entry,
        "Num supported plots per GPU": num_supported_plots,
        "Honest farm size (TB)": honest_farm_bytes / (1000 * 1000 * 1000 * 1000),
        "Attacker compression": attacker_compression,
        "Attacker plot size (bytes)": attacker_plot_bytes,
        "Attacker farm size (TB)": attacker_farm_bytes / (1000 * 1000 * 1000 * 1000),
        "Attacker saved size (TB)": attacker_saved_TB,
        "Attacker GPU W per TB on saved bytes": attacker_gpu_w_per_tb_on_saved_bytes,
        "Attacker GPU cost per TB on saved bytes": attacker_gpu_cost_per_tb_on_saved_bytes
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
function get_pairing_time(device_params, num_hashes) {
    return num_hashes / device_params.pair_hashes_per_ms;
}
function get_target_time(device_params, num_hashes) {
    return num_hashes / device_params.target_hashes_per_ms;
}
function get_sloth_time(device_params, num_sloths) {
    return num_sloths / device_params.sloths_per_ms;
}


function calc_plotting_time(plot_params, device_params) {
    var g_hashes = num_entries_per_table;
    var t1_target_hashes = num_entries_per_table * (1 << plot_params.t1_match_bits);
    var t1_pairing_hashes = num_entries_per_table;
    var t2_target_hashes = num_entries_per_table * (1 << plot_params.t2_match_bits);
    var t2_pairing_hashes = num_entries_per_table;
    var t3_target_hashes = num_entries_per_table * (1 << plot_params.t3_match_bits);
    var t3_pairing_hashes = num_entries_per_table;
    var g_hashes_time = get_g_time(device_params, g_hashes);
    var t1_target_hashes_time = get_target_time(device_params, t1_target_hashes);
    var t1_pairing_hashes_time = get_pairing_time(device_params, t1_pairing_hashes);
    var t1_time = t1_target_hashes_time + t1_pairing_hashes_time;
    var t2_target_hashes_time = get_target_time(device_params, t2_target_hashes);
    var t2_pairing_hashes_time = get_pairing_time(device_params, t2_pairing_hashes);
    var t2_time = t2_target_hashes_time + t2_pairing_hashes_time;
    var t3_target_hashes_time = get_target_time(device_params, t3_target_hashes);
    var t3_pairing_hashes_time = get_pairing_time(device_params, t3_pairing_hashes);
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
    var t1_pairing_hashes = challenge_data.uniqueXs / 2;
    var t1_matches = t1_pairing_hashes;

    var t2_target_hashes = t1_matches * (1 << plot_params.t2_match_bits);
    var t2_pairing_hashes = challenge_data.uniqueXs / 4;
    var t2_matches = t2_pairing_hashes;

    var t3_target_hashes = t2_matches * (1 << plot_params.t3_match_bits);
    var t3_pairing_hashes = challenge_data.uniqueXs / 8;
    var t3_matches = t3_pairing_hashes;

    var g_hashes_time = get_g_time(device_params, g_hashes);
    console.log(`Calculating attack collected XS with ${g_hashes} G hashes`);
    console.log(`G hashes time: ${g_hashes_time.toFixed(2)} ms`);
    var t1_target_hashes_time = get_target_time(device_params, t1_target_hashes);
    var t1_pairing_hashes_time = get_pairing_time(device_params, t1_pairing_hashes);
    var t1_time = g_hashes_time + t1_target_hashes_time + t1_pairing_hashes_time;

    var t2_target_hashes_time = get_target_time(device_params, t2_target_hashes);
    var t2_pairing_hashes_time = get_pairing_time(device_params, t2_pairing_hashes);
    var t2_time = t2_target_hashes_time + t2_pairing_hashes_time;

    var t3_target_hashes_time = get_target_time(device_params, t3_target_hashes);
    var t3_pairing_hashes_time = get_pairing_time(device_params, t3_pairing_hashes);
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
    var t1_pairing_hashes = challenge_data.uniqueLxs; // TODO: this is somewhere between uniqueLxs and num entries...
    var t1_matches = t1_pairing_hashes;

    var t2_target_hashes = t1_matches * (1 << plot_params.t2_match_bits);
    var t2_pairing_hashes = challenge_data.uniqueLxs / 2; // TODO: this is somewhere between uniqueLxs and num entries...
    var t2_matches = t2_pairing_hashes;

    var t3_target_hashes = t2_matches * (1 << plot_params.t3_match_bits);
    var t3_pairing_hashes = challenge_data.uniqueLxs / 4; // TODO: this should actually be # entries...
    var t3_matches = t3_pairing_hashes;

    var g_hashes_time = get_g_time(device_params, all_g_hashes);
    var lx_g_hashes_time = get_g_time(device_params, lx_g_hashes);
    var t1_target_hashes_time = get_target_time(device_params, t1_target_hashes);
    var t1_pairing_hashes_time = get_pairing_time(device_params, t1_pairing_hashes);
    var t1_time = lx_g_hashes_time + t1_target_hashes_time + t1_pairing_hashes_time;

    var t2_target_hashes_time = get_target_time(device_params, t2_target_hashes);
    var t2_pairing_hashes_time = get_pairing_time(device_params, t2_pairing_hashes);
    var t2_time = t2_target_hashes_time + t2_pairing_hashes_time;

    var t3_target_hashes_time = get_target_time(device_params, t3_target_hashes);
    var t3_pairing_hashes_time = get_pairing_time(device_params, t3_pairing_hashes);
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
function calc_attack_challenge_components_bit_dropping(plot_params, device_params, proof_fragments_to_scan, drop_bits) {
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
    var t1_pairing_hashes = avg_unique_lx_groups * Math.pow(2, 14 + drop_bits);
    var t1_matches = t1_pairing_hashes;

    var t2_target_hashes = t1_matches * (1 << plot_params.t2_match_bits);
    var t2_matches = (t1_matches / num_entries_per_table) * (t1_matches / num_entries_per_table) * num_entries_per_table;
    t2_matches = get_n_in_m_buckets(t2_matches, num_entries_per_table);
    var t2_pairing_hashes = t2_matches;

    var t3_target_hashes = t2_matches * (1 << plot_params.t3_match_bits);
    var t3_matches = (t2_matches / num_entries_per_table) * (t2_matches / num_entries_per_table) * num_entries_per_table;
    t3_matches = get_n_in_m_buckets(t3_matches, num_entries_per_table);
    var t3_pairing_hashes = t3_matches;

    var g_hashes_time = get_g_time(device_params, g_hashes);
    var t1_target_hashes_time = get_target_time(device_params, t1_target_hashes);
    var t1_pairing_hashes_time = get_pairing_time(device_params, t1_pairing_hashes);
    var t1_time = t1_target_hashes_time + t1_pairing_hashes_time;

    var t2_target_hashes_time = get_target_time(device_params, t2_target_hashes);
    var t2_pairing_hashes_time = get_pairing_time(device_params, t2_pairing_hashes);
    var t2_time = t2_target_hashes_time + t2_pairing_hashes_time;

    var t3_target_hashes_time = get_target_time(device_params, t3_target_hashes);
    var t3_pairing_hashes_time = get_pairing_time(device_params, t3_pairing_hashes);
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



function calc_attack_proof_fragments_bit_dropping(plot_params, device_params, proof_fragments_to_scan, drop_bits) {
    console.log(`Calculating attack proof fragments bit dropping #proof fragments: ${proof_fragments_to_scan}bit dropping: ${drop_bits} bits`);
    console.table(plot_params);

    var num_2_to_the_14_x_groups = proof_fragments_to_scan * 4 * Math.pow(2, drop_bits);
    console.log(`Num 2^14 x groups: ${num_2_to_the_14_x_groups}`);

    const possible_bit_dropped_groups = Math.pow(2, 14);
    console.log(`Possible bit dropped groups: ${possible_bit_dropped_groups}`);

    var avg_unique_x_groups = get_n_in_m_buckets(num_2_to_the_14_x_groups, possible_bit_dropped_groups);
    console.log(`Avg. unique x groups: ${avg_unique_x_groups.toFixed(2)}`);

    const bits_per_entry_proof_fragments = k - drop_bits + 1.45;
    console.log(`Bits per entry (proof fragments sorted): ${bits_per_entry_proof_fragments.toFixed(4)}`);

    const g_entries = num_entries_per_table;
    var t1_entries = (avg_unique_x_groups / possible_bit_dropped_groups) * num_entries_per_table;
    t1_entries = get_n_in_m_buckets(t1_entries, num_entries_per_table);
    var t2_entries = t1_entries;
    var t3_entries = proof_fragments_to_scan * 2 * Math.pow(2, drop_bits);
    t3_entries = get_n_in_m_buckets(t3_entries, num_entries_per_table);

    var t1_hashes = avg_unique_x_groups * Math.pow(2, 14) * ((1 << plot_params.t1_match_bits) + 1);
    console.log(`T1 hashes: ${t1_hashes}`);
    var t1_hashes_check = num_t1_hashes(plot_params) * (avg_unique_x_groups / possible_bit_dropped_groups);
    console.log(`T1 hashes check: ${t1_hashes_check}`);
    var t2_hashes = num_t2_hashes(plot_params) * (t2_entries / num_entries_per_table);
    console.log(`T2 hashes: ${t2_hashes}`);
    var t3_hashes = num_t3_hashes(plot_params) * (t3_entries / num_entries_per_table);
    console.log(`T3 hashes: ${t3_hashes}`);

    var g_perc = (g_entries / num_entries_per_table) * 100;
    var t1_perc = (t1_entries / num_entries_per_table) * 100;
    var t2_perc = (t2_entries / num_entries_per_table) * 100;
    var t3_perc = (t3_entries / num_entries_per_table) * 100;

    var g_time = get_g_time(plot_params, device_params) * (g_entries / num_entries_per_table);
    var t1_time = get_t1_time(plot_params, device_params) * (avg_unique_x_groups / possible_bit_dropped_groups);
    var t2_time = get_t2_time(plot_params, device_params) * (t2_entries / num_entries_per_table);
    var t3_time = get_t3_time(plot_params, device_params) * (t3_entries / num_entries_per_table);

    var challenge_solve_time = g_time + 2 * (t1_time + t2_time + t3_time); // 2 scan sets

    var results = {
        "Proof fragments to scan": proof_fragments_to_scan,
        "Drop bits": drop_bits,
        "Possible bit dropped groups": possible_bit_dropped_groups,
        "Avg. unique x groups": avg_unique_x_groups.toFixed(2),
        "Bits per entry (proof fragments sorted)": bits_per_entry_proof_fragments.toFixed(4),
        "G entries": g_entries,
        "T1 entries": t1_entries.toFixed(2),
        "T2 entries": t2_entries.toFixed(2),
        "T3 entries": t3_entries.toFixed(2),
        "G percent (%)": g_perc.toFixed(4),
        "T1 percent (%)": t1_perc.toFixed(4),
        "T2 percent (%)": t2_perc.toFixed(4),
        "T3 percent (%)": t3_perc.toFixed(4),
        "G solve time (ms)": g_time.toFixed(2),
        "T1 solve time (ms)": t1_time.toFixed(2),
        "T2 solve time (ms)": t2_time.toFixed(2),
        "T3 solve time (ms)": t3_time.toFixed(2),
        "Sloth time (ms)": "TODO",
        "Challenge solve time (2 scan sets) (ms)": challenge_solve_time.toFixed(2)
    };
    // NOTE that T3 entries must be then Feistel'd and filtered to within the scan PFs, though we see this as "free" work.
    console.table(results);

    return calc_attack_effectiveness(plot_params, default_equipment_params, challenge_solve_time, bits_per_entry_proof_fragments);
}

function calc_attack_proof_fragments_drop_bits(plot_params, device_params, proof_fragments_to_solve, bits_dropped) {
    console.log(`Calculating attack proof fragments drop bits #proof fragments: ${proof_fragments_to_solve} bits dropped: ${bits_dropped}`);
    console.table(plot_params);

    var num_2_to_the_14_x_groups = proof_fragments_to_solve * 4 * Math.pow(2, bits_dropped);
    console.log(`Num 2^14 x groups: ${num_2_to_the_14_x_groups}`);

    const possible_bit_dropped_groups = Math.pow(2, 14);
    console.log(`Possible bit dropped groups: ${possible_bit_dropped_groups}`);

    var avg_unique_x_groups = get_n_in_m_buckets(num_2_to_the_14_x_groups, possible_bit_dropped_groups);
    console.log(`Avg. unique x groups: ${avg_unique_x_groups.toFixed(2)}`);

    var all_g_hashes = num_entries_per_table;
    console.log(`All G hashes: ${all_g_hashes}`);

    var t1_target_hashes = avg_unique_x_groups * Math.pow(2, 14) * ((1 << plot_params.t1_match_bits));
    console.log(`T1 target hashes: ${t1_target_hashes}`);

    var pairing_hashes = avg_unique_x_groups * Math.pow(2, 14); // once we have a match, the hash to pair them to get next meta
    var num_t1_matches = pairing_hashes;
    console.log(`Num T1 matches: ${num_t1_matches}`);

    const g_time = get_g_time(device_params, all_g_hashes);
    const t1_pairing_hashes_time = get_pairing_time(device_params, pairing_hashes);
    const t1_target_hashes_time = get_target_time(device_params, t1_target_hashes);
    const t1_time = t1_pairing_hashes_time + t1_target_hashes_time;
    console.log(`G time (ms): ${g_time.toFixed(2)}`);
    console.log(`T1 target hashes time (ms): ${t1_target_hashes_time.toFixed(2)}`);
    console.log(`T1 pairing hashes time (ms): ${t1_pairing_hashes_time.toFixed(2)}`);
    console.log(`T1 time (ms): ${t1_time.toFixed(2)}`);

    const t2_target_hashes = num_t1_matches * ((1 << plot_params.t2_match_bits));
    console.log(`T2 target hashes: ${t2_target_hashes}`);
    const t2_target_hashes_time = get_target_time(device_params, t2_target_hashes);
    console.log(`T2 target hashes time (ms): ${t2_target_hashes_time.toFixed(2)}`);
    var t2_matches = proof_fragments_to_solve * 2 * Math.pow(2, bits_dropped);
    t2_matches = get_n_in_m_buckets(t2_matches, num_entries_per_table);
    console.log(`T2 matches: ${t2_matches}`);
    const t2_pairing_hashes = t2_matches;
    const t2_pairing_hashes_time = get_pairing_time(device_params, t2_pairing_hashes);
    console.log(`T2 pairing hashes time (ms): ${t2_pairing_hashes_time.toFixed(2)}`);
    const t2_time = t2_target_hashes_time + t2_pairing_hashes_time;
    console.log(`T2 time (ms): ${t2_time.toFixed(2)}`);

    const t3_target_hashes = t2_matches * ((1 << plot_params.t3_match_bits));
    console.log(`T3 target hashes: ${t3_target_hashes}`);
    const t3_target_hashes_time = get_target_time(device_params, t3_target_hashes);
    console.log(`T3 target hashes time (ms): ${t3_target_hashes_time.toFixed(2)}`);
    var t3_matches = proof_fragments_to_solve; // TODO: may be extra matches from T2 volume, but use this conversative value for now
    t3_matches = get_n_in_m_buckets(t3_matches, num_entries_per_table);
    console.log(`T3 matches: ${t3_matches}`);
    const t3_pairing_hashes = t3_matches;
    const t3_pairing_hashes_time = get_pairing_time(device_params, t3_pairing_hashes);
    console.log(`T3 pairing hashes time (ms): ${t3_pairing_hashes_time.toFixed(2)}`);
    const t3_time = t3_target_hashes_time + t3_pairing_hashes_time;

    var bits_per_entry_proof_fragments = k - bits_dropped + 1.45;
    console.log(`Bits per entry (proof fragments sorted): ${bits_per_entry_proof_fragments.toFixed(4)}`);

    var challenge_solve_time = g_time + 2 * (t1_time + t2_time + t3_time);

    var results = {
        "Proof fragments to solve": proof_fragments_to_solve,
        "Bits dropped": bits_dropped,
        "Avg. unique x groups": avg_unique_x_groups.toFixed(2),
        "Bits per entry (proof fragments sorted)": bits_per_entry_proof_fragments.toFixed(4),
        "T1 matches": Math.round(num_t1_matches),
        "T2 matches": Math.round(t2_matches),
        "T3 matches": Math.round(t3_matches),
        "T1 match bits": plot_params.t1_match_bits,
        "T2 match bits": plot_params.t2_match_bits,
        "T3 match bits": plot_params.t3_match_bits,
        "G hashes": Math.round(all_g_hashes),
        "T1 target hashes": Math.round(t1_target_hashes),
        "T1 pairing hashes": Math.round(pairing_hashes),
        "T2 target hashes": Math.round(t2_target_hashes),
        "T2 pairing hashes": Math.round(t2_pairing_hashes),
        "T3 target hashes": Math.round(t3_target_hashes),
        "T3 pairing hashes": Math.round(t3_pairing_hashes),
        "T1 target hashes time (ms)": t1_target_hashes_time.toFixed(2),
        "T1 pairing hashes time (ms)": t1_pairing_hashes_time.toFixed(2),
        "T2 target hashes time (ms)": t2_target_hashes_time.toFixed(2),
        "T2 pairing hashes time (ms)": t2_pairing_hashes_time.toFixed(2),
        "T3 target hashes time (ms)": t3_target_hashes_time.toFixed(2),
        "T3 pairing hashes time (ms)": t3_pairing_hashes_time.toFixed(2),
        "G time (ms)": g_time.toFixed(2),
        "T1 time (ms)": t1_time.toFixed(2),
        "T2 time (ms)": t2_time.toFixed(2),
        "T3 time (ms)": t3_time.toFixed(2),
        "Challenge solve time (ms)": challenge_solve_time.toFixed(2),
        "NOTE:": "Bit dropping proof fragments means only need to find false one, which can be determined earlier since x1/2/3/4 pairs may not match on bogus decryptions"
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
    var t1_target_hashes_time = get_target_time(device_params, t1_target_hashes);
    var t1_pairing_hashes_time = get_pairing_time(device_params, t1_pairing_hashes);
    var t1_time = t1_target_hashes_time + t1_pairing_hashes_time;

    var t2_target_hashes_time = get_target_time(device_params, t2_target_hashes);
    var t2_pairing_hashes_time = get_pairing_time(device_params, t2_pairing_hashes);
    var t2_time = t2_target_hashes_time + t2_pairing_hashes_time;

    var t3_target_hashes_time = get_target_time(device_params, t3_target_hashes);
    var t3_pairing_hashes_time = get_pairing_time(device_params, t3_pairing_hashes);
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
